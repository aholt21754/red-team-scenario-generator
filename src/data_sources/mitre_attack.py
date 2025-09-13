# Alternative MITRE Loader (use if mitreattack library fails)
# Replace the content of src/data_sources/mitre_attack.py with this

"""
Alternative MITRE ATT&CK data loading using direct JSON download.
Use this if the mitreattack library installation fails.
"""

import json
import requests
from typing import List, Dict, Any, Tuple

from data_sources.base_loader import BaseDataLoader
from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class MitreAttackLoader(BaseDataLoader):
    """Alternative loader for MITRE ATT&CK framework data using direct JSON download."""
    
    def __init__(self, domain: str = None):
        """Initialize MITRE ATT&CK loader.
        
        Args:
            domain: MITRE domain (currently only supports 'enterprise-attack')
        """
        self.domain = domain or config.MITRE_DOMAIN
        
        # MITRE ATT&CK Enterprise JSON URL
        self.enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        self.mitre_data = None
        
        logger.info(f"Initializing alternative MITRE loader for domain: {self.domain}")
    
    def load_data(self) -> List[Dict[str, Any]]:
        """Load MITRE ATT&CK data directly from GitHub.
        
        Returns:
            List of processed technique documents
        """
        try:
            logger.info("Loading MITRE ATT&CK data from GitHub...")
            
            # Download MITRE data
            response = requests.get(self.enterprise_url, timeout=30)
            response.raise_for_status()
            
            self.mitre_data = response.json()
            logger.info("Successfully downloaded MITRE ATT&CK data")
            
            # Extract techniques
            techniques = []
            for obj in self.mitre_data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    # Skip deprecated techniques if not included
                    if not config.INCLUDE_DEPRECATED and obj.get('x_mitre_deprecated', False):
                        continue
                    
                    techniques.append(obj)
            
            logger.info(f"Found {len(techniques)} techniques")
            
            # Process techniques into documents
            documents = []
            for technique in techniques:
                processed_doc = self._process_technique(technique)
                if processed_doc:
                    documents.append(processed_doc)
            
            logger.info(f"Processed {len(documents)} technique documents")
            return documents
            
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            # Return sample data for testing if download fails
            return self._get_sample_data()
    
    def validate_data(self, data: List[Dict]) -> bool:
        """Validate loaded MITRE data.
        
        Args:
            data: List of technique documents
            
        Returns:
            bool: True if data is valid
        """
        if not data:
            logger.error("No MITRE data to validate")
            return False
        
        required_fields = ['technique_id', 'name', 'description', 'document_text']
        
        for i, doc in enumerate(data):
            for field in required_fields:
                if field not in doc:
                    logger.error(f"Document {i} missing required field: {field}")
                    return False
            
            # Validate technique ID format
            tech_id = doc['technique_id']
            if not tech_id or not tech_id.startswith('T'):
                logger.error(f"Invalid technique ID format: {tech_id}")
                return False
        
        logger.info(f"Validated {len(data)} MITRE documents")
        return True
    
    def get_data_type(self) -> str:
        """Get the data type identifier."""
        return "mitre_technique"
    
    def _process_technique(self, technique: Dict) -> Dict[str, Any]:
        """Process a single MITRE technique.
        
        Args:
            technique: Raw technique data from MITRE
            
        Returns:
            Processed technique document
        """
        try:
            # Extract basic information
            tech_id = self._extract_technique_id(technique)
            name = technique.get('name', '')
            description = technique.get('description', '')
            
            if not tech_id or not name:
                logger.warning(f"Skipping technique with missing ID or name")
                return None
            
            # Extract tactics (kill chain phases)
            tactics = self._extract_tactics(technique)
            
            # Extract platforms
            platforms = technique.get('x_mitre_platforms', [])
            
            # Extract data sources
            data_sources = technique.get('x_mitre_data_sources', [])
            
            # Create comprehensive document text for embedding
            doc_text = self._create_document_text(
                tech_id, name, description, tactics, platforms, data_sources
            )
            
            # Create metadata
            metadata = {
                'technique_id': tech_id,
                'name': name,
                'tactics': ', '.join(tactics) if tactics else '',
                'platforms': ', '.join(platforms) if platforms else '',
                'data_sources': ', '.join(data_sources) if data_sources else '',
                'type': self.get_data_type(),
                'description': description[:500],
                'domain': self.domain,
                'deprecated': bool(technique.get('x_mitre_deprecated', False))
            } 

            return {
                'id': f"mitre_{tech_id}",
                'document_text': doc_text,
                'metadata': metadata,
                'technique_id': tech_id,
                'name': name,
                'description': description
            }
            
        except Exception as e:
            logger.error(f"Failed to process technique: {e}")
            return None
    
    def _extract_technique_id(self, technique: Dict) -> str:
        """Extract technique ID from external references.
        
        Args:
            technique: Raw technique data
            
        Returns:
            Technique ID (e.g., 'T1566.001')
        """
        external_refs = technique.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id', '')
        return ''
    
    def _extract_tactics(self, technique: Dict) -> List[str]:
        """Extract tactics from kill chain phases.
        
        Args:
            technique: Raw technique data
            
        Returns:
            List of tactic names
        """
        tactics = []
        kill_chain_phases = technique.get('kill_chain_phases', [])
        
        for phase in kill_chain_phases:
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactic = phase.get('phase_name', '')
                if tactic:
                    # Convert from hyphenated to readable format
                    readable_tactic = tactic.replace('-', ' ').title()
                    tactics.append(readable_tactic)
        
        return list(set(tactics))  # Remove duplicates
    
    def _create_document_text(self, tech_id: str, name: str, description: str,
                            tactics: List[str], platforms: List[str], 
                            data_sources: List[str]) -> str:
        """Create comprehensive document text for embedding.
        
        Args:
            tech_id: Technique ID
            name: Technique name
            description: Technique description
            tactics: List of tactics
            platforms: List of platforms
            data_sources: List of data sources
            
        Returns:
            Formatted document text
        """
        doc_parts = [
            f"Technique: {name} ({tech_id})",
            f"Tactics: {', '.join(tactics) if tactics else 'None'}",
            f"Platforms: {', '.join(platforms) if platforms else 'Multiple'}",
            f"Data Sources: {', '.join(data_sources) if data_sources else 'Various'}",
            f"Description: {description}"
        ]
        
        return '\n'.join(doc_parts)
    
    def _get_sample_data(self) -> List[Dict[str, Any]]:
        """Get sample MITRE data for testing when download fails.
        
        Returns:
            List of sample technique documents
        """
        logger.warning("Using sample MITRE data - download failed")
        
        sample_techniques = [
            {
                'technique_id': 'T1566.001',
                'name': 'Spearphishing Attachment',
                'description': 'Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.',
                'tactics': ['Initial Access'],
                'platforms': ['Linux', 'macOS', 'Windows'],
                'data_sources': ['Email Gateway', 'File Monitoring']
            },
            {
                'technique_id': 'T1190',
                'name': 'Exploit Public-Facing Application',
                'description': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.',
                'tactics': ['Initial Access'],
                'platforms': ['Linux', 'Windows', 'macOS', 'Network'],
                'data_sources': ['Web Application Firewall Logs', 'Application Logs']
            },
            {
                'technique_id': 'T1078',
                'name': 'Valid Accounts',
                'description': 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
                'tactics': ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'],
                'platforms': ['Linux', 'macOS', 'Windows', 'SaaS', 'IaaS', 'Network', 'Containers'],
                'data_sources': ['Authentication Logs', 'Logon Session']
            }
        ]
        
        documents = []
        for tech_data in sample_techniques:
            doc_text = self._create_document_text(
                tech_data['technique_id'],
                tech_data['name'],
                tech_data['description'],
                tech_data['tactics'],
                tech_data['platforms'],
                tech_data['data_sources']
            )
            
            metadata = {
                'technique_id': tech_data['technique_id'],
                'name': tech_data['name'],
                'tactics': ', '.join(tech_data['tactics']),  # Convert list to string
                'platforms': ', '.join(tech_data['platforms']),  # Convert list to string
                'data_sources': ', '.join(tech_data['data_sources']),  # Convert list to string
                'type': self.get_data_type(),
                'description': tech_data['description'][:500],
                'domain': self.domain,
                'deprecated': False
            }
            
            documents.append({
                'id': f"mitre_{tech_data['technique_id']}",
                'document_text': doc_text,
                'metadata': metadata,
                'technique_id': tech_data['technique_id'],
                'name': tech_data['name'],
                'description': tech_data['description']
            })
        
        return documents