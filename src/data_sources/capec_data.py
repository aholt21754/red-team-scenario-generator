# src/data_sources/capec_data.py
"""CAPEC attack pattern data loading and processing."""

from typing import List, Dict, Any

from data_sources.base_loader import BaseDataLoader
from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class CapecDataLoader(BaseDataLoader):
    """Loader for CAPEC (Common Attack Pattern Enumeration and Classification) data."""
    
    def __init__(self):
        """Initialize CAPEC loader with predefined mappings."""
        # Simplified CAPEC mappings for MVP
        # In production, you would load from official CAPEC database
        self.capec_mappings = {
            "T1566": {
                "capec_ids": ["CAPEC-98", "CAPEC-163"],
                "name": "Phishing",
                "description": "Social engineering attacks via email, messaging, or other communication methods to trick users into revealing information or performing actions",
                "tactics": ["Initial Access"],
                "platforms": ["Email", "Web", "Mobile"],
                "likelihood": "High",
                "severity": "High"
            },
            "T1190": {
                "capec_ids": ["CAPEC-66", "CAPEC-169"],
                "name": "Exploit Public-Facing Application",
                "description": "Exploitation of vulnerabilities in public-facing web applications and services",
                "tactics": ["Initial Access"],
                "platforms": ["Web Applications", "Network Services"],
                "likelihood": "Medium",
                "severity": "High"
            },
            "T1078": {
                "capec_ids": ["CAPEC-2", "CAPEC-16"],
                "name": "Valid Accounts",
                "description": "Use of legitimate user accounts to maintain access and avoid detection",
                "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                "platforms": ["Windows", "macOS", "Linux", "Cloud"],
                "likelihood": "High",
                "severity": "Medium"
            },
            "T1055": {
                "capec_ids": ["CAPEC-640", "CAPEC-17"],
                "name": "Process Injection",
                "description": "Injection of code into legitimate processes to avoid detection and gain elevated privileges",
                "tactics": ["Defense Evasion", "Privilege Escalation"],
                "platforms": ["Windows", "Linux", "macOS"],
                "likelihood": "Medium",
                "severity": "High"
            },
            "T1569": {
                "capec_ids": ["CAPEC-576"],
                "name": "System Services",
                "description": "Abuse of system services for execution, persistence, or privilege escalation",
                "tactics": ["Execution"],
                "platforms": ["Windows", "Linux", "macOS"],
                "likelihood": "Medium",
                "severity": "Medium"
            },
            "T1027": {
                "capec_ids": ["CAPEC-267", "CAPEC-588"],
                "name": "Obfuscated Files or Information",
                "description": "Hiding or disguising files and information to evade detection",
                "tactics": ["Defense Evasion"],
                "platforms": ["Windows", "macOS", "Linux"],
                "likelihood": "High",
                "severity": "Low"
            },
            "T1003": {
                "capec_ids": ["CAPEC-52", "CAPEC-555"],
                "name": "OS Credential Dumping",
                "description": "Obtaining account login and password information from the operating system and software",
                "tactics": ["Credential Access"],
                "platforms": ["Windows", "Linux", "macOS"],
                "likelihood": "High",
                "severity": "High"
            },
            "T1021": {
                "capec_ids": ["CAPEC-555", "CAPEC-600"],
                "name": "Remote Services",
                "description": "Use of valid accounts with remote services to move laterally",
                "tactics": ["Lateral Movement"],
                "platforms": ["Windows", "Linux", "macOS", "Network"],
                "likelihood": "High",
                "severity": "Medium"
            },
            "T1059": {
                "capec_ids": ["CAPEC-88", "CAPEC-15"],
                "name": "Command and Scripting Interpreter",
                "description": "Abuse of command and script interpreters to execute commands",
                "tactics": ["Execution"],
                "platforms": ["Windows", "Linux", "macOS"],
                "likelihood": "High",
                "severity": "Medium"
            },
            "T1105": {
                "capec_ids": ["CAPEC-436"],
                "name": "Ingress Tool Transfer",
                "description": "Transfer of tools or files from external systems into a compromised environment",
                "tactics": ["Command and Control"],
                "platforms": ["Windows", "Linux", "macOS"],
                "likelihood": "High",
                "severity": "Medium"
            }
        }
        
        logger.info(f"Initialized CAPEC loader with {len(self.capec_mappings)} mappings")
    
    def load_data(self) -> List[Dict[str, Any]]:
        """Load CAPEC data.
        
        Returns:
            List of processed CAPEC attack pattern documents
        """
        logger.info("Loading CAPEC attack pattern data...")
        
        documents = []
        
        for tech_id, capec_info in self.capec_mappings.items():
            processed_doc = self._process_capec_mapping(tech_id, capec_info)
            if processed_doc:
                documents.append(processed_doc)
        
        logger.info(f"Processed {len(documents)} CAPEC attack patterns")
        return documents
    
    def validate_data(self, data: List[Dict]) -> bool:
        """Validate loaded CAPEC data.
        
        Args:
            data: List of CAPEC documents
            
        Returns:
            bool: True if data is valid
        """
        if not data:
            logger.error("No CAPEC data to validate")
            return False
        
        required_fields = ['technique_id', 'name', 'description', 'document_text', 'capec_ids']
        
        for i, doc in enumerate(data):
            for field in required_fields:
                if field not in doc:
                    logger.error(f"CAPEC document {i} missing required field: {field}")
                    return False
            
            # Validate CAPEC IDs format
            capec_ids = doc['capec_ids']
            if not isinstance(capec_ids, list) or not capec_ids:
                logger.error(f"Invalid CAPEC IDs in document {i}")
                return False
            
            for capec_id in capec_ids:
                if not capec_id.startswith('CAPEC-'):
                    logger.error(f"Invalid CAPEC ID format: {capec_id}")
                    return False
        
        logger.info(f"Validated {len(data)} CAPEC documents")
        return True
    
    def get_data_type(self) -> str:
        """Get the data type identifier."""
        return "capec_mapping"
    
    def _process_capec_mapping(self, tech_id: str, capec_info: Dict) -> Dict[str, Any]:
        """Process a single CAPEC mapping.
        
        Args:
            tech_id: MITRE technique ID
            capec_info: CAPEC information dictionary
            
        Returns:
            Processed CAPEC document
        """
        try:
            name = capec_info['name']
            description = capec_info['description']
            capec_ids = capec_info['capec_ids']
            tactics = capec_info.get('tactics', [])
            platforms = capec_info.get('platforms', [])
            likelihood = capec_info.get('likelihood', 'Unknown')
            severity = capec_info.get('severity', 'Unknown')
            
            # Create comprehensive document text for embedding
            doc_text = self._create_document_text(
                tech_id, name, description, capec_ids, tactics, platforms, likelihood, severity
            )
            
            # Create metadata (ChromaDB only accepts str, int, float, bool, None)
            metadata = {
                'technique_id': tech_id,
                'name': name,
                'capec_ids': ', '.join(capec_ids),  # Convert list to string
                'tactics': ', '.join(tactics) if tactics else '',  # Convert list to string
                'platforms': ', '.join(platforms) if platforms else '',  # Convert list to string
                'likelihood': likelihood,
                'severity': severity,
                'type': self.get_data_type(),
                'description': description[:500],  # Truncate for metadata
                'attack_pattern_count': len(capec_ids)
            }
            
            return {
                'id': f"capec_{tech_id}",
                'document_text': doc_text,
                'metadata': metadata,
                'technique_id': tech_id,
                'name': name,
                'description': description,
                'capec_ids': capec_ids
            }
            
        except Exception as e:
            logger.error(f"Failed to process CAPEC mapping for {tech_id}: {e}")
            return None
    
    def _create_document_text(self, tech_id: str, name: str, description: str,
                            capec_ids: List[str], tactics: List[str], 
                            platforms: List[str], likelihood: str, severity: str) -> str:
        """Create comprehensive document text for embedding.
        
        Args:
            tech_id: MITRE technique ID
            name: Attack pattern name
            description: Attack pattern description
            capec_ids: List of CAPEC IDs
            tactics: List of tactics
            platforms: List of platforms
            likelihood: Attack likelihood
            severity: Attack severity
            
        Returns:
            Formatted document text
        """
        doc_parts = [
            f"Attack Pattern: {name}",
            f"MITRE Technique: {tech_id}",
            f"CAPEC IDs: {', '.join(capec_ids)}",
            f"Tactics: {', '.join(tactics) if tactics else 'Multiple'}",
            f"Platforms: {', '.join(platforms) if platforms else 'Multiple'}",
            f"Likelihood: {likelihood}",
            f"Severity: {severity}",
            f"Description: {description}"
        ]
        
        return '\n'.join(doc_parts)
    
    def get_mappings_by_tactic(self, tactic: str) -> List[Dict]:
        """Get CAPEC mappings filtered by specific tactic.
        
        Args:
            tactic: Tactic name to filter by
            
        Returns:
            List of CAPEC mappings for the specified tactic
        """
        filtered_mappings = []
        
        for tech_id, capec_info in self.capec_mappings.items():
            if tactic.lower() in [t.lower() for t in capec_info.get('tactics', [])]:
                processed = self._process_capec_mapping(tech_id, capec_info)
                if processed:
                    filtered_mappings.append(processed)
        
        return filtered_mappings
    
    def get_mappings_by_platform(self, platform: str) -> List[Dict]:
        """Get CAPEC mappings filtered by specific platform.
        
        Args:
            platform: Platform name to filter by
            
        Returns:
            List of CAPEC mappings for the specified platform
        """
        filtered_mappings = []
        
        for tech_id, capec_info in self.capec_mappings.items():
            if platform.lower() in [p.lower() for p in capec_info.get('platforms', [])]:
                processed = self._process_capec_mapping(tech_id, capec_info)
                if processed:
                    filtered_mappings.append(processed)
        
        return filtered_mappings
    
    def get_high_likelihood_attacks(self) -> List[Dict]:
        """Get attack patterns with high likelihood.
        
        Returns:
            List of high-likelihood attack patterns
        """
        high_likelihood_attacks = []
        
        for tech_id, capec_info in self.capec_mappings.items():
            if capec_info.get('likelihood', '').lower() == 'high':
                processed = self._process_capec_mapping(tech_id, capec_info)
                if processed:
                    high_likelihood_attacks.append(processed)
        
        return high_likelihood_attacks
    
    def add_custom_mapping(self, tech_id: str, capec_info: Dict) -> bool:
        """Add a custom CAPEC mapping.
        
        Args:
            tech_id: MITRE technique ID
            capec_info: CAPEC information dictionary
            
        Returns:
            bool: True if mapping added successfully
        """
        try:
            # Validate required fields
            required_fields = ['capec_ids', 'name', 'description']
            for field in required_fields:
                if field not in capec_info:
                    logger.error(f"Missing required field in custom mapping: {field}")
                    return False
            
            # Add to mappings
            self.capec_mappings[tech_id] = capec_info
            logger.info(f"Added custom CAPEC mapping for {tech_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add custom mapping: {e}")
            return False