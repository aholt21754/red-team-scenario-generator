# src/data_sources/capec_data.py
"""Enhanced CAPEC attack pattern data loading with proper XML parsing."""

import xml.etree.ElementTree as ET
import requests
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import re

from data_sources.base_loader import BaseDataLoader
from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class CapecDataLoader(BaseDataLoader):
    """Enhanced loader for CAPEC (Common Attack Pattern Enumeration and Classification) data."""
    
    def __init__(self, cache_enabled: bool = True, cache_duration_hours: int = 24):
        """Initialize CAPEC loader with XML parsing capabilities.
        
        Args:
            cache_enabled: Whether to enable local caching
            cache_duration_hours: How long to cache data before refreshing
        """
        self.cache_enabled = cache_enabled
        self.cache_duration = timedelta(hours=cache_duration_hours)
        
        # CAPEC XML data source
        self.capec_xml_url = "https://capec.mitre.org/data/xml/capec_latest.xml"
        self.backup_urls = [
            "https://capec.mitre.org/data/xml/capec_v3.9.xml",
            "https://raw.githubusercontent.com/mitre/capec/master/capec/data/capec_latest.xml"
        ]
        
        # Cache file location
        self.cache_dir = Path("data/cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "capec_data.json"
        self.xml_cache_file = self.cache_dir / "capec_latest.xml"
        
        # XML namespace
        self.namespace = {
            'capec': 'http://capec.mitre.org/capec-3',
            'xhtml': 'http://www.w3.org/1999/xhtml'
        }
        
        logger.info(f"Initialized CAPEC loader with caching: {cache_enabled}")
    
    def load_data(self) -> List[Dict[str, Any]]:
        """Load CAPEC data from XML source or cache.
        
        Returns:
            List of processed CAPEC attack pattern documents
        """
        logger.info("Loading CAPEC attack pattern data...")
        
        try:
            # Check cache first
            if self.cache_enabled and self._is_cache_valid():
                logger.info("Loading CAPEC data from cache...")
                cached_data = self._load_from_cache()
                if cached_data:
                    logger.info(f"Loaded {len(cached_data)} patterns from cache")
                    return cached_data
            
            # Download fresh data
            xml_data = self._download_capec_data()
            if not xml_data:
                logger.warning("Failed to download CAPEC data, using fallback patterns")
                return self._get_fallback_patterns()
            
            # Parse XML data
            patterns = self._parse_capec_xml(xml_data)
            if not patterns:
                logger.warning("Failed to parse CAPEC XML, using fallback patterns")
                return self._get_fallback_patterns()
            
            # Process patterns into documents
            documents = []
            for pattern in patterns:
                processed_doc = self._process_capec_pattern(pattern)
                if processed_doc:
                    documents.append(processed_doc)
            
            # Cache the processed data
            if self.cache_enabled and documents:
                self._save_to_cache(documents)
            
            logger.info(f"Successfully loaded and processed {len(documents)} CAPEC patterns")
            return documents
            
        except Exception as e:
            logger.error(f"CAPEC data loading failed: {e}")
            return self._get_fallback_patterns()
    
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
        
        required_fields = ['capec_id', 'name', 'description', 'document_text']
        
        for i, doc in enumerate(data):
            for field in required_fields:
                if field not in doc:
                    logger.error(f"CAPEC document {i} missing required field: {field}")
                    return False
            
            # Validate CAPEC ID format
            capec_id = doc['capec_id']
            if not capec_id or not str(capec_id).isdigit():
                logger.error(f"Invalid CAPEC ID format: {capec_id}")
                return False
        
        logger.info(f"Validated {len(data)} CAPEC documents")
        return True
    
    def get_data_type(self) -> str:
        """Get the data type identifier."""
        return "capec_pattern"
    
    def _download_capec_data(self) -> Optional[str]:
        """Download CAPEC XML data from official source.
        
        Returns:
            XML data as string or None if failed
        """
        urls_to_try = [self.capec_xml_url] + self.backup_urls
        
        for url in urls_to_try:
            try:
                logger.info(f"Downloading CAPEC data from: {url}")
                response = requests.get(url, timeout=60)
                response.raise_for_status()
                
                xml_data = response.text
                
                # Basic validation - check if it's XML
                if '<?xml' in xml_data and 'capec' in xml_data.lower():
                    logger.info(f"Successfully downloaded {len(xml_data):,} characters of CAPEC XML")
                    
                    # Cache the raw XML
                    if self.cache_enabled:
                        try:
                            with open(self.xml_cache_file, 'w', encoding='utf-8') as f:
                                f.write(xml_data)
                            logger.info("Cached raw CAPEC XML data")
                        except Exception as e:
                            logger.warning(f"Failed to cache XML: {e}")
                    
                    return xml_data
                else:
                    logger.warning(f"Downloaded data from {url} doesn't appear to be valid XML")
                    continue
                    
            except requests.RequestException as e:
                logger.warning(f"Failed to download from {url}: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error downloading from {url}: {e}")
                continue
        
        # Try to use cached XML if download fails
        if self.cache_enabled and self.xml_cache_file.exists():
            try:
                logger.info("Attempting to use cached XML data...")
                with open(self.xml_cache_file, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to read cached XML: {e}")
        
        logger.error("Failed to download CAPEC data from all sources")
        return None
    
    def _parse_capec_xml(self, xml_data: str) -> List[Dict]:
        """Parse CAPEC XML data into structured patterns.
        
        Args:
            xml_data: Raw XML data string
            
        Returns:
            List of parsed attack patterns
        """
        try:
            logger.info("Parsing CAPEC XML data...")
            
            # Parse XML
            root = ET.fromstring(xml_data)
            
            # Find all attack patterns
            patterns = []
            
            # The XML structure is: Attack_Pattern_Catalog -> Attack_Patterns -> Attack_Pattern
            attack_patterns = root.findall('.//capec:Attack_Pattern', self.namespace)
            
            if not attack_patterns:
                # Try without namespace
                attack_patterns = root.findall('.//Attack_Pattern')
            
            logger.info(f"Found {len(attack_patterns)} attack patterns in XML")
            
            for pattern_elem in attack_patterns:
                try:
                    pattern = self._parse_single_pattern(pattern_elem)
                    if pattern:
                        patterns.append(pattern)
                except Exception as e:
                    logger.warning(f"Failed to parse individual pattern: {e}")
                    continue
            
            logger.info(f"Successfully parsed {len(patterns)} attack patterns")
            return patterns
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {e}")
            return []
    
    def _parse_single_pattern(self, pattern_elem) -> Optional[Dict]:
        """Parse a single attack pattern element.
        
        Args:
            pattern_elem: XML element for attack pattern
            
        Returns:
            Parsed pattern dictionary or None if failed
        """
        try:
            # Extract basic attributes
            capec_id = pattern_elem.get('ID', '')
            name = pattern_elem.get('Name', '')
            abstraction = pattern_elem.get('Abstraction', '')
            status = pattern_elem.get('Status', '')
            
            if not capec_id or not name:
                return None
            
            # Extract description
            desc_elem = pattern_elem.find('capec:Description', self.namespace)
            if desc_elem is None:
                desc_elem = pattern_elem.find('Description')
            description = desc_elem.text if desc_elem is not None else ''
            
            # Extract likelihood and severity
            likelihood_elem = pattern_elem.find('capec:Likelihood_Of_Attack', self.namespace)
            if likelihood_elem is None:
                likelihood_elem = pattern_elem.find('Likelihood_Of_Attack')
            likelihood = likelihood_elem.text if likelihood_elem is not None else 'Unknown'
            
            severity_elem = pattern_elem.find('capec:Typical_Severity', self.namespace)
            if severity_elem is None:
                severity_elem = pattern_elem.find('Typical_Severity')
            severity = severity_elem.text if severity_elem is not None else 'Unknown'
            
            # Extract prerequisites
            prerequisites = []
            prereq_elems = pattern_elem.findall('.//capec:Prerequisite', self.namespace)
            if not prereq_elems:
                prereq_elems = pattern_elem.findall('.//Prerequisite')
            
            for prereq in prereq_elems:
                if prereq.text:
                    prerequisites.append(prereq.text.strip())
            
            # Extract skills required
            skills = []
            skill_elems = pattern_elem.findall('.//capec:Skill', self.namespace)
            if not skill_elems:
                skill_elems = pattern_elem.findall('.//Skill')
            
            for skill in skill_elems:
                level = skill.get('Level', 'Unknown')
                text = skill.text if skill.text else ''
                if text:
                    skills.append(f"{level}: {text.strip()}")
            
            # Extract execution flow steps
            execution_steps = []
            step_elems = pattern_elem.findall('.//capec:Attack_Step', self.namespace)
            if not step_elems:
                step_elems = pattern_elem.findall('.//Attack_Step')
            
            for step in step_elems:
                step_num = step.find('capec:Step', self.namespace)
                if step_num is None:
                    step_num = step.find('Step')
                
                phase = step.find('capec:Phase', self.namespace)
                if phase is None:
                    phase = step.find('Phase')
                
                step_desc = step.find('capec:Description', self.namespace)
                if step_desc is None:
                    step_desc = step.find('Description')
                
                if step_num is not None and phase is not None and step_desc is not None:
                    execution_steps.append({
                        'step': step_num.text,
                        'phase': phase.text,
                        'description': step_desc.text
                    })
            
            # Extract mitigations
            mitigations = []
            mitigation_elems = pattern_elem.findall('.//capec:Mitigation', self.namespace)
            if not mitigation_elems:
                mitigation_elems = pattern_elem.findall('.//Mitigation')
            
            for mitigation in mitigation_elems:
                # Handle both text content and nested HTML
                mitigation_text = self._extract_text_content(mitigation)
                if mitigation_text:
                    mitigations.append(mitigation_text)
            
            # Extract related attack patterns
            related_patterns = []
            related_elems = pattern_elem.findall('.//capec:Related_Attack_Pattern', self.namespace)
            if not related_elems:
                related_elems = pattern_elem.findall('.//Related_Attack_Pattern')
            
            for related in related_elems:
                related_id = related.get('CAPEC_ID', '')
                nature = related.get('Nature', '')
                if related_id:
                    related_patterns.append(f"{nature}: CAPEC-{related_id}")
            
            # Extract MITRE ATT&CK mappings
            attack_mappings = []
            taxonomy_elems = pattern_elem.findall('.//capec:Taxonomy_Mapping', self.namespace)
            if not taxonomy_elems:
                taxonomy_elems = pattern_elem.findall('.//Taxonomy_Mapping')
            
            for taxonomy in taxonomy_elems:
                taxonomy_name = taxonomy.get('Taxonomy_Name', '')
                if taxonomy_name == 'ATTACK':
                    entry_id = taxonomy.find('capec:Entry_ID', self.namespace)
                    if entry_id is None:
                        entry_id = taxonomy.find('Entry_ID')
                    
                    if entry_id is not None and entry_id.text:
                        attack_mappings.append(entry_id.text)
            
            return {
                'capec_id': capec_id,
                'name': name,
                'description': description,
                'abstraction': abstraction,
                'status': status,
                'likelihood': likelihood,
                'severity': severity,
                'prerequisites': prerequisites,
                'skills': skills,
                'execution_steps': execution_steps,
                'mitigations': mitigations,
                'related_patterns': related_patterns,
                'attack_mappings': attack_mappings
            }
            
        except Exception as e:
            logger.warning(f"Error parsing pattern {pattern_elem.get('ID', 'unknown')}: {e}")
            return None
    
    def _extract_text_content(self, element) -> str:
        """Extract text content from XML element, handling nested HTML.
        
        Args:
            element: XML element
            
        Returns:
            Extracted text content
        """
        if element.text:
            text = element.text
        else:
            # Handle nested content (like xhtml:p tags)
            texts = []
            for child in element.iter():
                if child.text:
                    texts.append(child.text.strip())
                if child.tail:
                    texts.append(child.tail.strip())
            text = ' '.join(filter(None, texts))
        
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def _process_capec_pattern(self, pattern: Dict) -> Dict[str, Any]:
        """Process a parsed CAPEC pattern into a document.
        
        Args:
            pattern: Parsed pattern dictionary
            
        Returns:
            Processed document ready for vector database
        """
        try:
            capec_id = pattern['capec_id']
            name = pattern['name']
            description = pattern['description']
            
            # Determine attack complexity based on skills and prerequisites
            complexity = self._determine_complexity(pattern)
            
            # Determine skill level
            skill_level = self._determine_skill_level(pattern)
            
            # Determine environment suitability
            environment_suitability = self._determine_environments(pattern)
            
            # Create comprehensive document text
            doc_text = self._create_comprehensive_document_text(pattern)
            
            # Create metadata (ensure all values are simple types for ChromaDB)
            metadata = {
                'capec_id': str(capec_id),
                'name': name,
                'abstraction': pattern.get('abstraction', ''),
                'status': pattern.get('status', ''),
                'likelihood': pattern.get('likelihood', 'Unknown'),
                'severity': pattern.get('severity', 'Unknown'),
                'attack_complexity': complexity,
                'skill_level': skill_level,
                'environment_suitability': ', '.join(environment_suitability),
                'type': self.get_data_type(),
                'description': description[:500],  # Truncate for metadata
                'prerequisite_count': len(pattern.get('prerequisites', [])),
                'mitigation_count': len(pattern.get('mitigations', [])),
                'related_techniques': ', '.join(pattern.get('attack_mappings', []))
            }
            
            return {
                'id': f"capec_{capec_id}",
                'document_text': doc_text,
                'metadata': metadata,
                'capec_id': capec_id,
                'name': name,
                'description': description,
                'prerequisites': pattern.get('prerequisites', []),
                'skills': pattern.get('skills', []),
                'execution_steps': pattern.get('execution_steps', []),
                'mitigations': pattern.get('mitigations', []),
                'related_patterns': pattern.get('related_patterns', []),
                'attack_mappings': pattern.get('attack_mappings', []),
                'attack_complexity': complexity,
                'skill_level': skill_level,
                'environment_suitability': environment_suitability
            }
            
        except Exception as e:
            logger.error(f"Failed to process CAPEC pattern {pattern.get('capec_id', 'unknown')}: {e}")
            return None
    
    def _determine_complexity(self, pattern: Dict) -> str:
        """Determine attack complexity based on pattern characteristics.
        
        Args:
            pattern: Parsed pattern dictionary
            
        Returns:
            Complexity level string
        """
        # Analyze prerequisites and skills to determine complexity
        prerequisites = pattern.get('prerequisites', [])
        skills = pattern.get('skills', [])
        execution_steps = pattern.get('execution_steps', [])
        
        complexity_score = 0
        
        # More prerequisites = higher complexity
        complexity_score += min(len(prerequisites), 3)
        
        # Analyze skill requirements
        for skill in skills:
            if 'high' in skill.lower():
                complexity_score += 3
            elif 'medium' in skill.lower():
                complexity_score += 2
            elif 'low' in skill.lower():
                complexity_score += 1
        
        # More execution steps = higher complexity
        complexity_score += min(len(execution_steps), 2)
        
        # Determine complexity level
        if complexity_score <= 2:
            return "Low"
        elif complexity_score <= 5:
            return "Medium"
        else:
            return "High"
    
    def _determine_skill_level(self, pattern: Dict) -> str:
        """Determine required skill level.
        
        Args:
            pattern: Parsed pattern dictionary
            
        Returns:
            Skill level string
        """
        skills = pattern.get('skills', [])
        
        # Extract skill levels mentioned
        for skill in skills:
            if 'high' in skill.lower():
                return "Expert"
            elif 'medium' in skill.lower():
                return "Intermediate"
            elif 'low' in skill.lower():
                return "Beginner"
        
        # Default based on complexity
        complexity = self._determine_complexity(pattern)
        if complexity == "High":
            return "Expert"
        elif complexity == "Medium":
            return "Intermediate"
        else:
            return "Beginner"
    
    def _determine_environments(self, pattern: Dict) -> List[str]:
        """Determine suitable environments based on pattern content.
        
        Args:
            pattern: Parsed pattern dictionary
            
        Returns:
            List of suitable environment types
        """
        environments = []
        
        # Analyze description and other content for environment clues
        content = (pattern.get('description', '') + ' ' + 
                  ' '.join(pattern.get('prerequisites', [])) + ' ' +
                  ' '.join([step.get('description', '') for step in pattern.get('execution_steps', [])])).lower()
        
        # Web-based environments
        if any(term in content for term in ['web', 'http', 'url', 'browser', 'application']):
            environments.append("Web Applications")
        
        # Network environments
        if any(term in content for term in ['network', 'tcp', 'udp', 'protocol', 'packet']):
            environments.append("Network")
        
        # Corporate environments
        if any(term in content for term in ['enterprise', 'corporate', 'organization', 'employee']):
            environments.append("Corporate")
        
        # Cloud environments
        if any(term in content for term in ['cloud', 'aws', 'azure', 'saas', 'iaas']):
            environments.append("Cloud")
        
        # Mobile environments
        if any(term in content for term in ['mobile', 'android', 'ios', 'smartphone']):
            environments.append("Mobile")
        
        # Default if none detected
        if not environments:
            environments = ["General"]
        
        return environments
    
    def _create_comprehensive_document_text(self, pattern: Dict) -> str:
        """Create comprehensive document text for embedding.
        
        Args:
            pattern: Parsed pattern dictionary
            
        Returns:
            Formatted document text
        """
        parts = []
        
        # Basic information
        parts.append(f"CAPEC-{pattern['capec_id']}: {pattern['name']}")
        parts.append(f"Description: {pattern['description']}")
        parts.append(f"Likelihood: {pattern.get('likelihood', 'Unknown')}")
        parts.append(f"Severity: {pattern.get('severity', 'Unknown')}")
        
        # Prerequisites
        if pattern.get('prerequisites'):
            parts.append("Prerequisites:")
            for prereq in pattern['prerequisites']:
                parts.append(f"- {prereq}")
        
        # Skills required
        if pattern.get('skills'):
            parts.append("Skills Required:")
            for skill in pattern['skills']:
                parts.append(f"- {skill}")
        
        # Execution steps
        if pattern.get('execution_steps'):
            parts.append("Execution Steps:")
            for step in pattern['execution_steps']:
                parts.append(f"Step {step.get('step', '')}: {step.get('phase', '')} - {step.get('description', '')}")
        
        # Mitigations
        if pattern.get('mitigations'):
            parts.append("Mitigations:")
            for mitigation in pattern['mitigations'][:3]:  # Limit to first 3 to avoid huge documents
                parts.append(f"- {mitigation}")
        
        # Related patterns
        if pattern.get('related_patterns'):
            parts.append(f"Related Patterns: {', '.join(pattern['related_patterns'][:5])}")
        
        # MITRE ATT&CK mappings
        if pattern.get('attack_mappings'):
            parts.append(f"MITRE ATT&CK: {', '.join(pattern['attack_mappings'])}")
        
        return '\n'.join(parts)
    
    def _is_cache_valid(self) -> bool:
        """Check if cached data is still valid.
        
        Returns:
            bool: True if cache is valid
        """
        if not self.cache_file.exists():
            return False
        
        try:
            cache_time = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            return datetime.now() - cache_time < self.cache_duration
        except Exception:
            return False
    
    def _load_from_cache(self) -> Optional[List[Dict]]:
        """Load data from cache file.
        
        Returns:
            Cached data or None if failed
        """
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load from cache: {e}")
            return None
    
    def _save_to_cache(self, data: List[Dict]) -> None:
        """Save data to cache file.
        
        Args:
            data: Data to cache
        """
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Cached {len(data)} CAPEC patterns")
        except Exception as e:
            logger.warning(f"Failed to save to cache: {e}")
    
    def _get_fallback_patterns(self) -> List[Dict[str, Any]]:
        """Get fallback CAPEC patterns when download/parsing fails.
        
        Returns:
            List of fallback pattern documents
        """
        logger.info("Using fallback CAPEC patterns")
        
        fallback_patterns = [
            {
                'capec_id': '1',
                'name': 'Accessing Functionality Not Properly Constrained by ACLs',
                'description': 'An attacker gains access to functionality that is not properly protected by access control lists, potentially compromising the application.',
                'likelihood': 'High',
                'severity': 'High',
                'prerequisites': ['Application uses ACL-based authorization', 'Administrator misconfigured ACLs'],
                'skills': ['Low: Basic application testing skills'],
                'execution_steps': [
                    {'step': '1', 'phase': 'Explore', 'description': 'Survey the application for accessible resources'},
                    {'step': '2', 'phase': 'Experiment', 'description': 'Attempt direct access to restricted functionality'}
                ],
                'mitigations': ['Implement default-deny ACL policies', 'Regular ACL audits'],
                'attack_mappings': ['T1574.010']
            },
            {
                'capec_id': '2',
                'name': 'Inducing Account Lockout',
                'description': 'An attacker attempts to lock out legitimate user accounts by triggering account lockout policies.',
                'likelihood': 'Medium',
                'severity': 'Low',
                'prerequisites': ['System has account lockout policy', 'Knowledge of valid usernames'],
                'skills': ['Low: Basic understanding of authentication systems'],
                'execution_steps': [
                    {'step': '1', 'phase': 'Explore', 'description': 'Identify valid user accounts'},
                    {'step': '2', 'phase': 'Experiment', 'description': 'Repeatedly attempt invalid logins'}
                ],
                'mitigations': ['Implement progressive delays', 'Monitor for lockout patterns'],
                'attack_mappings': []
            },
            {
                'capec_id': '98',
                'name': 'Phishing',
                'description': 'An attacker sends fraudulent communications that appear to come from a reputable source to steal sensitive data.',
                'likelihood': 'High',
                'severity': 'High',
                'prerequisites': ['Target uses email or messaging', 'Social engineering opportunity'],
                'skills': ['Medium: Social engineering and technical setup'],
                'execution_steps': [
                    {'step': '1', 'phase': 'Explore', 'description': 'Research target and create convincing pretext'},
                    {'step': '2', 'phase': 'Experiment', 'description': 'Send phishing messages to targets'}
                ],
                'mitigations': ['Security awareness training', 'Email filtering', 'Multi-factor authentication'],
                'attack_mappings': ['T1566.001', 'T1566.002']
            }
        ]
        
        # Process fallback patterns
        documents = []
        for pattern in fallback_patterns:
            processed_doc = self._process_capec_pattern(pattern)
            if processed_doc:
                documents.append(processed_doc)
        
        return documents
    
    def refresh_data(self) -> bool:
        """Force refresh of CAPEC data from source.
        
        Returns:
            bool: True if refresh successful
        """
        try:
            # Remove cache files
            if self.cache_file.exists():
                self.cache_file.unlink()
            if self.xml_cache_file.exists():
                self.xml_cache_file.unlink()
            
            # Reload data
            data = self.load_data()
            return len(data) > 0
            
        except Exception as e:
            logger.error(f"Data refresh failed: {e}")
            return False
    
    def get_source_info(self) -> Dict[str, Any]:
        """Get information about the data source.
        
        Returns:
            Source information dictionary
        """
        return {
            'source_type': 'Official MITRE CAPEC XML',
            'source_url': self.capec_xml_url,
            'cache_enabled': self.cache_enabled,
            'cache_duration_hours': self.cache_duration.total_seconds() / 3600,
            'cache_status': 'Valid' if self._is_cache_valid() else 'Invalid/Missing',
            'last_update': datetime.fromtimestamp(self.cache_file.stat().st_mtime).isoformat() if self.cache_file.exists() else 'Never'
        }