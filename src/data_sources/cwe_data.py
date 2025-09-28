# src/data_sources/cwe_data.py
"""Complete CWE data loading with proper ZIP file handling and method ordering."""

import xml.etree.ElementTree as ET
import requests
import json
import re
import zipfile
import io
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from data_sources.base_loader import BaseDataLoader
from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class CweDataLoader(BaseDataLoader):
    """Complete CWE loader with ZIP support and proper method structure."""
    
    def __init__(self, cache_enabled: bool = True, cache_duration_hours: int = 24):
        """Initialize CWE loader with ZIP parsing capabilities."""
        self.cache_enabled = cache_enabled
        self.cache_duration = timedelta(hours=cache_duration_hours)
        
        # Corrected CWE XML data sources (ZIP format)
        self.cwe_xml_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
        self.backup_urls = [
            "https://cwe.mitre.org/data/xml/cwec_v4.18.xml.zip",
            "https://cwe.mitre.org/data/xml/cwec_v4.17.xml.zip",
            "https://cwe.mitre.org/data/xml/cwec_v4.16.xml.zip"
        ]

        # XML namespace
        self.namespace = {'cwe': 'http://cwe.mitre.org/cwe-7',
                          'xhtml': 'http://www.w3.org/1999/xhtml',
        }
        
        # Cache file locations
        self.cache_dir = Path("data/cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "cwe_data.json"
        self.xml_cache_file = self.cache_dir / "cwec_latest.xml"
        self.zip_cache_file = self.cache_dir / "cwec_latest.xml.zip"
        
        logger.info(f"Initialized CWE loader with ZIP support, caching: {cache_enabled}")
    
    def _is_cache_valid(self) -> bool:
        """Check if cached data is still valid."""
        if not self.cache_file.exists():
            return False
        
        try:
            cache_time = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
            return datetime.now() - cache_time < self.cache_duration
        except Exception:
            return False
    
    def _load_from_cache(self) -> Optional[List[Dict]]:
        """Load data from cache file."""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load from cache: {e}")
            return None
    
    def _save_to_cache(self, data: List[Dict]) -> None:
        """Save data to cache file."""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Cached {len(data)} CWE weaknesses")
        except Exception as e:
            logger.warning(f"Failed to save to cache: {e}")
    
    def load_data(self) -> List[Dict[str, Any]]:
        """Load CWE data from ZIP XML source or cache."""
        logger.info("Loading CWE weakness data...")
        
        try:
            # Check cache first
            if self.cache_enabled and self._is_cache_valid():
                logger.info("Loading CWE data from cache...")
                cached_data = self._load_from_cache()
                if cached_data:
                    logger.info(f"Loaded {len(cached_data)} weaknesses from cache")
                    return cached_data
            
            # Download fresh data (ZIP format)
            xml_data = self._download_and_extract_cwe_data()
            if not xml_data:
                logger.warning("Failed to download CWE data, using fallback weaknesses")
                return self._get_fallback_weaknesses()
            
            # Parse XML data
            weaknesses = self._parse_cwe_xml(xml_data)
            if not weaknesses:
                logger.warning("Failed to parse CWE XML, using fallback weaknesses")
                return self._get_fallback_weaknesses()
            
            # Process weaknesses into documents
            documents = []
            for weakness in weaknesses:
                processed_doc = self._process_cwe_weakness(weakness)
                if processed_doc:
                    documents.append(processed_doc)
            
            # Cache the processed data
            if self.cache_enabled and documents:
                self._save_to_cache(documents)
            
            logger.info(f"Successfully loaded and processed {len(documents)} CWE weaknesses")
            return documents
            
        except Exception as e:
            logger.error(f"CWE data loading failed: {e}")
            return self._get_fallback_weaknesses()
    
    def _download_and_extract_cwe_data(self) -> Optional[str]:
        """Download CWE ZIP file and extract XML data."""
        urls_to_try = [self.cwe_xml_url] + self.backup_urls
        
        for url in urls_to_try:
            try:
                logger.info(f"Downloading CWE ZIP from: {url}")
                response = requests.get(url, timeout=90, stream=True)
                response.raise_for_status()
                
                zip_data = response.content
                logger.info(f"Downloaded {len(zip_data):,} bytes of ZIP data")
                
                # Cache the ZIP file
                if self.cache_enabled:
                    try:
                        with open(self.zip_cache_file, 'wb') as f:
                            f.write(zip_data)
                        logger.info("Cached CWE ZIP file")
                    except Exception as e:
                        logger.warning(f"Failed to cache ZIP: {e}")
                
                # Extract XML from ZIP
                xml_data = self._extract_xml_from_zip(zip_data)
                if xml_data:
                    return xml_data
                else:
                    logger.warning(f"Failed to extract XML from ZIP downloaded from {url}")
                    continue
                    
            except requests.RequestException as e:
                logger.warning(f"Failed to download from {url}: {e}")
                continue
            except Exception as e:
                logger.warning(f"Unexpected error downloading from {url}: {e}")
                continue
        
        # Try to use cached ZIP if download fails
        if self.cache_enabled and self.zip_cache_file.exists():
            try:
                logger.info("Attempting to use cached ZIP data...")
                with open(self.zip_cache_file, 'rb') as f:
                    zip_data = f.read()
                
                xml_data = self._extract_xml_from_zip(zip_data)
                if xml_data:
                    return xml_data
            except Exception as e:
                logger.warning(f"Failed to read cached ZIP: {e}")
        
        # Try cached XML directly
        if self.cache_enabled and self.xml_cache_file.exists():
            try:
                logger.info("Attempting to use cached XML data...")
                with open(self.xml_cache_file, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to read cached XML: {e}")
        
        logger.error("Failed to download CWE data from all sources")
        return None
    
    def _extract_xml_from_zip(self, zip_data: bytes) -> Optional[str]:
        """Extract XML data from ZIP file."""
        try:
            with zipfile.ZipFile(io.BytesIO(zip_data), 'r') as zip_file:
                # List files in ZIP
                file_list = zip_file.namelist()
                logger.info(f"ZIP contains files: {file_list}")
                
                # Look for XML file
                xml_filename = None
                for filename in file_list:
                    if filename.endswith('.xml') and ('cwec' in filename.lower() or 'cwe' in filename.lower()):
                        xml_filename = filename
                        break
                
                if not xml_filename:
                    # Take the first XML file
                    xml_files = [f for f in file_list if f.endswith('.xml')]
                    if xml_files:
                        xml_filename = xml_files[0]
                    else:
                        logger.error("No XML files found in ZIP")
                        return None
                
                logger.info(f"Extracting XML file: {xml_filename}")
                
                # Extract and read XML content
                with zip_file.open(xml_filename) as xml_file:
                    xml_content = xml_file.read().decode('utf-8')
                
                # Validate XML content
                if '<?xml' in xml_content and ('weakness' in xml_content.lower() or 'cwe' in xml_content.lower()):
                    logger.info(f"Successfully extracted {len(xml_content):,} characters of CWE XML")
                    
                    # Cache the extracted XML
                    if self.cache_enabled:
                        try:
                            with open(self.xml_cache_file, 'w', encoding='utf-8') as f:
                                f.write(xml_content)
                            logger.info("Cached extracted CWE XML")
                        except Exception as e:
                            logger.warning(f"Failed to cache extracted XML: {e}")
                    
                    return xml_content
                else:
                    logger.error("Extracted content doesn't appear to be valid CWE XML")
                    return None
                    
        except zipfile.BadZipFile as e:
            logger.error(f"Invalid ZIP file: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to extract XML from ZIP: {e}")
            return None
    
    def _parse_cwe_xml(self, xml_data: str) -> List[Dict]:
        """Parse CWE XML data into structured weaknesses."""
        try:
            logger.info("Parsing CWE XML data...")
            
            # Parse XML with namespace handling
            root = ET.fromstring(xml_data)
            
            # Find all weaknesses
            weaknesses = []
            
            # The structure is: Weakness_Catalog -> Weaknesses -> Weakness
            # All with namespace {http://cwe.mitre.org/cwe-7}
            weakness_elements = root.findall('.//cwe:Weakness', self.namespace)
            
            logger.info(f"Found {len(weakness_elements)} weakness elements in XML")            

            for weakness_elem in weakness_elements:
                try:
                    weakness = self._parse_single_weakness(weakness_elem, self.namespace)
                    if weakness:
                        weaknesses.append(weakness)
                except Exception as e:
                    logger.warning(f"Failed to parse individual weakness: {e}")
                    continue
            
            # Also look for categories (higher-level groupings)
            category_elements = root.findall('.//cwe:Category', self.namespace)
            
            logger.info(f"Found {len(category_elements)} category elements in XML")
            
            for category_elem in category_elements:
                try:
                    category = self._parse_single_category(category_elem, self.namespace)
                    if category:
                        weaknesses.append(category)
                except Exception as e:
                    logger.warning(f"Failed to parse individual category: {e}")
                    continue
            
            logger.info(f"Successfully parsed {len(weaknesses)} total CWE items")
            return weaknesses
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error parsing XML: {e}")
            return []
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize text content."""
        if not text:
            return ""
        
        # Remove excessive whitespace and normalize
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Remove HTML-like tags if present
        text = re.sub(r'<[^>]+>', '', text)
        
        return text
    
    def _extract_element_text(self, parent_elem, element_name: str, namespace: Dict) -> str:
        """Extract text from a child element, handling namespaces."""
    
        elem = parent_elem.find(f"cwe:{element_name}", namespace)
        if elem is None:
            # Try without namespace as fallback
            elem = parent_elem.find(element_name)        

        if elem is not None and elem.text:
            return self._clean_text(elem.text)
        return ""
    
    def _parse_single_weakness(self, weakness_elem, namespace: Dict) -> Optional[Dict]:
        """Parse a single weakness element."""
        try:
            # Extract basic attributes
            cwe_id = weakness_elem.get('ID', '')
            name = weakness_elem.get('Name', '')
            abstraction = weakness_elem.get('Abstraction', '')
            structure = weakness_elem.get('Structure', '')
            status = weakness_elem.get('Status', '')
            
            if not cwe_id or not name:
                return None
            
            # Skip deprecated weaknesses unless configured to include them
            if status == 'Deprecated' and not config.INCLUDE_DEPRECATED:
                return None
            
            # Extract description
            description = self._extract_element_text(weakness_elem, 'Description', namespace)
            
            # Extract extended description for more context
            extended_description = self._extract_element_text(weakness_elem, 'Extended_Description', namespace)
            if extended_description:
                description = f"{description} {extended_description}"
            
            # Extract consequences (CIA impact)
            consequences = self._extract_consequences(weakness_elem, namespace)
            
            # Extract likelihood and detection difficulty
            likelihood = self._extract_element_text(weakness_elem, 'Likelihood_Of_Exploit', namespace) or 'Unknown'
            detection_difficulty = self._extract_element_text(weakness_elem, 'Detection_Difficulty', namespace) or 'Unknown'
            
            # Extract applicable platforms
            platforms = self._extract_platforms(weakness_elem, namespace)
            
            # Extract potential mitigations
            mitigations = self._extract_mitigations(weakness_elem, namespace)
            
            # Extract relationships to other CWEs
            relationships = self._extract_relationships(weakness_elem, namespace)
            
            # Extract CAPEC mappings
            capec_mappings = self._extract_capec_mappings(weakness_elem, namespace)
            
            # Extract demonstrative examples
            examples = self._extract_examples(weakness_elem, namespace)
            
            # Extract detection methods
            detection_methods = self._extract_detection_methods(weakness_elem, namespace)
            
            return {
                'cwe_id': cwe_id,
                'name': name,
                'description': description,
                'abstraction': abstraction,
                'structure': structure,
                'status': status,
                'likelihood': likelihood,
                'detection_difficulty': detection_difficulty,
                'consequences': consequences,
                'platforms': platforms,
                'mitigations': mitigations,
                'relationships': relationships,
                'capec_mappings': capec_mappings,
                'examples': examples,
                'detection_methods': detection_methods,
                'type': 'weakness'
            }
            
        except Exception as e:
            logger.warning(f"Error parsing weakness {weakness_elem.get('ID', 'unknown')}: {e}")
            return None
    
    def _parse_single_category(self, category_elem, namespace: Dict) -> Optional[Dict]:
        """Parse a single category element."""
        try:
            # Extract basic attributes
            cwe_id = category_elem.get('ID', '')
            name = category_elem.get('Name', '')
            status = category_elem.get('Status', '')
            
            if not cwe_id or not name:
                return None
            
            # Skip deprecated categories unless configured to include them
            if status == 'Deprecated' and not config.INCLUDE_DEPRECATED:
                return None
            
            # Extract description/summary
            description = (
                self._extract_element_text(category_elem, 'Summary', namespace) or
                self._extract_element_text(category_elem, 'Description', namespace) or
                f"Category: {name}"
            )
            
            # Extract category relationships (member weaknesses)
            relationships = self._extract_category_relationships(category_elem, namespace)
            
            return {
                'cwe_id': cwe_id,
                'name': name,
                'description': description,
                'abstraction': 'Category',
                'structure': 'Simple',
                'status': status,
                'likelihood': 'N/A',
                'detection_difficulty': 'N/A',
                'consequences': [],
                'platforms': [],
                'mitigations': [],
                'relationships': relationships,
                'capec_mappings': [],
                'examples': [],
                'detection_methods': [],
                'type': 'category'
            }
            
        except Exception as e:
            logger.warning(f"Error parsing category {category_elem.get('ID', 'unknown')}: {e}")
            return None
    
    def _extract_consequences(self, weakness_elem, namespace: Dict) -> List[Dict[str, str]]:
        """Extract consequence information (CIA impact)."""
        consequences = []
        
        # Look for Common_Consequences with namespace
        consequences_elem = weakness_elem.find('cwe:Common_Consequences', namespace)
        if consequences_elem is None:
            consequences_elem = weakness_elem.find('Common_Consequences')
        
        if consequences_elem is not None:
            consequence_elems = consequences_elem.findall('cwe:Consequence', namespace)
            if not consequence_elems:
                consequence_elems = consequences_elem.findall('Consequence')
                
            for consequence in consequence_elems:
                scope = self._extract_element_text(consequence, 'Scope', namespace)
                impact = self._extract_element_text(consequence, 'Impact', namespace)
                note = self._extract_element_text(consequence, 'Note', namespace)
                
                if scope or impact:
                    consequences.append({
                        'scope': scope,
                        'impact': impact,
                        'note': note
                    })
        
        return consequences
    
    def _extract_platforms(self, weakness_elem, namespace: Dict) -> List[str]:
        """Extract applicable platforms."""
        platforms = []
        
        # Look for Applicable_Platforms
        platforms_elem = weakness_elem.find('.//Applicable_Platforms', namespace)
        
        if platforms_elem is not None:
            # Extract different platform types
            for platform_type in ['Language', 'Technology', 'Operating_System', 'Architecture']:
                platform_elems = platforms_elem.findall(f'.//{platform_type}', namespace)
                for platform in platform_elems:
                    name = platform.get('Name', '')
                    if name:
                        platforms.append(name)
        
        return list(set(platforms))  # Remove duplicates
    
    def _extract_mitigations(self, weakness_elem, namespace: Dict) -> List[Dict[str, str]]:
        """Extract mitigation strategies."""
        mitigations = []
        
        # Look for Potential_Mitigations
        mitigations_elem = weakness_elem.find('.//Potential_Mitigations', namespace)
        
        if mitigations_elem is not None:
            for mitigation in mitigations_elem.findall('.//Mitigation', namespace):
                phase = self._extract_element_text(mitigation, 'Phase', namespace)
                strategy = self._extract_element_text(mitigation, 'Strategy', namespace)
                description = self._extract_element_text(mitigation, 'Description', namespace)
                effectiveness = self._extract_element_text(mitigation, 'Effectiveness', namespace)
                
                if description:
                    mitigations.append({
                        'phase': phase,
                        'strategy': strategy,
                        'description': description,
                        'effectiveness': effectiveness
                    })
        
        return mitigations
    
    def _extract_relationships(self, weakness_elem, namespace: Dict) -> List[Dict[str, str]]:
        """Extract relationships to other CWEs."""
        relationships = []
        
        # Look for Related_Weaknesses
        relationships_elem = weakness_elem.find('.//Related_Weaknesses', namespace)
        
        if relationships_elem is not None:
            for related in relationships_elem.findall('.//Related_Weakness', namespace):
                nature = related.get('Nature', '')
                cwe_id = related.get('CWE_ID', '')
                view_id = related.get('View_ID', '')
                
                if nature and cwe_id:
                    relationships.append({
                        'nature': nature,
                        'cwe_id': cwe_id,
                        'view_id': view_id
                    })
        
        return relationships
    
    def _extract_capec_mappings(self, weakness_elem, namespace: Dict) -> List[str]:
        """Extract CAPEC attack pattern mappings."""
        capec_mappings = []
        
        # Look for Related_Attack_Patterns with namespace
        patterns_elem = weakness_elem.find('cwe:Related_Attack_Patterns', namespace)
        if patterns_elem is None:
            # Fallback without namespace
            patterns_elem = weakness_elem.find('Related_Attack_Patterns')
        
        if patterns_elem is not None:
            # Find all Related_Attack_Pattern elements
            attack_patterns = patterns_elem.findall('cwe:Related_Attack_Pattern', namespace)
            if not attack_patterns:
                # Fallback without namespace
                attack_patterns = patterns_elem.findall('Related_Attack_Pattern')
            
            for pattern in attack_patterns:
                capec_id = pattern.get('CAPEC_ID', '')
                if capec_id:
                    capec_mappings.append(f"CAPEC-{capec_id}")
        
        return capec_mappings
    
    def _extract_examples(self, weakness_elem, namespace: Dict) -> List[Dict[str, str]]:
        """Extract demonstrative examples."""
        examples = []
        
        # Look for Demonstrative_Examples
        examples_elem = weakness_elem.find('.//Demonstrative_Examples', namespace)
        
        if examples_elem is not None:
            for example in examples_elem.findall('.//Demonstrative_Example', namespace):
                intro_text = self._extract_element_text(example, 'Intro_Text', namespace)
                example_code = self._extract_element_text(example, 'Example_Code', namespace)
                body_text = self._extract_element_text(example, 'Body_Text', namespace)
                
                if intro_text or example_code or body_text:
                    examples.append({
                        'intro_text': intro_text,
                        'example_code': example_code[:500] if example_code else '',  # Limit code size
                        'body_text': body_text
                    })
        
        return examples[:3]  # Limit to 3 examples
    
    def _extract_detection_methods(self, weakness_elem, namespace: Dict) -> List[Dict[str, str]]:
        """Extract detection methods."""
        detection_methods = []
        
        # Look for Detection_Methods
        detection_elem = weakness_elem.find('.//Detection_Methods', namespace)
        
        if detection_elem is not None:
            for method in detection_elem.findall('.//Detection_Method', namespace):
                method_type = self._extract_element_text(method, 'Method', namespace)
                description = self._extract_element_text(method, 'Description', namespace)
                effectiveness = self._extract_element_text(method, 'Effectiveness', namespace)
                
                if method_type and description:
                    detection_methods.append({
                        'method': method_type,
                        'description': description,
                        'effectiveness': effectiveness
                    })
        
        return detection_methods
    
    def _extract_category_relationships(self, category_elem, namespace: Dict) -> List[Dict[str, str]]:
        """Extract category member relationships."""
        relationships = []
        
        # Look for Relationships
        relationships_elem = category_elem.find('.//Relationships', namespace)
        
        if relationships_elem is not None:
            for member in relationships_elem.findall('.//Has_Member', namespace):
                cwe_id = member.get('CWE_ID', '')
                view_id = member.get('View_ID', '')
                
                if cwe_id:
                    relationships.append({
                        'nature': 'Has_Member',
                        'cwe_id': cwe_id,
                        'view_id': view_id
                    })
        
        return relationships
    
    def _determine_impact_severity(self, weakness: Dict) -> str:
        """Determine impact severity based on consequences."""
        consequences = weakness.get('consequences', [])
        
        # Count high-impact consequences
        high_impact_indicators = ['complete', 'total', 'full', 'execute', 'bypass', 'gain']
        medium_impact_indicators = ['partial', 'some', 'limited']
        
        high_impact_count = 0
        medium_impact_count = 0
        
        for consequence in consequences:
            impact_text = (consequence.get('impact', '') + ' ' + 
                          consequence.get('note', '')).lower()
            
            if any(indicator in impact_text for indicator in high_impact_indicators):
                high_impact_count += 1
            elif any(indicator in impact_text for indicator in medium_impact_indicators):
                medium_impact_count += 1
        
        # Determine overall severity
        if high_impact_count >= 2:
            return "High"
        elif high_impact_count >= 1 or medium_impact_count >= 2:
            return "Medium"
        else:
            return "Low"
    
    def _determine_exploitation_complexity(self, weakness: Dict) -> str:
        """Determine exploitation complexity."""
        # Analyze abstraction level
        abstraction = weakness.get('abstraction', '').lower()
        
        # Analyze detection difficulty
        detection_difficulty = weakness.get('detection_difficulty', '').lower()
        
        # Analyze likelihood
        likelihood = weakness.get('likelihood', '').lower()
        
        # Analyze mitigation count (more mitigations usually means more complex to exploit)
        mitigation_count = len(weakness.get('mitigations', []))
        
        complexity_score = 0
        
        # Abstraction level scoring
        if 'variant' in abstraction:
            complexity_score += 3  # Variants are usually more specific/complex
        elif 'base' in abstraction:
            complexity_score += 2
        elif 'class' in abstraction:
            complexity_score += 1
        
        # Detection difficulty scoring
        if 'high' in detection_difficulty:
            complexity_score += 2
        elif 'medium' in detection_difficulty:
            complexity_score += 1
        
        # Likelihood scoring (inverse - low likelihood usually means high complexity)
        if 'low' in likelihood:
            complexity_score += 2
        elif 'medium' in likelihood:
            complexity_score += 1
        
        # Mitigation count scoring
        if mitigation_count > 3:
            complexity_score += 2
        elif mitigation_count > 1:
            complexity_score += 1
        
        # Determine complexity level
        if complexity_score >= 6:
            return "High"
        elif complexity_score >= 3:
            return "Medium"
        else:
            return "Low"
    
    def _determine_applicable_environments(self, weakness: Dict) -> List[str]:
        """Determine applicable environments based on weakness content."""
        environments = []
        
        # Analyze platforms and description for environment clues
        platforms = weakness.get('platforms', [])
        description = weakness.get('description', '').lower()
        name = weakness.get('name', '').lower()
        
        # Combine analysis text
        analysis_text = f"{' '.join(platforms)} {description} {name}".lower()
        
        # Web application environments
        if any(term in analysis_text for term in ['web', 'http', 'html', 'javascript', 'php', 'asp', 'jsp']):
            environments.append("Web Applications")
        
        # Network environments
        if any(term in analysis_text for term in ['network', 'tcp', 'udp', 'protocol', 'socket', 'dns']):
            environments.append("Network")
        
        # Mobile environments
        if any(term in analysis_text for term in ['mobile', 'android', 'ios', 'smartphone']):
            environments.append("Mobile")
        
        # Cloud environments
        if any(term in analysis_text for term in ['cloud', 'aws', 'azure', 'saas', 'api']):
            environments.append("Cloud")
        
        # Database environments
        if any(term in analysis_text for term in ['database', 'sql', 'mysql', 'postgresql', 'mongodb']):
            environments.append("Database")
        
        # Operating system environments
        if any(term in analysis_text for term in ['windows', 'linux', 'unix', 'macos', 'operating system']):
            environments.append("Operating System")
        
        # Corporate/Enterprise environments
        if any(term in analysis_text for term in ['enterprise', 'corporate', 'business', 'organization']):
            environments.append("Corporate")
        
        # Default if none detected
        if not environments:
            # Determine based on abstraction level
            abstraction = weakness.get('abstraction', '').lower()
            if 'class' in abstraction:
                environments = ["General"]
            else:
                environments = ["Software Development"]
        
        return environments
    
    def _create_comprehensive_document_text(self, weakness: Dict) -> str:
        """Create comprehensive document text for embedding."""
        parts = []
        
        # Basic information
        parts.append(f"CWE-{weakness['cwe_id']}: {weakness['name']}")
        parts.append(f"Abstraction: {weakness.get('abstraction', 'Unknown')}")
        parts.append(f"Description: {weakness['description']}")
        
        # Add likelihood and detection info
        if weakness.get('likelihood') != 'Unknown':
            parts.append(f"Exploitation Likelihood: {weakness['likelihood']}")
        if weakness.get('detection_difficulty') != 'Unknown':
            parts.append(f"Detection Difficulty: {weakness['detection_difficulty']}")
        
        # Add consequences (CIA impact)
        consequences = weakness.get('consequences', [])
        if consequences:
            parts.append("Potential Consequences:")
            for consequence in consequences[:3]:  # Limit to first 3
                scope = consequence.get('scope', '')
                impact = consequence.get('impact', '')
                if scope and impact:
                    parts.append(f"- {scope}: {impact}")
        
        # Add applicable platforms
        platforms = weakness.get('platforms', [])
        if platforms:
            parts.append(f"Applicable Platforms: {', '.join(platforms[:5])}")
        
        # Add mitigation strategies
        mitigations = weakness.get('mitigations', [])
        if mitigations:
            parts.append("Mitigation Strategies:")
            for mitigation in mitigations[:3]:  # Limit to first 3
                phase = mitigation.get('phase', '')
                description = mitigation.get('description', '')
                if description:
                    parts.append(f"- {phase}: {description[:200]}")  # Truncate long descriptions
        
        # Add CAPEC mappings
        capec_mappings = weakness.get('capec_mappings', [])
        if capec_mappings:
            parts.append(f"Related CAPEC Patterns: {', '.join(capec_mappings[:5])}")
        
        # Add detection methods
        detection_methods = weakness.get('detection_methods', [])
        if detection_methods:
            parts.append("Detection Methods:")
            for method in detection_methods[:2]:  # Limit to first 2
                method_type = method.get('method', '')
                description = method.get('description', '')
                if method_type:
                    parts.append(f"- {method_type}: {description[:150]}")  # Truncate
        
        # Add examples if available
        examples = weakness.get('examples', [])
        if examples:
            parts.append("Examples:")
            for example in examples[:1]:  # Just one example to avoid huge documents
                intro = example.get('intro_text', '')
                if intro:
                    parts.append(f"- {intro[:200]}")
        
        return '\n'.join(parts)
    
    def _process_cwe_weakness(self, weakness: Dict) -> Dict[str, Any]:
        """Process a parsed CWE weakness into a document."""
        try:
            cwe_id = weakness['cwe_id']
            name = weakness['name']
            description = weakness['description']
            
            # Determine impact severity based on consequences
            impact_severity = self._determine_impact_severity(weakness)
            
            # Determine exploitation complexity
            exploitation_complexity = self._determine_exploitation_complexity(weakness)
            
            # Determine applicable environments
            applicable_environments = self._determine_applicable_environments(weakness)
            
            # Create comprehensive document text
            doc_text = self._create_comprehensive_document_text(weakness)
            
            # Create metadata (ensure all values are simple types for ChromaDB)
            metadata = {
                'cwe_id': str(cwe_id),
                'name': name,
                'abstraction': weakness.get('abstraction', ''),
                'structure': weakness.get('structure', ''),
                'status': weakness.get('status', ''),
                'likelihood': weakness.get('likelihood', 'Unknown'),
                'detection_difficulty': weakness.get('detection_difficulty', 'Unknown'),
                'impact_severity': impact_severity,
                'exploitation_complexity': exploitation_complexity,
                'applicable_environments': ', '.join(applicable_environments),
                'type': self.get_data_type(),
                'description': description[:500],  # Truncate for metadata
                'consequence_count': len(weakness.get('consequences', [])),
                'mitigation_count': len(weakness.get('mitigations', [])),
                'example_count': len(weakness.get('examples', [])),
                'related_capec': ', '.join(weakness.get('capec_mappings', [])),
                'platform_count': len(weakness.get('platforms', [])),
                'detection_method_count': len(weakness.get('detection_methods', []))
            }
            
            return {
                'id': f"cwe_{cwe_id}",
                'document_text': doc_text,
                'metadata': metadata,
                'cwe_id': cwe_id,
                'name': name,
                'description': description,
                'abstraction': weakness.get('abstraction', ''),
                'consequences': weakness.get('consequences', []),
                'platforms': weakness.get('platforms', []),
                'mitigations': weakness.get('mitigations', []),
                'relationships': weakness.get('relationships', []),
                'capec_mappings': weakness.get('capec_mappings', []),
                'examples': weakness.get('examples', []),
                'detection_methods': weakness.get('detection_methods', []),
                'impact_severity': impact_severity,
                'exploitation_complexity': exploitation_complexity,
                'applicable_environments': applicable_environments
            }
            
        except Exception as e:
            logger.error(f"Failed to process CWE weakness {weakness.get('cwe_id', 'unknown')}: {e}")
            return None
    
    def transform_for_vector_db(self, data: List[Dict]) -> tuple:
        """Transform CWE data into format required by vector database.
        
        This method leverages the existing _process_cwe_weakness functionality
        to maintain consistency with other data loaders.
        
        Args:
            data: List of processed CWE weakness documents from load_data()
            
        Returns:
            Tuple of (documents, metadatas, ids) for vector DB
        """
        documents = []
        metadatas = []
        ids = []
        
        for weakness_doc in data:
            try:
                # The data from load_data() already has the right structure:
                # {
                #     'id': 'cwe_79',
                #     'document_text': comprehensive_text,
                #     'metadata': {...},
                #     'cwe_id': '79',
                #     'name': 'Cross-site Scripting',
                #     # ... other fields
                # }
                
                if 'document_text' in weakness_doc and 'metadata' in weakness_doc and 'id' in weakness_doc:
                    documents.append(weakness_doc['document_text'])
                    metadatas.append(weakness_doc['metadata'])
                    ids.append(weakness_doc['id'])
                else:
                    logger.warning(f"Skipping malformed weakness document: {weakness_doc.get('id', 'unknown')}")
                    continue
                    
            except Exception as e:
                logger.error(f"Failed to transform weakness document: {e}")
                continue
        
        logger.info(f"Transformed {len(documents)} CWE documents for vector database")
        return documents, metadatas, ids

    def _get_fallback_weaknesses(self) -> List[Dict[str, Any]]:
        """Get fallback CWE weaknesses when download/parsing fails."""
        logger.info("Using fallback CWE weaknesses")
        
        fallback_weaknesses = [
            {
                'cwe_id': '79',
                'name': 'Cross-site Scripting',
                'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
                'abstraction': 'Base',
                'structure': 'Simple',
                'status': 'Draft',
                'likelihood': 'High',
                'detection_difficulty': 'Easy',
                'consequences': [
                    {'scope': 'Confidentiality', 'impact': 'Read Application Data'},
                    {'scope': 'Integrity', 'impact': 'Execute Unauthorized Code or Commands'}
                ],
                'platforms': ['Web', 'JavaScript', 'PHP', 'ASP.NET'],
                'mitigations': [
                    {'phase': 'Implementation', 'description': 'Validate all input and encode output'},
                    {'phase': 'Architecture', 'description': 'Use Content Security Policy headers'}
                ],
                'capec_mappings': ['CAPEC-591', 'CAPEC-209'],
                'examples': [],
                'detection_methods': []
            },
            {
                'cwe_id': '89',
                'name': 'SQL Injection',
                'description': 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements.',
                'abstraction': 'Base',
                'structure': 'Simple',
                'status': 'Draft',
                'likelihood': 'High',
                'detection_difficulty': 'Easy',
                'consequences': [
                    {'scope': 'Confidentiality', 'impact': 'Read Application Data'},
                    {'scope': 'Integrity', 'impact': 'Modify Application Data'},
                    {'scope': 'Authorization', 'impact': 'Bypass Protection Mechanism'}
                ],
                'platforms': ['Database', 'SQL', 'Web'],
                'mitigations': [
                    {'phase': 'Implementation', 'description': 'Use parameterized queries'},
                    {'phase': 'Implementation', 'description': 'Validate and sanitize all input'}
                ],
                'capec_mappings': ['CAPEC-66', 'CAPEC-7'],
                'examples': [],
                'detection_methods': []
            },
            {
                'cwe_id': '20',
                'name': 'Improper Input Validation',
                'description': 'The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.',
                'abstraction': 'Class',
                'structure': 'Simple',
                'status': 'Draft',
                'likelihood': 'High',
                'detection_difficulty': 'Medium',
                'consequences': [
                    {'scope': 'Integrity', 'impact': 'Unexpected State'},
                    {'scope': 'Availability', 'impact': 'DoS: Crash, Exit, or Restart'}
                ],
                'platforms': ['All'],
                'mitigations': [
                    {'phase': 'Implementation', 'description': 'Assume all input is malicious'},
                    {'phase': 'Architecture', 'description': 'Use whitelist validation'}
                ],
                'capec_mappings': ['CAPEC-28', 'CAPEC-47'],
                'examples': [],
                'detection_methods': []
            },
            {
                'cwe_id': '287',
                'name': 'Improper Authentication',
                'description': 'When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.',
                'abstraction': 'Class',
                'structure': 'Simple',
                'status': 'Draft',
                'likelihood': 'High',
                'detection_difficulty': 'Medium',
                'consequences': [
                    {'scope': 'Access Control', 'impact': 'Bypass Protection Mechanism'},
                    {'scope': 'Confidentiality', 'impact': 'Read Application Data'}
                ],
                'platforms': ['All'],
                'mitigations': [
                    {'phase': 'Architecture', 'description': 'Use multi-factor authentication'},
                    {'phase': 'Implementation', 'description': 'Implement proper session management'}
                ],
                'capec_mappings': ['CAPEC-560', 'CAPEC-114'],
                'examples': [],
                'detection_methods': []
            },
            {
                'cwe_id': '502',
                'name': 'Deserialization of Untrusted Data',
                'description': 'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.',
                'abstraction': 'Base',
                'structure': 'Simple',
                'status': 'Draft',
                'likelihood': 'Medium',
                'detection_difficulty': 'High',
                'consequences': [
                    {'scope': 'Integrity', 'impact': 'Execute Unauthorized Code or Commands'},
                    {'scope': 'Availability', 'impact': 'DoS: Crash, Exit, or Restart'}
                ],
                'platforms': ['Java', '.NET', 'Python', 'PHP'],
                'mitigations': [
                    {'phase': 'Implementation', 'description': 'Avoid deserializing untrusted data'},
                    {'phase': 'Architecture', 'description': 'Use safe serialization formats like JSON'}
                ],
                'capec_mappings': ['CAPEC-586'],
                'examples': [],
                'detection_methods': []
            }
        ]
        
        # Process fallback weaknesses
        documents = []
        for weakness in fallback_weaknesses:
            processed_doc = self._process_cwe_weakness(weakness)
            if processed_doc:
                documents.append(processed_doc)
        
        return documents
    
    def validate_data(self, data: List[Dict]) -> bool:
        """Validate loaded CWE data."""
        if not data:
            logger.error("No CWE data to validate")
            return False
        
        required_fields = ['cwe_id', 'name', 'description', 'document_text']
        
        for i, doc in enumerate(data):
            for field in required_fields:
                if field not in doc:
                    logger.error(f"CWE document {i} missing required field: {field}")
                    return False
            
            # Validate CWE ID format
            cwe_id = doc['cwe_id']
            if not cwe_id or not str(cwe_id).isdigit():
                logger.error(f"Invalid CWE ID format: {cwe_id}")
                return False
        
        logger.info(f"Validated {len(data)} CWE documents")
        return True
    
    def get_data_type(self) -> str:
        """Get the data type identifier."""
        return "cwe_weakness"
    
    def refresh_data(self) -> bool:
        """Force refresh of CWE data from source."""
        try:
            # Remove cache files
            if self.cache_file.exists():
                self.cache_file.unlink()
            if self.xml_cache_file.exists():
                self.xml_cache_file.unlink()
            if self.zip_cache_file.exists():
                self.zip_cache_file.unlink()
            
            # Reload data
            data = self.load_data()
            return len(data) > 0
            
        except Exception as e:
            logger.error(f"Data refresh failed: {e}")
            return False
    
    def get_source_info(self) -> Dict[str, Any]:
        """Get information about the data source."""
        return {
            'source_type': 'Official MITRE CWE XML (ZIP format)',
            'source_url': self.cwe_xml_url,
            'cache_enabled': self.cache_enabled,
            'cache_duration_hours': self.cache_duration.total_seconds() / 3600,
            'cache_status': 'Valid' if self._is_cache_valid() else 'Invalid/Missing',
            'last_update': datetime.fromtimestamp(self.cache_file.stat().st_mtime).isoformat() if self.cache_file.exists() else 'Never'
        }
    
    def get_cwe_capec_mappings(self) -> Dict[str, List[str]]:
        """Get CWE to CAPEC mappings for cross-reference purposes."""
        try:
            data = self.load_data()
            mappings = {}
            
            for weakness in data:
                cwe_id = weakness.get('cwe_id')
                capec_mappings = weakness.get('capec_mappings', [])
                
                if cwe_id and capec_mappings:
                    mappings[f"CWE-{cwe_id}"] = capec_mappings
            
            return mappings
            
        except Exception as e:
            logger.error(f"Failed to extract CWE-CAPEC mappings: {e}")
            return {}

    def test_zip_download(self) -> bool:
        """Test method to verify ZIP download functionality."""
        try:
            logger.info("Testing CWE ZIP download...")
            
            xml_data = self._download_and_extract_cwe_data()
            if xml_data:
                logger.info(f"✅ Successfully downloaded and extracted {len(xml_data):,} characters of XML")
                
                # Quick validation
                if '<?xml' in xml_data and ('weakness' in xml_data.lower() or 'cwe' in xml_data.lower()):
                    logger.info("✅ XML appears to be valid CWE data")
                    return True
                else:
                    logger.warning("⚠️ XML doesn't appear to be CWE data")
                    return False
            else:
                logger.error("❌ Failed to download or extract XML")
                return False
                
        except Exception as e:
            logger.error(f"❌ ZIP download test failed: {e}")
            return False