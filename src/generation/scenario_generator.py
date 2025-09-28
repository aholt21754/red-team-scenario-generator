# src/generation/scenario_generator.py
"""Main scenario generation orchestration."""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from database.vector_db import VectorDB
from generation.prompt_builder import PromptBuilder
from generation.llm_client import LLMClient
from evaluation.evaluator import ScenarioEvaluator
from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class ScenarioRequest:
    """Data class for scenario generation requests."""
    query: str
    environment: str = "Corporate"
    skill_level: str = "Intermediate"
    objectives: List[str] = None
    constraints: List[str] = None
    target_duration: str = "2-4 hours"
    team_size: int = 3
    
    def __post_init__(self):
        if self.objectives is None:
            self.objectives = []
        if self.constraints is None:
            self.constraints = []


@dataclass
class GeneratedScenario:
    """Data class for generated scenarios."""
    title: str
    description: str
    objective: str
    prerequisites: List[str]
    timeline: List[Dict[str, str]]
    techniques_used: List[str]
    detection_points: List[str]
    success_metrics: List[str]
    resources_required: List[str]
    evaluation_scores: Optional[Dict[str, float]] = None
    raw_response: str = ""
    target_weakness: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)
    exploitation_methods: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.target_weakness is None:
            self.target_weakness = []
        if self.attack_patterns is None:
            self.attack_patterns = []
        if self.exploitation_methods is None:
            self.exploitation_methods = []
        if self.mitigation_strategies is None:
            self.mitigation_strategies = []

class ScenarioGenerator:
    """Main class for generating red team scenarios."""
    
    def __init__(self, vector_db: VectorDB, llm_client: LLMClient = None, 
                 evaluator: ScenarioEvaluator = None):
        """Initialize scenario generator.
        
        Args:
            vector_db: Vector database instance
            llm_client: LLM client for generation (optional)
            evaluator: Scenario evaluator (optional)
        """
        self.vector_db = vector_db
        self.llm_client = llm_client or LLMClient()
        self.evaluator = evaluator or ScenarioEvaluator()
        self.prompt_builder = PromptBuilder()
        
        logger.info("ScenarioGenerator initialized")
    
    def generate_scenario(self, request: ScenarioRequest, 
                         evaluate: bool = True) -> GeneratedScenario:
        """Generate a complete red team scenario.
        
        Args:
            request: Scenario generation request
            evaluate: Whether to evaluate the generated scenario
            
        Returns:
            Generated scenario with optional evaluation
        """
        logger.info(f"Generating scenario for query: '{request.query}'")
        
        try:
            # Step 1: Query vector database for relevant techniques
            query_results = self._query_relevant_techniques(request)
            
            if not query_results or not query_results['documents']:
                logger.warning("No relevant techniques found")
                return self._create_fallback_scenario(request)
            
            # Step 2: Build LLM prompt
            prompt = self.prompt_builder.build_scenario_prompt(request, query_results)
            
            # Step 3: Generate scenario using LLM
            raw_response = self.llm_client.generate(prompt)
            
            if not raw_response:
                logger.error("LLM generation failed")
                return self._create_fallback_scenario(request)
            
            # Step 4: Parse response into structured scenario
            scenario = self._parse_scenario_response(raw_response, request)
            
            # Step 5: Evaluate scenario if requested
            if evaluate and self.evaluator:
                try:
                    evaluation = self.evaluator.evaluate_scenario(raw_response)
                    scenario.evaluation_scores = evaluation.get('scores', {}) if evaluation else {}
                except Exception as e:
                    logger.warning(f"Scenario evaluation failed: {e}")
                    scenario.evaluation_scores = {}
            
            logger.info(f"Successfully generated scenario: '{scenario.title}'")
            return scenario
            
        except Exception as e:
            logger.error(f"Scenario generation failed: {e}")
            return self._create_fallback_scenario(request)
    
    def generate_multiple_scenarios(self, request: ScenarioRequest, 
                                   count: int = 3) -> List[GeneratedScenario]:
        """Generate multiple scenario variants.
        
        Args:
            request: Base scenario request
            count: Number of scenarios to generate
            
        Returns:
            List of generated scenarios
        """
        scenarios = []
        
        for i in range(count):
            logger.info(f"Generating scenario variant {i+1}/{count}")
            
            # Add variation to the request
            varied_request = self._create_scenario_variation(request, i)
            scenario = self.generate_scenario(varied_request)
            scenarios.append(scenario)
        
        return scenarios
    
    def _query_relevant_techniques(self, request: ScenarioRequest) -> Optional[Dict]:
        """Enhanced query strategy leveraging CAPEC metadata filtering."""
        try:
            # Build base search query
            search_query = self._build_search_query(request)
            
            # First, get a broader set of results
            initial_results = self.vector_db.query(
                query_text=search_query,
                n_results=config.DEFAULT_N_RESULTS * 2  # Get more results for filtering
            )
            
            if not initial_results:
                return None
            
            # Apply CAPEC-aware filtering
            filtered_results = self._apply_capec_filtering(initial_results, request)
            
            # If we have good filtered results, use them; otherwise fall back to initial
            final_results = filtered_results if filtered_results['documents'] else initial_results
            
            # Limit to requested number
            if len(final_results['documents']) > config.DEFAULT_N_RESULTS:
                for key in final_results:
                    final_results[key] = final_results[key][:config.DEFAULT_N_RESULTS]
            
            logger.info(f"Enhanced query returned {len(final_results['documents'])} results")
            return final_results
            
        except Exception as e:
            logger.error(f"Enhanced query failed: {e}")
            return None

    def _apply_capec_filtering(self, results: Dict, request: ScenarioRequest) -> Dict:
        """Apply CAPEC-aware filtering based on request parameters."""
        if not results or not results.get('metadatas'):
            return results
        
        filtered_docs = []
        filtered_metas = []
        filtered_distances = []
        filtered_ids = []
        
        for i, metadata in enumerate(results['metadatas']):
            include_item = True
            
            # Filter by environment if it's a CAPEC pattern
            if metadata.get('type') == 'capec_pattern' and request.environment != "Generic":
                environments = metadata.get('environment_suitability', '').split(', ')
                if environments and request.environment not in environments:
                    # Only exclude if environment is explicitly incompatible
                    if 'General' not in environments and len(environments) > 0:
                        include_item = False
            
            # Filter by skill level if it's a CAPEC pattern
            if metadata.get('type') == 'capec_pattern' and include_item:
                pattern_skill = metadata.get('skill_level', '').lower()
                request_skill = request.skill_level.lower()
                
                # Skill level mapping
                skill_levels = {'beginner': 1, 'intermediate': 2, 'expert': 3}
                
                pattern_level = skill_levels.get(pattern_skill, 2)
                request_level = skill_levels.get(request_skill, 2)
                
                # Allow patterns at or below requested skill level
                if pattern_level > request_level + 1:  # Allow some flexibility
                    include_item = False
            
            # Filter by complexity for duration matching
            if metadata.get('type') == 'capec_pattern' and include_item:
                complexity = metadata.get('attack_complexity', '').lower()
                duration = request.target_duration.lower()
                
                # Simple heuristic: complex patterns need more time
                if 'high' in complexity and ('1' in duration or '30 min' in duration):
                    include_item = False
                elif 'low' in complexity and ('6' in duration or '8' in duration):
                    # Low complexity patterns might not fill long sessions well
                    pass  # Keep them but they'll rank lower
            
            if include_item:
                filtered_docs.append(results['documents'][i])
                filtered_metas.append(metadata)
                filtered_distances.append(results['distances'][i])
                filtered_ids.append(results['ids'][i])
        
        return {
            'documents': filtered_docs,
            'metadatas': filtered_metas,
            'distances': filtered_distances,
            'ids': filtered_ids
        }

    def _build_search_query(self, request: ScenarioRequest) -> str:
        """Enhanced search query building with CAPEC considerations."""
        query_parts = [request.query]
        
        # Add environment context
        if request.environment and request.environment != "Generic":
            query_parts.append(f"{request.environment} environment")
        
        # Add skill level context for CAPEC matching
        if request.skill_level:
            skill_terms = {
                'Beginner': ['basic', 'simple', 'low complexity'],
                'Intermediate': ['standard', 'moderate'],
                'Expert': ['advanced', 'complex', 'sophisticated']
            }
            if request.skill_level in skill_terms:
                query_parts.extend(skill_terms[request.skill_level])
        
        # Add objectives if specified
        if request.objectives:
            query_parts.extend(request.objectives)
        
        return " ".join(query_parts)

    def _parse_scenario_response(self, response: str, request: ScenarioRequest) -> GeneratedScenario:
        """Enhanced parsing with CAPEC structure awareness."""
        lines = response.split('\n')
        
        # Extract title
        title = "Generated Red Team Scenario"
        for line in lines:
            if line.strip() and not line.startswith('#'):
                title = line.strip()
                break
        
        # Enhanced parsing for CAPEC-informed content
        techniques_used = self._extract_techniques_from_response(response)
        detection_points = self._extract_detection_points_from_response(response)
        success_metrics = self._extract_success_metrics_from_response(response)
        timeline = self._extract_enhanced_timeline_from_response(response)
        vulnerability_info = self._extract_vulnerability_info_from_response(response)
        
        scenario = GeneratedScenario(
            title=title,
            description=response,
            objective=f"Execute {request.query} in {request.environment} environment",
            prerequisites=self._extract_prerequisites_from_response(response),
            timeline=timeline,
            techniques_used=techniques_used,
            detection_points=detection_points,
            success_metrics=success_metrics,
            resources_required=self._extract_resources_from_response(response),
            raw_response=response,
            target_weakness=vulnerability_info.get('target_weaknesses', []),
            attack_patterns=vulnerability_info.get('attack_patterns', []),
            exploitation_methods=vulnerability_info.get('exploitation_methods', []),
            mitigation_strategies=vulnerability_info.get('mitigation_strategies', [])
        )
        
        return scenario

    def _extract_techniques_from_response(self, response: str) -> List[str]:
        """Extract both ATT&CK techniques, CAPEC patterns, and CWE weaknesses from response."""
        techniques = []
        
        # Look for ATT&CK technique patterns (T####)
        mitre_pattern = re.compile(r'T\d{4}(?:\.\d{3})?')
        mitre_matches = mitre_pattern.findall(response)
        techniques.extend(mitre_matches)
        
        # Look for CAPEC pattern references (CAPEC-###)
        capec_pattern = re.compile(r'CAPEC-\d+')
        capec_matches = capec_pattern.findall(response)
        techniques.extend(capec_matches)

        # Look for CWE weakness references (CWE-###)
        cwe_pattern = re.compile(r'CWE-\d+')
        cwe_matches = cwe_pattern.findall(response)
        techniques.extend(cwe_matches)        
        
        # Remove duplicates while preserving order
        seen = set()
        unique_techniques = []
        for technique in techniques:
            if technique not in seen:
                seen.add(technique)
                unique_techniques.append(technique)
        
        return unique_techniques[:15]  # Limit to reasonable number

    def _extract_vulnerability_info_from_response(self, response: str) -> Dict[str, List[str]]:
        """Extract vulnerability and weakness information from response."""
        vulnerability_info = {
            'target_weaknesses': [],
            'attack_patterns': [],
            'exploitation_methods': [],
            'mitigation_strategies': []
        }
        
        # Extract target weaknesses section
        weakness_section = re.search(r'Target Weakness.*?:\s*([^\n]+)', response, re.IGNORECASE)
        if weakness_section:
            weakness_text = weakness_section.group(1)
            # Extract CWE references
            cwe_matches = re.findall(r'CWE-\d+[^,\n]*', weakness_text)
            vulnerability_info['target_weaknesses'] = cwe_matches
        
        # Extract attack patterns section
        pattern_section = re.search(r'Attack Patterns.*?:\s*([^\n]+)', response, re.IGNORECASE)
        if pattern_section:
            pattern_text = pattern_section.group(1)
            # Extract CAPEC references
            capec_matches = re.findall(r'CAPEC-\d+[^,\n]*', pattern_text)
            vulnerability_info['attack_patterns'] = capec_matches
        
        # Extract exploitation methods
        exploitation_section = re.search(r'Exploitation.*?:(.*?)(?=##|$)', response, re.IGNORECASE | re.DOTALL)
        if exploitation_section:
            exploitation_text = exploitation_section.group(1)
            # Extract bullet points or numbered items
            methods = re.findall(r'[-*]\s*([^\n]+)', exploitation_text)
            vulnerability_info['exploitation_methods'] = methods[:5]  # Limit to 5
        
        # Extract mitigation strategies
        mitigation_section = re.search(r'(?:Mitigation|Remediation).*?:(.*?)(?=##|$)', response, re.IGNORECASE | re.DOTALL)
        if mitigation_section:
            mitigation_text = mitigation_section.group(1)
            strategies = re.findall(r'[-*]\s*([^\n]+)', mitigation_text)
            vulnerability_info['mitigation_strategies'] = strategies[:5]  # Limit to 5
        
        return vulnerability_info

    def _extract_enhanced_timeline_from_response(self, response: str) -> List[Dict[str, str]]:
        """Extract timeline with CAPEC execution flow awareness."""
        timeline = []
        
        # Look for phase patterns that align with CAPEC execution flows
        phase_patterns = [
            r'Phase \d+:?\s*([^(]+)\s*\(([^)]+)\)',
            r'Step \d+:?\s*([^(]+)\s*\(([^)]+)\)',
            r'### ([^(]+)\s*\(([^)]+)\)',
            r'## ([^(]+)\s*\(([^)]+)\)'
        ]
        
        for pattern in phase_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                phase_name = match[0].strip()
                duration = match[1].strip()
                
                # Extract description for this phase
                phase_description = f"Execute {phase_name.lower()}"
                
                timeline.append({
                    "phase": phase_name,
                    "duration": duration,
                    "description": phase_description
                })
        
        # Fallback to default CAPEC-inspired timeline if none found
        if not timeline:
            timeline = [
                {"phase": "Reconnaissance", "duration": "30 minutes", "description": "Gather target information and identify attack vectors"},
                {"phase": "Resource Development", "duration": "45 minutes", "description": "Prepare tools and payloads for attack execution"},
                {"phase": "Initial Access", "duration": "1 hour", "description": "Establish initial foothold using identified vulnerabilities"},
                {"phase": "Execution", "duration": "90 minutes", "description": "Execute main attack objectives and techniques"},
                {"phase": "Impact & Cleanup", "duration": "30 minutes", "description": "Demonstrate impact and remove attack artifacts"}
            ]
        
        return timeline

    def _extract_detection_points_from_response(self, response: str) -> List[str]:
        """Extract detection opportunities with CAPEC mitigation awareness."""
        detection_points = []
        
        # Common detection patterns enhanced with CAPEC insights
        detection_keywords = [
            'monitoring', 'alerts', 'logs', 'detection', 'indicators',
            'anomalies', 'signatures', 'behavioral', 'network traffic',
            'file integrity', 'process monitoring', 'authentication logs'
        ]
        
        # Look for bullet points or numbered lists mentioning detection
        lines = response.split('\n')
        for line in lines:
            if any(keyword in line.lower() for keyword in detection_keywords):
                if any(marker in line for marker in ['•', '-', '*', '1.', '2.', '3.']):
                    clean_line = re.sub(r'^[\s\-\*\•\d\.]+', '', line).strip()
                    if clean_line and len(clean_line) > 10:
                        detection_points.append(clean_line)
        
        # Ensure we have some detection points
        if not detection_points:
            detection_points = [
                "Network traffic anomalies and unusual connection patterns",
                "Authentication system alerts for suspicious login attempts", 
                "Process monitoring for unexpected application behavior",
                "File system monitoring for unauthorized access attempts"
            ]
        
        return detection_points[:6]  # Reasonable limit

    def _extract_prerequisites_from_response(self, response: str) -> List[str]:
        """Extract prerequisites with CAPEC prerequisite awareness."""
        prerequisites = []
        
        # Look for prerequisite sections
        prereq_section_match = re.search(r'(?:prerequisites?|requirements?):?\s*\n((?:[-\*\•]\s*.+\n?)+)', response, re.IGNORECASE)
        
        if prereq_section_match:
            prereq_text = prereq_section_match.group(1)
            prereq_lines = prereq_text.split('\n')
            for line in prereq_lines:
                clean_line = re.sub(r'^[\s\-\*\•]+', '', line).strip()
                if clean_line and len(clean_line) > 5:
                    prerequisites.append(clean_line)
        
        # Fallback prerequisites
        if not prerequisites:
            prerequisites = [
                "Target system or application access",
                "Basic reconnaissance tools and techniques",
                "Understanding of target environment architecture",
                "Appropriate authorization for testing activities"
            ]
        
        return prerequisites[:5]

    def _extract_success_metrics_from_response(self, response: str) -> List[str]:
        """Extract success metrics from response."""
        success_metrics = []
        
        # Look for success/metrics sections
        lines = response.split('\n')
        in_metrics_section = False
        
        for line in lines:
            line_lower = line.lower()
            
            # Check if we're entering a metrics section
            if any(keyword in line_lower for keyword in ['success', 'metrics', 'criteria', 'objectives']):
                in_metrics_section = True
                continue
            
            # Check if we're leaving the section
            if in_metrics_section and line.startswith('#'):
                in_metrics_section = False
                continue
            
            # Extract metrics from bullet points
            if in_metrics_section and any(marker in line for marker in ['•', '-', '*', '1.', '2.', '3.']):
                clean_line = re.sub(r'^[\s\-\*\•\d\.]+', '', line).strip()
                if clean_line and len(clean_line) > 10:
                    success_metrics.append(clean_line)
        
        # Fallback metrics if none found
        if not success_metrics:
            success_metrics = [
                "Successful completion of attack objectives",
                "Demonstration of vulnerabilities without causing damage",
                "Documentation of attack path and techniques used",
                "Validation of detection and response capabilities"
            ]
        
        return success_metrics[:5]  # Limit to reasonable number

    def _extract_resources_from_response(self, response: str) -> List[str]:
        """Extract required resources from response."""
        resources = []
        
        # Look for resources/requirements sections
        lines = response.split('\n')
        in_resources_section = False
        
        for line in lines:
            line_lower = line.lower()
            
            # Check if we're entering a resources section
            if any(keyword in line_lower for keyword in ['resources', 'requirements', 'tools', 'equipment']):
                in_resources_section = True
                continue
            
            # Check if we're leaving the section
            if in_resources_section and line.startswith('#'):
                in_resources_section = False
                continue
            
            # Extract resources from bullet points
            if in_resources_section and any(marker in line for marker in ['•', '-', '*', '1.', '2.', '3.']):
                clean_line = re.sub(r'^[\s\-\*\•\d\.]+', '', line).strip()
                if clean_line and len(clean_line) > 5:
                    resources.append(clean_line)
        
        # Fallback resources if none found
        if not resources:
            resources = [
                "Red team testing toolkit",
                "Target environment access",
                "Testing authorization documentation",
                "Monitoring and logging access"
            ]
        
        return resources[:6]  # Limit to reasonable number

    def _extract_prerequisites_from_response(self, response: str) -> List[str]:
        """Extract prerequisites with CAPEC prerequisite awareness."""
        prerequisites = []
        
        # Look for prerequisite sections
        prereq_section_match = re.search(r'(?:prerequisites?|requirements?):?\s*\n((?:[-\*\•]\s*.+\n?)+)', response, re.IGNORECASE)
        
        if prereq_section_match:
            prereq_text = prereq_section_match.group(1)
            prereq_lines = prereq_text.split('\n')
            for line in prereq_lines:
                clean_line = re.sub(r'^[\s\-\*\•]+', '', line).strip()
                if clean_line and len(clean_line) > 5:
                    prerequisites.append(clean_line)
        
        # Fallback prerequisites
        if not prerequisites:
            prerequisites = [
                "Target system or application access",
                "Basic reconnaissance tools and techniques",
                "Understanding of target environment architecture",
                "Appropriate authorization for testing activities"
            ]
        
        return prerequisites[:5]
    
    def _create_fallback_scenario(self, request: ScenarioRequest) -> GeneratedScenario:
        """Create a basic fallback scenario when generation fails.
        
        Args:
            request: Original scenario request
            
        Returns:
            Basic fallback scenario
        """
        return GeneratedScenario(
            title=f"Basic {request.query} Scenario",
            description=f"A basic red team scenario for {request.query} in a {request.environment} environment.",
            objective=f"Demonstrate {request.query} techniques",
            prerequisites=["Basic red team tools", "Target environment access"],
            timeline=[
                {"phase": "Setup", "duration": "15 minutes", "description": "Prepare tools and environment"},
                {"phase": "Execution", "duration": "1 hour", "description": "Execute planned attack"},
                {"phase": "Cleanup", "duration": "15 minutes", "description": "Clean up artifacts"}
            ],
            techniques_used=["Basic techniques"],
            detection_points=["Standard monitoring"],
            success_metrics=["Scenario completed"],
            resources_required=["Standard red team toolkit"],
            raw_response="Fallback scenario - original generation failed"
        )
    
    def _create_scenario_variation(self, base_request: ScenarioRequest, 
                                 variant_index: int) -> ScenarioRequest:
        """Create a variation of the base scenario request.
        
        Args:
            base_request: Base scenario request
            variant_index: Index of the variant
            
        Returns:
            Modified scenario request
        """
        # Create variations by modifying aspects of the request
        variations = [
            {"skill_level": "Beginner", "target_duration": "1-2 hours"},
            {"skill_level": "Advanced", "target_duration": "4-6 hours"},
            {"environment": "Cloud", "constraints": ["No persistent access"]}
        ]
        
        if variant_index < len(variations):
            variation = variations[variant_index]
            # Create new request with modifications
            new_request = ScenarioRequest(
                query=base_request.query,
                environment=variation.get("environment", base_request.environment),
                skill_level=variation.get("skill_level", base_request.skill_level),
                objectives=base_request.objectives,
                constraints=variation.get("constraints", base_request.constraints),
                target_duration=variation.get("target_duration", base_request.target_duration),
                team_size=base_request.team_size
            )
            return new_request
        
        return base_request
    
    def get_scenario_suggestions(self, partial_query: str) -> List[str]:
        """Get scenario suggestions based on partial query.
        
        Args:
            partial_query: Partial user input
            
        Returns:
            List of suggested scenarios
        """
        try:
            results = self.vector_db.query(
                query_text=partial_query,
                n_results=5
            )
            
            suggestions = []
            if results and results['metadatas']:
                for metadata in results['metadatas']:
                    technique_name = metadata.get('name', '')
                    if technique_name and technique_name not in suggestions:
                        suggestions.append(f"{technique_name} scenario")
            
            return suggestions[:3]  # Return top 3 suggestions
            
        except Exception as e:
            logger.error(f"Failed to get suggestions: {e}")
            return []