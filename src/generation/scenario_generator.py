# src/generation/scenario_generator.py
"""Main scenario generation orchestration."""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass

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
        """Query vector database for techniques relevant to the request.
        
        Args:
            request: Scenario generation request
            
        Returns:
            Query results from vector database
        """
        try:
            # Build search query from request
            search_query = self._build_search_query(request)
            
            # Query vector database
            results = self.vector_db.query(
                query_text=search_query,
                n_results=config.DEFAULT_N_RESULTS
            )
            
            if results:
                logger.info(f"Found {len(results['documents'])} relevant techniques")
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to query techniques: {e}")
            return None
    
    def _build_search_query(self, request: ScenarioRequest) -> str:
        """Build search query from scenario request.
        
        Args:
            request: Scenario generation request
            
        Returns:
            Search query string
        """
        query_parts = [request.query]
        
        # Add environment context
        if request.environment and request.environment != "Generic":
            query_parts.append(f"{request.environment} environment")
        
        # Add objectives if specified
        if request.objectives:
            query_parts.extend(request.objectives)
        
        return " ".join(query_parts)
    
    def _parse_scenario_response(self, response: str, 
                               request: ScenarioRequest) -> GeneratedScenario:
        """Parse LLM response into structured scenario.
        
        Args:
            response: Raw LLM response
            request: Original request
            
        Returns:
            Structured scenario object
        """
        # Simple parsing - in production, you might use more sophisticated parsing
        lines = response.split('\n')
        
        # Extract title (first non-empty line or fallback)
        title = "Generated Red Team Scenario"
        for line in lines:
            if line.strip() and not line.startswith('#'):
                title = line.strip()
                break
        
        # For now, create a basic scenario structure
        # In production, you'd implement proper parsing of the LLM response
        scenario = GeneratedScenario(
            title=title,
            description=response[:500] + "..." if len(response) > 500 else response,
            objective=f"Execute {request.query} in {request.environment} environment",
            prerequisites=["Network access", "Basic tools", "Target reconnaissance"],
            timeline=[
                {"phase": "Reconnaissance", "duration": "30 minutes", "description": "Gather target information"},
                {"phase": "Initial Access", "duration": "1 hour", "description": "Establish foothold"},
                {"phase": "Execution", "duration": "2 hours", "description": "Execute main objectives"},
                {"phase": "Cleanup", "duration": "30 minutes", "description": "Remove traces"}
            ],
            techniques_used=["T1566.001", "T1190", "T1078"],  # These would be extracted from query results
            detection_points=["Email security alerts", "Network monitoring", "Login anomalies"],
            success_metrics=["Initial access achieved", "Objectives completed", "No detection"],
            resources_required=["Red team tools", "Test accounts", "Monitoring access"],
            raw_response=response
        )
        
        return scenario
    
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