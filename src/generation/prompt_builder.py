# src/generation/prompt_builder.py
"""Prompt building for scenario generation."""

from typing import Dict, Any, List
from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class PromptBuilder:
    """Builder for LLM prompts used in scenario generation."""
    
    def __init__(self):
        """Initialize prompt builder."""
        self.max_prompt_length = config.MAX_PROMPT_LENGTH
        self.include_examples = config.INCLUDE_EXAMPLES
        
    def build_scenario_prompt(self, request, query_results: Dict) -> str:
        """Build comprehensive scenario generation prompt.
        
        Args:
            request: ScenarioRequest object with user requirements
            query_results: Results from vector database query
            
        Returns:
            Formatted prompt string for LLM
        """
        try:
            # Extract and rank relevant techniques
            techniques = self._extract_techniques(query_results)
            
            # Build main prompt
            prompt = self._build_main_prompt(request, techniques)
            
            # Add examples if configured
            if self.include_examples:
                prompt += self._add_examples()
            
            # Add output format instructions
            prompt += self._add_output_format()
            
            # Ensure prompt doesn't exceed length limit
            if len(prompt) > self.max_prompt_length:
                prompt = self._truncate_prompt(prompt)
                logger.warning(f"Prompt truncated to {self.max_prompt_length} characters")
            
            logger.info(f"Built scenario prompt ({len(prompt)} characters)")
            return prompt
            
        except Exception as e:
            logger.error(f"Failed to build scenario prompt: {e}")
            return self._build_fallback_prompt(request)

    #TODO: evaluation criteria is still not finalized.  Will need to update here once finalized.
    def build_evaluation_prompt(self, scenario_text: str) -> str:
        """Build evaluation prompt for scenario assessment.
        
        Args:
            scenario_text: Generated scenario to evaluate
            
        Returns:
            Evaluation prompt string
        """
        evaluation_prompt = f"""
You are an expert cybersecurity evaluator. Assess the following red team scenario on these criteria using a scale of 1-10:

**Scenario to Evaluate:**
{scenario_text}

**Evaluation Criteria (1-10 scale):**

1. **Level of Detail (1-10)**
   - Does the scenario provide sufficient technical specifics?
   - Are attack vectors clearly defined with step-by-step instructions?
   - Are timelines, tools, and resources specified?
   - Score 1-3: Vague, missing critical details
   - Score 4-6: Adequate detail, some gaps
   - Score 7-10: Comprehensive, actionable detail

2. **Technical Accuracy (1-10)**
   - Are the described techniques realistic and feasible?
   - Do the tools and methods align with actual attack patterns?
   - Are vulnerabilities and exploits technically sound?
   - Score 1-3: Significant technical errors
   - Score 4-6: Mostly accurate, minor issues
   - Score 7-10: Highly accurate and realistic

3. **Realism (1-10)**
   - Would this scenario likely occur in a real environment?
   - Are the attacker motivations and capabilities believable?
   - Does the scenario reflect current threat landscape?
   - Score 1-3: Unrealistic or outdated
   - Score 4-6: Somewhat realistic
   - Score 7-10: Highly realistic and current

4. **Creativity (1-10)**
   - Does the scenario present novel attack approaches?
   - Are there innovative combinations of techniques?
   - Does it challenge defenders in new ways?
   - Score 1-3: Generic, predictable approach
   - Score 4-6: Some creative elements
   - Score 7-10: Highly innovative and challenging

5. **Understandability (1-10)**
   - Is the scenario clearly written and easy to follow?
   - Can stakeholders at different technical levels comprehend it?
   - Are complex concepts explained appropriately?
   - Score 1-3: Confusing or poorly written
   - Score 4-6: Understandable with effort
   - Score 7-10: Clear and accessible

**Required Output Format (JSON only):**
{{
    "scores": {{
        "level_of_detail": X,
        "technical_accuracy": X,
        "realism": X,
        "creativity": X,
        "understandability": X
    }},
    "overall_score": X.X,
    "strengths": ["strength1", "strength2", "strength3"],
    "improvements": ["improvement1", "improvement2"],
    "justification": "Brief explanation of scoring rationale (2-3 sentences)"
}}

Provide only the JSON response with no additional text.
"""
        
        logger.info("Built evaluation prompt")
        return evaluation_prompt
    
    def _extract_techniques(self, query_results: Dict) -> List[Dict]:
        """Extract and process techniques from query results.
        
        Args:
            query_results: Vector database query results
            
        Returns:
            List of processed technique information
        """
        techniques = []
        
        if not query_results or not query_results.get('metadatas'):
            return techniques
        
        for i, metadata in enumerate(query_results['metadatas']):
            # Calculate relevance score (convert distance to relevance)
            relevance_score = 1 - query_results['distances'][i] if i < len(query_results['distances']) else 0.5
            
            technique = {
                'id': metadata.get('technique_id', 'Unknown'),
                'name': metadata.get('name', 'Unknown Technique'),
                'tactics': metadata.get('tactics', []),
                'platforms': metadata.get('platforms', []),
                'description': metadata.get('description', '')[:300],  # Truncate for prompt
                'relevance_score': relevance_score,
                'type': metadata.get('type', 'unknown')
            }
            
            # Only include techniques with reasonable relevance
            if relevance_score > 0.3:
                techniques.append(technique)
        
        # Sort by relevance score (highest first)
        techniques.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return techniques[:5]  # Limit to top 5 most relevant

    #TODO: prompt hasn't been determined - there's a placeholder here but it's not final   
    def _build_main_prompt(self, request, techniques: List[Dict]) -> str:
        """Build the main scenario generation prompt.
        
        Args:
            request: ScenarioRequest object
            techniques: List of relevant techniques
            
        Returns:
            Main prompt string
        """
        prompt = f"""
Generate a detailed, realistic red team attack scenario based on the following requirements:

"""

 # TODO: Perhaps if time allows - add these back in - but for now leaving out to simplify prompt       
 #       if request.objectives:
 #           prompt += f"\n- Additional Objectives: {', '.join(request.objectives)}"
        
 #       if request.constraints:
 #           prompt += f"\n- Constraints: {', '.join(request.constraints)}"
        
        if techniques:
            prompt += f"""

**Relevant MITRE ATT&CK Techniques (prioritized by relevance):**
"""
            for i, tech in enumerate(techniques, 1):
                prompt += f"""
{i}. **{tech['name']} ({tech['id']})** [Relevance: {tech['relevance_score']:.2f}]
   - Tactics: {', '.join(tech['tactics']) if tech['tactics'] else 'Multiple'}
   - Platforms: {', '.join(tech['platforms']) if tech['platforms'] else 'Cross-platform'}
   - Description: {tech['description']}
"""
        
        prompt += f"""

**Scenario Context:**

**Requirements:**
1. Use realistic attack techniques that align with the provided MITRE ATT&CK techniques
2. Include specific tools, commands, and procedures where appropriate
3. Provide clear success criteria and detection opportunities
4. Ensure the scenario is ethical and suitable for authorized testing
5. Make it engaging and educational for the red team participants
"""
        
        return prompt

  #TODO: example needs to be finalized this is a placeholder  
    def _add_examples(self) -> str:
        """Add example scenarios for context.
        
        Returns:
            Example scenarios string
        """
        examples = """

**Example Scenario Structure:**
Title: "Corporate Email Compromise Campaign"
Objective: Demonstrate lateral movement following initial email compromise
Prerequisites: External email access, basic social engineering tools
Timeline:
- Phase 1 (30 min): Reconnaissance and target identification
- Phase 2 (1 hour): Spear-phishing campaign execution
- Phase 3 (90 min): Initial access and credential harvesting
- Phase 4 (60 min): Lateral movement and objective completion
Detection Points: Email security alerts, unusual login patterns, network traffic anomalies
Success Metrics: Successful credential harvesting, lateral movement to target systems
"""
        
        return examples

  #TODO: output format needs to be finalized - this is a placeholder  
    def _add_output_format(self) -> str:
        """Add output format instructions.
        
        Returns:
            Output format string
        """
        format_instructions = """

**Required Output Format:**

# [Scenario Title]

## Objective
[Clear, concise mission statement]

## Prerequisites
- [Required tools and access]
- [Necessary skills and knowledge]
- [Environmental requirements]

## Attack Timeline
### Phase 1: [Phase Name] (Duration)
- [Specific actions and techniques]
- [Expected outcomes]

### Phase 2: [Phase Name] (Duration)
- [Specific actions and techniques]
- [Expected outcomes]

[Continue for all phases...]

## Techniques Used
- [MITRE Technique ID]: [Brief description]
- [Additional techniques as relevant]

## Detection Opportunities
- [Where defenders might detect this activity]
- [Specific indicators to monitor]

## Success Metrics
- [Objective completion criteria]
- [Measurable outcomes]

## Resources Required
- [Tools and software needed]
- [Personnel requirements]
- [Access requirements]

## Cleanup and Documentation
- [Steps to remove artifacts]
- [Documentation requirements]

Ensure the scenario is detailed enough to execute but flexible enough to adapt to specific environments.
"""
        
        return format_instructions
    
    def _truncate_prompt(self, prompt: str) -> str:
        """Truncate prompt to maximum length while preserving structure.
        
        Args:
            prompt: Original prompt
            
        Returns:
            Truncated prompt
        """
        if len(prompt) <= self.max_prompt_length:
            return prompt
        
        # Try to truncate at a logical boundary
        truncation_point = self.max_prompt_length - 200  # Leave room for ending
        
        # Find the last complete section before truncation point
        lines = prompt[:truncation_point].split('\n')
        
        # Remove incomplete lines
        while lines and not lines[-1].strip():
            lines.pop()
        
        truncated = '\n'.join(lines)
        truncated += "\n\n[Prompt truncated - please provide a more specific query for detailed results]"
        
        return truncated
    
    def _build_fallback_prompt(self, request) -> str:
        """Build a basic fallback prompt when main prompt building fails.
        
        Args:
            request: ScenarioRequest object
            
        Returns:
            Fallback prompt string
        """
        fallback = f"""
Generate a red team scenario for: {request.query}

Environment: {request.environment}
Skill Level: {request.skill_level}
Duration: {request.target_duration}

Provide a basic attack scenario including:
1. Objective
2. Attack steps
3. Required tools
4. Success criteria

Keep it realistic and actionable.
"""
        
        logger.warning("Using fallback prompt due to error")
        return fallback
    
    def build_suggestion_prompt(self, partial_query: str, available_techniques: List[Dict]) -> str:
        """Build prompt for generating scenario suggestions.
        
        Args:
            partial_query: User's partial input
            available_techniques: Available techniques from database
            
        Returns:
            Suggestion prompt
        """
        techniques_list = []
        for tech in available_techniques[:10]:  # Limit to top 10
            techniques_list.append(f"- {tech.get('name', 'Unknown')} ({tech.get('technique_id', 'N/A')})")
        
        suggestion_prompt = f"""
Based on the partial query "{partial_query}" and available techniques, suggest 3-5 complete red team scenario ideas.

Available techniques include:
{chr(10).join(techniques_list)}

Provide realistic, actionable scenario suggestions that would be suitable for red team exercises.

Format as a simple list:
1. [Scenario name]: [Brief description]
2. [Scenario name]: [Brief description]
...
"""
        
        return suggestion_prompt