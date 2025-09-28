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
        """Enhanced technique extraction supporting both MITRE and CAPEC data."""
        techniques = []
    
        if not query_results or not query_results.get('metadatas'):
            return techniques
    
        for i, metadata in enumerate(query_results['metadatas']):
            relevance_score = 1 - query_results['distances'][i] if i < len(query_results['distances']) else 0.5
        
            # Handle MITRE techniques
            if metadata.get('type') == 'mitre_technique':
                technique = {
                    'id': metadata.get('technique_id', 'Unknown'),
                    'name': metadata.get('name', 'Unknown Technique'),
                    'tactics': metadata.get('tactics', '').split(', ') if metadata.get('tactics') else [],
                    'platforms': metadata.get('platforms', '').split(', ') if metadata.get('platforms') else [],
                    'description': metadata.get('description', '')[:300],  # Truncate to reduce prompt size - does it need to be a little bigger?
                    'relevance_score': relevance_score,
                    'type': 'mitre_technique',
                    'source': 'MITRE ATT&CK'
            }
        
            # Handle CAPEC patterns - NEW ENHANCED SUPPORT
            elif metadata.get('type') == 'capec_pattern':
                technique = {
                    'id': f"CAPEC-{metadata.get('capec_id', 'Unknown')}",
                    'name': metadata.get('name', 'Unknown Pattern'),
                    'tactics': [],  # CAPEC doesn't use MITRE tactics directly
                    'platforms': [],
                    'description': metadata.get('description', '')[:300], # Truncate to reduce prompt size - does it need to be a little bigger?
                    'relevance_score': relevance_score,
                    'type': 'capec_pattern',
                    'source': 'CAPEC',
                    # Enhanced CAPEC-specific fields
                    'attack_complexity': metadata.get('attack_complexity', 'Unknown'),
                    'skill_level': metadata.get('skill_level', 'Unknown'),
                    'environment_suitability': metadata.get('environment_suitability', '').split(', ') if metadata.get('environment_suitability') else [],
                    'likelihood': metadata.get('likelihood', 'Unknown'),
                    'severity': metadata.get('severity', 'Unknown'),
                    'prerequisite_count': metadata.get('prerequisite_count', 0),
                    'mitigation_count': metadata.get('mitigation_count', 0),
                    'related_techniques': metadata.get('related_techniques', '').split(', ') if metadata.get('related_techniques') else []
                }
        
        # Only include techniques with reasonable relevance
        if relevance_score > 0.5:
            techniques.append(technique)
    
        # Sort by relevance score (highest first)
        techniques.sort(key=lambda x: x['relevance_score'], reverse=True)
    
        return techniques[:8]  # Increased limit to top 8 techniques

    #TODO: prompt hasn't been determined - there's a placeholder here but it's not final   
    def _build_main_prompt(self, request, techniques: List[Dict]) -> str:
        """Enhanced main prompt building with CAPEC integration."""
        prompt = f"""
    Generate a detailed, realistic red team attack scenario based on the following requirements:

    **Scenario Request:** {request.query}
    **Target Environment:** {request.environment}
    **Skill Level:** {request.skill_level}
    **Target Duration:** {request.target_duration}

    """

        if techniques:
            # Separate MITRE and CAPEC techniques
            mitre_techniques = [t for t in techniques if t['type'] == 'mitre_technique']
            capec_patterns = [t for t in techniques if t['type'] == 'capec_pattern']
            
            if mitre_techniques:
                prompt += f"""
**Relevant MITRE ATT&CK Techniques:**
"""
                for i, tech in enumerate(mitre_techniques, 1):
                    prompt += f"""
{i}. **{tech['name']} ({tech['id']})** [Relevance: {tech['relevance_score']:.2f}]
- Tactics: {', '.join(tech['tactics']) if tech['tactics'] else 'Multiple'}
- Platforms: {', '.join(tech['platforms']) if tech['platforms'] else 'Cross-platform'}
- Description: {tech['description']}
"""

            if capec_patterns:
                prompt += f"""

    **Relevant CAPEC Attack Patterns:**
    """
                for i, pattern in enumerate(capec_patterns, 1):
                    prompt += f"""
    {i}. **{pattern['name']} ({pattern['id']})** [Relevance: {pattern['relevance_score']:.2f}]
    - Attack Complexity: {pattern['attack_complexity']}
    - Required Skill Level: {pattern['skill_level']}
    - Suitable Environments: {', '.join(pattern['environment_suitability']) if pattern['environment_suitability'] else 'General'}
    - Likelihood: {pattern['likelihood']} | Severity: {pattern['severity']}
    - Prerequisites: {pattern['prerequisite_count']} items
    - Available Mitigations: {pattern['mitigation_count']} strategies
    - Related ATT&CK Techniques: {', '.join(pattern['related_techniques']) if pattern['related_techniques'] else 'None mapped'}
    - Description: {pattern['description']}
    """

            prompt += f"""

    **Enhanced Scenario Context:**

    **Requirements:**
    1. **Leverage both MITRE ATT&CK techniques AND CAPEC attack patterns** for comprehensive coverage
    2. **Match complexity to skill level**: Use CAPEC complexity ratings to ensure appropriate difficulty
    3. **Environment alignment**: Utilize CAPEC environment suitability data for realistic targeting
    4. **Realistic prerequisites**: Incorporate actual CAPEC prerequisite analysis
    5. **Balanced likelihood**: Consider CAPEC likelihood ratings for scenario realism
    6. **Comprehensive mitigations**: Include both preventive and detective controls
    7. **Attack pattern progression**: Show natural flow from CAPEC patterns to MITRE techniques
    8. **Skill-appropriate execution**: Align technical depth with specified skill level

    **Scenario Generation Guidelines:**
    - For **Beginner** scenarios: Focus on CAPEC patterns with "Low" complexity and clear prerequisites
    - For **Intermediate** scenarios: Combine multiple CAPEC patterns with moderate complexity
    - For **Expert** scenarios: Chain complex CAPEC patterns with advanced MITRE techniques
    - **Always** include realistic detection opportunities based on pattern characteristics
    - **Always** provide practical mitigation strategies drawn from CAPEC mitigation data
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

    def _add_output_format(self) -> str:
        """Enhanced output format instructions leveraging CAPEC structure."""
        format_instructions = """

    **Required Output Format (Enhanced with CAPEC Integration):**

    # [Scenario Title]

    ## Objective
    [Clear, concise mission statement aligned with CAPEC attack pattern goals]

    ## Prerequisites (CAPEC-Informed)
    - [Technical requirements based on CAPEC prerequisite analysis]
    - [Environmental conditions needed for attack success]
    - [Skill and knowledge requirements matching specified level]
    - [Tools and access requirements]

    ## Attack Pattern Foundation
    **Primary CAPEC Pattern(s):** [List main CAPEC patterns being demonstrated]
    **Supporting MITRE Techniques:** [List relevant ATT&CK techniques]
    **Attack Complexity:** [Based on CAPEC complexity assessment]
    **Likelihood/Severity:** [Based on CAPEC likelihood and severity ratings]

    ## Execution Timeline (CAPEC Execution Flow Based)
    ### Phase 1: Reconnaissance & Resource Development (Duration)
    - **CAPEC Preparation Steps:**
    - [Specific reconnaissance activities based on CAPEC prerequisites]
    - [Tool and payload preparation requirements]
    - **Expected Outcomes:** [What should be achieved in this phase]

    ### Phase 2: Initial Access & Exploitation (Duration)
    - **CAPEC Attack Execution:**
    - [Step-by-step implementation of CAPEC pattern]
    - [Integration with MITRE techniques where applicable]
    - **Technical Implementation:** [Specific commands, tools, or techniques]
    - **Expected Outcomes:** [Indicators of successful execution]

    ### Phase 3: Post-Exploitation & Impact Demonstration (Duration)
    - **Follow-on Activities:**
    - [Actions after successful initial exploitation]
    - [Demonstration of business impact]
    - **Evidence Collection:** [What to document for scenario completion]

    ### Phase 4: Detection Testing & Cleanup (Duration)
    - **Detection Validation:**
    - [Test detection capabilities based on CAPEC mitigation strategies]
    - [Verify monitoring and alerting effectiveness]
    - **Cleanup Activities:** [Remove artifacts and restore systems]

    ## Technical Implementation Details
    **Attack Vectors:** [Specific methods from CAPEC pattern analysis]
    **Tools Required:** [Based on CAPEC execution requirements and skill level]
    **Target Systems:** [Aligned with CAPEC environment suitability]
    **Payload/Exploit Details:** [Technical specifics appropriate to skill level]

    ## Detection Opportunities (CAPEC Mitigation-Informed)
    **Preventive Controls:**
    - [Controls that would prevent this CAPEC pattern]
    - [Input validation, access controls, etc.]

    **Detective Controls:**
    - [Monitoring and alerting for CAPEC pattern indicators]
    - [Log analysis and behavioral detection]

    **Response Actions:**
    - [Incident response procedures for this attack pattern]
    - [Containment and eradication steps]

    ## Success Metrics & Validation
    **Primary Objectives:**
    - [Core goals based on CAPEC pattern completion]
    - [Technical milestones for attack success]

    **Learning Objectives:**
    - [Skills and knowledge gained from this scenario]
    - [Understanding of attack pattern effectiveness]

    **Detection Effectiveness:**
    - [Validation of defensive capabilities]
    - [Gaps identified in monitoring and response]

    ## Resources Required
    **Personnel:** [Team roles and skill requirements]
    **Technical Resources:** [Systems, tools, and access needed]
    **Time Investment:** [Realistic time allocation per phase]
    **Environment Setup:** [Infrastructure and configuration requirements]

    ## Follow-up Recommendations
    **Immediate Actions:** [Priority remediation based on CAPEC mitigations]
    **Long-term Improvements:** [Strategic security enhancements]
    **Additional Testing:** [Related attack patterns to explore]

    ---

    **Scenario Characteristics:**
    - Complexity Level: [Based on CAPEC complexity rating]
    - Skill Level Required: [Aligned with CAPEC skill requirements]
    - Environment Applicability: [Based on CAPEC environment suitability]
    - Real-world Likelihood: [Based on CAPEC likelihood assessment]

    Ensure the scenario provides a realistic, educational experience that demonstrates both offensive techniques and defensive considerations while maintaining appropriate complexity for the specified skill level.
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