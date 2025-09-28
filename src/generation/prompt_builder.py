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

    def build_evaluation_prompt(self, scenario_text: str) -> str:
        """Build evaluation prompt for scenario assessment.
        
        Args:
            scenario_text: Generated scenario to evaluate
            
        Returns:
            Evaluation prompt string
        """
        evaluation_prompt = f"""
You are an expert cybersecurity evaluator. Assess the following red team scenario on these criteria using a scale of 1-5 (1 = Poor, 5 = Excellent):

**Scenario to Evaluate:**
{scenario_text}

**Evaluation Criteria (1-5 scale):**

1. **Level of Detail (1-5)**
   - Does the scenario provide sufficient technical specifics?
   - Are attack vectors clearly defined with step-by-step instructions?
   - Are timelines, tools, and resources specified?
   - Score 1: Lacks detail, vague descriptions and instructions
   - Score 2-3: Some detail but missing key elements - must include both attack steps and detection points
   - Score 4: Some gaps which could include missing detailed steps for executing vulnerabilities or detection points
   - Score 5: Comprehensive, actionable detail

2. **Technical Accuracy (1-5)**
   - Are the described techniques realistic and feasible?
   - Do the tools and methods align with actual attack patterns?
   - Are vulnerabilities and exploits technically sound?
   - Score 1-2: Significant technical errors
   - Score 3-4: Mostly accurate, minor issues
   - Score 5: Highly accurate and realistic

3. **Realism (1-5)**
   - Would this scenario likely occur in a real environment?
   - Are the attacker motivations and capabilities believable?
   - Does the scenario reflect current threat landscape?
   - Score 1-2: Unrealistic or outdated
   - Score 3-4: Somewhat realistic
   - Score 5: Highly realistic and current

4. **Creativity (1-5)**
   - Does the scenario present novel attack approaches?
   - Are there innovative combinations of techniques?
   - Does it challenge defenders in new ways?
   - Score 1-2: Generic, predictable approach
   - Score 3-4: Some creative elements
   - Score 5: Highly innovative and challenging

5. **Match Environment and Skill Level (1-5)**
   - Did the scenario align well with the specified environment?
   - Did the scenario match the requested skill level (Beginner, Intermediate, Expert)?
   - Do the tools and techniques fit the requested skill level?
   - Do the defensive measures align with the environment and requested skill level?
   - Score 1: Totally misaligned
   - Score 2: Some overlap with requested environment/skill level, but mostly misaligned
   - Score 3: Matches some aspects of environment/skill level, but has notable misalignments or well aligned but only on either environment or skill level
   - Score 4: Mostly aligned with environment/skill level, minor misalignments
   - Score 5: Perfectly aligned with environment/skill level

   **Strengths**
    - Identify 2-3 key strengths of the scenario in terms of detail, accuracy, realism, creativity, or alignment.

   **Improvements**
    - Provide 2-3 specific suggestions for improving the scenario in terms of detail, accuracy, realism, creativity, or alignment.

**Required Output Format (JSON only):**
{{
    "scores": {{
        "level_of_detail": X,
        "technical_accuracy": X,
        "realism": X,
        "creativity": X,
        "alignment": X
    }},
    "overall_score": X.X,
    "strengths": ["strength1", "strength2", "strength3"],
    "improvements": ["improvement1", "improvement2"],
    "justification": "Brief explanation of scoring rationale (3 - 5 sentences)"
}}

Provide only the JSON response with no additional text.
"""
        
        logger.info("Built evaluation prompt")
        return evaluation_prompt
    
    def _extract_techniques(self, query_results: Dict) -> List[Dict]:
        """Enhanced technique extraction supporting both ATT&CK, CAPEC, and CWE data."""
        techniques = []
    
        if not query_results or not query_results.get('metadatas'):
            return techniques
    
        for i, metadata in enumerate(query_results['metadatas']):
            relevance_score = 1 - query_results['distances'][i] if i < len(query_results['distances']) else 0.5
        
            # Handle ATT&CK techniques
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
        
            # Handle CAPEC patterns 
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

            # Handle CWE weaknesses (NEW)
            elif metadata.get('type') == 'cwe_weakness':
                technique = {
                    'id': f"CWE-{metadata.get('cwe_id', 'Unknown')}",
                    'name': metadata.get('name', 'Unknown Weakness'),
                    'tactics': [],
                    'platforms': metadata.get('platforms', '').split(', ') if metadata.get('platforms') else [],
                    'description': metadata.get('description', '')[:300],
                    'relevance_score': relevance_score,
                    'type': 'cwe_weakness',
                    'source': 'CWE',
                    'abstraction': metadata.get('abstraction', 'Unknown'),
                    'impact_severity': metadata.get('impact_severity', 'Unknown'),
                    'exploitation_complexity': metadata.get('exploitation_complexity', 'Unknown'),
                    'applicable_environments': metadata.get('applicable_environments', '').split(', ') if metadata.get('applicable_environments') else [],
                    'capec_mappings': metadata.get('capec_mappings', '').split(', ') if metadata.get('capec_mappings') else [],
                    'mitigation_count': len(metadata.get('mitigations', [])) if metadata.get('mitigations') else 0,
                    'detection_methods': len(metadata.get('detection_methods', [])) if metadata.get('detection_methods') else 0
                }
        
        # Only include techniques with reasonable relevance
        if relevance_score > 0.5:
            techniques.append(technique)
    
        # Sort by relevance score (highest first)
        techniques.sort(key=lambda x: x['relevance_score'], reverse=True)
    
        return techniques[:10]  

    def _build_main_prompt(self, request, techniques: List[Dict]) -> str:
        """Enhanced main prompt building with ATT&CK, CAPEC, and CWE integration."""
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
            cwe_weaknesses = [t for t in techniques if t['type'] == 'cwe_weakness']
            
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

            if cwe_weaknesses:
             prompt += f"""

**Relevant CWE Weaknesses (Common Weakness Enumeration):**
"""
            for i, weakness in enumerate(cwe_weaknesses, 1):
                prompt += f"""
{i}. **{weakness['name']} ({weakness['id']})** [Relevance: {weakness['relevance_score']:.2f}]
- Abstraction Level: {weakness['abstraction']}
- Impact Severity: {weakness['impact_severity']}
- Exploitation Complexity: {weakness['exploitation_complexity']}
- Applicable Environments: {', '.join(weakness['applicable_environments']) if weakness['applicable_environments'] else 'General'}
- Related CAPEC Patterns: {', '.join(weakness['capec_mappings']) if weakness['capec_mappings'] else 'None mapped'}
- Available Mitigations: {weakness['mitigation_count']} strategies
- Detection Methods: {weakness['detection_methods']} approaches
- Description: {weakness['description']}
"""               

            prompt += f"""

    **Enhanced Scenario Context:**

    **Requirements:**
    1. **Leverage both MITRE ATT&CK techniques, CAPEC attack patterns, and CWE weaknesses** for comprehensive coverage
    2. **Map weakness exploitation to attack patterns**: Use CWE weaknesses as foundation for CAPEC pattern selection
    3. **Vulnerability-driven approach**: When CWE weaknesses are identified, prioritize scenarios that exploit those specific weaknesses
    4. **Complexity alignment**: Ensure CWE exploitation complexity matches CAPEC complexity and skill level requirements
    5. **Environment consistency**: Align CWE applicable environments with CAPEC environment suitability and requested target environment
    6. **Defense integration**: Combine CWE mitigation strategies with CAPEC defenses and ATT&CK detection opportunities.  Include both preventive and detective controls.
    7. **Realistic prerequisites**: Incorporate actual CAPEC prerequisite analysis
    8. **Balanced likelihood**: Consider CAPEC likelihood ratings for scenario realism
    9. **Attack pattern progression**: Show natural flow from CAPEC patterns to MITRE ATT&CK techniques
    
    
    **Scenario Generation Guidelines:**
    - For **Beginner** scenarios: Focus on CAPEC patterns with "Low" complexity and clear prerequisites
    - For **Intermediate** scenarios: Combine multiple CAPEC patterns with moderate complexity
    - For **Expert** scenarios: Chain complex CAPEC patterns with advanced MITRE techniques
    - **Realistic Vulnerability Chains**: Show progression from weakness discovery → pattern exploitation → technical implementation
    - **Weakness-First Approach**: When CWE data is available, start scenario design with the identified weakness as the foundation
    - **Always** include realistic detection opportunities based on pattern characteristics
    - **Always** provide practical mitigation strategies drawn from CAPEC mitigation data
    - **Layered Defense**: Include prevention (CWE mitigations), detection (ATT&CK monitoring), and response strategies
    
    """
    
        return prompt


    def _add_output_format(self) -> str:
        """Enhanced output format instructions leveraging ATT&CK, CAPEC, and CWE structure."""
        format_instructions = """

    **Required Output Format (Enhanced with ATT&CK, CAPEC, and CWE Integration):**

    # [Scenario Title]

    ## Objective
    [Clear, concise mission statement aligned with CAPEC attack pattern goals]

    ## Prerequisites 
    - [Technical requirements based on CAPEC prerequisite analysis]
    - [Environmental conditions needed for attack success]
    - [Skill and knowledge requirements matching specified level]
    - [Tools and access requirements]
    - [Vulnerability prerequisites based on CWE exploitation requirements]

    ## Attack Foundation
    **Target Vulnerabilities (CWE):** [List primary CWE weaknesses being exploited]
    **Attack Patterns (CAPEC):** [List main CAPEC patterns being demonstrated]
    **Implementation Techniques (ATT&CK):** [List relevant ATT&CK techniques]
    **Attack Complexity:** [Based on CWE exploitation complexity and CAPEC complexity assessment]
    **Likelihood/Severity:** [Based on CWE impact severity and CAPEC likelihood and severity ratings]

    ## Vulnerability Exploitation Chain
    ### Target Weakness Analysis
    - **Primary CWE Weakness(es):** [Specific weaknesses being targeted]
    - **Weakness Characteristics:** [Abstraction level, exploitation complexity, impact severity]
    - **Exploitation Conditions:** [Environmental and technical conditions required]
    - **Attack Surface:** [Where these weaknesses typically manifest]

    ### Attack Pattern Implementation
    - **CAPEC Pattern Selection:** [How CAPEC patterns target the identified CWE weaknesses]
    - **Pattern Prerequisites:** [Specific conditions needed for pattern success]
    - **Environmental Suitability:** [Target environments where pattern is most effective]

    ### Technical Execution Methods
    - **ATT&CK Technique Integration:** [How ATT&CK techniques implement the CAPEC patterns]
    - **Tool and Command Selection:** [Specific tools that exploit the target weaknesses]
    - **Implementation Considerations:** [Technical factors for successful exploitation]

    ## Execution Timeline (Vulnerability-Driven Approach)
    ### Phase 1: Vulnerability Discovery & Analysis (Duration)
    - **Weakness Identification:**
    - [Methods for discovering target CWE weaknesses in environment]
    - [Vulnerability assessment and confirmation techniques]
    - [Analysis of weakness exploitability conditions]
    - **Expected Outcomes:** [Confirmed presence and exploitability of target weaknesses]

    ### Phase 2: Attack Pattern Preparation (Duration)
    - **CAPEC Pattern Setup:**
    - [Preparation steps specific to chosen CAPEC patterns]
    - [Tool and payload development targeting identified weaknesses]
    - [Environmental condition validation]
    - **Expected Outcomes:** [Ready-to-execute attack components targeting confirmed weaknesses]

    ### Phase 3: Weakness Exploitation (Duration)
    - **CWE Exploitation Execution:**
    - [Step-by-step weakness exploitation using prepared CAPEC patterns]
    - [Implementation via specific MITRE ATT&CK techniques]
    - [Monitoring for successful weakness exploitation indicators]
    - **Expected Outcomes:** [Successful exploitation of target weaknesses achieving initial objectives]

    ### Phase 4: Impact Demonstration & Assessment (Duration)
    - **Exploitation Impact:**
    - [Demonstration of CWE weakness exploitation consequences]
    - [Validation of CAPEC pattern effectiveness]
    - [Documentation of attack technique success]
    - **Expected Outcomes:** [Clear evidence of weakness exploitation and business impact]

    ### Phase 5: Detection Testing & Remediation Validation (Duration)
    - **Detection Validation:**
    - [Test detection capabilities for CWE weakness exploitation]
    - [Verify monitoring for CAPEC pattern execution]
    - [Validate alerting on MITRE technique implementation]
    - **Cleanup Activities:** [Remove artifacts and restore systems to secure state]

    ## Technical Implementation Details
    **Vulnerability Targeting:** [Specific methods for exploiting identified CWE weaknesses]
    **Attack Vector Implementation:** [How CAPEC patterns are technically executed]
    **Tools Required:** [Based on CWE exploitation requirements, CAPEC execution needs, and skill level]
    **Target Systems:** [Aligned with CWE applicability and CAPEC environment suitability]
    **Payload/Exploit Details:** [Technical specifics for weakness exploitation appropriate to skill level]

    ## Defense Integration 
    **Preventive Controls (CWE-Focused):**
    - [Input validation and secure coding practices to prevent CWE weaknesses]
    - [Architectural controls addressing weakness root causes]
    - [Configuration and deployment controls reducing weakness exploitability]

    **Detective Controls (CAPEC-Informed):**
    - [Monitoring and alerting for CAPEC pattern indicators]
    - [Behavioral detection for attack pattern execution]
    - [Log analysis for pattern-specific artifacts]

    **Response Controls (ATT&CK-Aligned):**
    - [Incident response procedures for detected ATT&CK techniques]
    - [Containment strategies for specific technique implementations]
    - [Eradication steps targeting weakness remediation]

    ##Learning Objectives:**
    - [Understanding of specific weakness exploitation methods]
    - [Knowledge of attack pattern effectiveness and limitations]
    - [Skills in technique implementation and detection]


    ## Resources Required
    **Personnel:** [Team roles and skill requirements]
    **Technical Resources:** [Systems, tools, and access needed]
    **Time Investment:** [Realistic time allocation per phase]
    **Environment Setup:** [Infrastructure and configuration requirements]

    ---

    **Scenario Characteristics:**
    - Vulnerability Focus: [Primary CWE weakness categories being targeted]
    - Attack Complexity: [Based on CWE exploitation complexity and CAPEC ratings]
    - Skill Level Required: [Aligned with weakness exploitation requirements]
    - Environment Applicability: [Based on CWE applicability and CAPEC environment suitability]
    - Real-world Likelihood: [Based on CWE prevalence and CAPEC likelihood assessment]

    Ensure the scenario demonstrates a realistic vulnerability exploitation chain that shows how specific weaknesses (CWE) enable attack patterns (CAPEC) implemented through techniques (MITRE ATT&CK), providing comprehensive offensive and defensive learning opportunities.    """
        
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