# src/evaluation/evaluator.py
"""Scenario evaluation system using LLM-based assessment."""

import json
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class EvaluationResult:
    #TODO: this is temporary categories - need to determine if these are the final ones to be used - this is mostly for testing
    """Data class for evaluation results."""
    scores: Dict[str, int]
    overall_score: float
    strengths: List[str]
    improvements: List[str]
    justification: str
    raw_response: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "scores": self.scores,
            "overall_score": self.overall_score,
            "strengths": self.strengths,
            "improvements": self.improvements,
            "justification": self.justification
        }

class ScenarioEvaluator:
    """Evaluator for generated red team scenarios using the 5-criteria rubric."""
    
    def __init__(self, llm_client=None):
        """Initialize scenario evaluator.
        
        Args:
            llm_client: LLM client for evaluation (optional, will create if None)
        """
        # Import here to avoid circular imports
        if llm_client is None:
            from generation.llm_client import LLMClient
            self.llm_client = LLMClient()
        else:
            self.llm_client = llm_client
            
        self.criteria = config.EVALUATION_CRITERIA
        self.scale_max = config.EVALUATION_SCALE_MAX
        self.scale_min = config.EVALUATION_SCALE_MIN
        
        logger.info("ScenarioEvaluator initialized")
    
    def evaluate_scenario(self, scenario_text: str, 
                         use_fallback: bool = True) -> Optional[EvaluationResult]:
        """Evaluate a scenario using the 5-criteria rubric.
        
        Args:
            scenario_text: Generated scenario text to evaluate
            use_fallback: Whether to use fallback scoring if LLM fails
            
        Returns:
            EvaluationResult object or None if evaluation failed
        """
        logger.info("Starting scenario evaluation")
        
        try:
            # Import prompt builder here to avoid circular imports
            from generation.prompt_builder import PromptBuilder
            prompt_builder = PromptBuilder()
            
            # Build evaluation prompt
            evaluation_prompt = prompt_builder.build_evaluation_prompt(scenario_text)
            
            # Get LLM evaluation
            raw_response = self.llm_client.generate(
                prompt=evaluation_prompt,
                temperature=0.1,  # Low temperature for consistent evaluation
                max_tokens=1000
            )
            
            if raw_response:
                # Parse LLM response
                evaluation = self._parse_evaluation_response(raw_response)
                if evaluation:
                    evaluation.raw_response = raw_response
                    logger.info(f"Scenario evaluated with overall score: {evaluation.overall_score}")
                    return evaluation
            
            # Fallback to rule-based evaluation if LLM fails
            if use_fallback:
                logger.warning("LLM evaluation failed, using fallback evaluation")
                return self._fallback_evaluation(scenario_text)
            else:
                logger.error("LLM evaluation failed and fallback disabled")
                return None
                
        except Exception as e:
            logger.error(f"Scenario evaluation failed: {e}")
            
            if use_fallback:
                return self._fallback_evaluation(scenario_text)
            return None
    
    def evaluate_multiple_scenarios(self, scenarios: List[str]) -> List[EvaluationResult]:
        """Evaluate multiple scenarios.
        
        Args:
            scenarios: List of scenario texts to evaluate
            
        Returns:
            List of evaluation results
        """
        results = []
        
        for i, scenario in enumerate(scenarios):
            logger.info(f"Evaluating scenario {i+1}/{len(scenarios)}")
            
            evaluation = self.evaluate_scenario(scenario)
            if evaluation:
                results.append(evaluation)
            else:
                logger.warning(f"Failed to evaluate scenario {i+1}")
        
        return results
    
    def compare_scenarios(self, scenarios: List[str]) -> Dict[str, Any]:
        """Compare multiple scenarios and provide recommendations.
        
        Args:
            scenarios: List of scenario texts to compare
            
        Returns:
            Comparison results with recommendations
        """
        evaluations = self.evaluate_multiple_scenarios(scenarios)
        
        if not evaluations:
            return {"error": "No scenarios could be evaluated"}
        
        # Calculate statistics
        all_scores = []
        criterion_averages = {criterion: [] for criterion in self.criteria}
        
        for eval_result in evaluations:
            all_scores.append(eval_result.overall_score)
            for criterion, score in eval_result.scores.items():
                if criterion in criterion_averages:
                    criterion_averages[criterion].append(score)
        
        # Find best and worst scenarios
        best_idx = all_scores.index(max(all_scores))
        worst_idx = all_scores.index(min(all_scores))
        
        return {
            "total_scenarios": len(scenarios),
            "successfully_evaluated": len(evaluations),
            "best_scenario": {
                "index": best_idx,
                "score": evaluations[best_idx].overall_score,
                "strengths": evaluations[best_idx].strengths
            },
            "worst_scenario": {
                "index": worst_idx,
                "score": evaluations[worst_idx].overall_score,
                "improvements": evaluations[worst_idx].improvements
            },
            "average_scores": {
                "overall": sum(all_scores) / len(all_scores),
                "by_criterion": {
                    criterion: sum(scores) / len(scores) if scores else 0
                    for criterion, scores in criterion_averages.items()
                }
            },
            "recommendations": self._generate_recommendations(evaluations)
        }
    
    def _parse_evaluation_response(self, response: str) -> Optional[EvaluationResult]:
        """Parse LLM evaluation response into structured result.
        
        Args:
            response: Raw LLM response
            
        Returns:
            EvaluationResult object or None if parsing failed
        """
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                logger.error("No JSON found in evaluation response")
                return None
            
            json_str = json_match.group(0)
            eval_data = json.loads(json_str)
            
            # Validate required fields
            required_fields = ["scores", "overall_score", "strengths", "improvements", "justification"]
            for field in required_fields:
                if field not in eval_data:
                    logger.error(f"Missing required field in evaluation: {field}")
                    return None
            
            # Validate scores
            scores = eval_data["scores"]
            for criterion in self.criteria:
                if criterion not in scores:
                    logger.error(f"Missing score for criterion: {criterion}")
                    return None
                
                score = scores[criterion]
                if not isinstance(score, (int, float)) or not (self.scale_min <= score <= self.scale_max):
                    logger.error(f"Invalid score for {criterion}: {score}")
                    return None
            
            # Create evaluation result
            evaluation = EvaluationResult(
                scores=scores,
                overall_score=float(eval_data["overall_score"]),
                strengths=eval_data["strengths"] if isinstance(eval_data["strengths"], list) else [],
                improvements=eval_data["improvements"] if isinstance(eval_data["improvements"], list) else [],
                justification=eval_data["justification"]
            )
            
            return evaluation
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON in evaluation response: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to parse evaluation response: {e}")
            return None
    
    def _fallback_evaluation(self, scenario_text: str) -> EvaluationResult:
        """Provide fallback evaluation using rule-based analysis.
        
        Args:
            scenario_text: Scenario text to evaluate
            
        Returns:
            Basic evaluation result
        """
        logger.info("Performing fallback evaluation")
        
        # Basic text analysis
        word_count = len(scenario_text.split())
        line_count = len(scenario_text.split('\n'))
        
        # Rule-based scoring
        scores = {}
        
        # Level of Detail - based on length and structure
        if word_count > 800:
            scores["level_of_detail"] = 8
        elif word_count > 400:
            scores["level_of_detail"] = 6
        else:
            scores["level_of_detail"] = 4
        
        # Technical Accuracy - look for technical terms
        technical_terms = ["T1566", "MITRE", "ATT&CK", "technique", "payload", "exploit"]
        technical_score = sum(1 for term in technical_terms if term.lower() in scenario_text.lower())
        scores["technical_accuracy"] = min(5 + technical_score, 10)
        
        # Realism - look for realistic elements
        realistic_elements = ["timeline", "prerequisite", "detection", "tool", "access"]
        realism_score = sum(1 for element in realistic_elements if element.lower() in scenario_text.lower())
        scores["realism"] = min(4 + realism_score, 9)
        
        # Creativity - harder to assess automatically, use medium score
        scores["creativity"] = 6
        
        # Understandability - based on structure and clarity
        structure_indicators = ["#", "##", "objective", "step", "phase"]
        structure_score = sum(1 for indicator in structure_indicators if indicator.lower() in scenario_text.lower())
        scores["alignment"] = min(5 + structure_score, 9)
        
        # Calculate overall score
        overall_score = sum(scores.values()) / len(scores)
        
        # Generate basic feedback
        strengths = []
        improvements = []
        
        if word_count > 600:
            strengths.append("Comprehensive detail provided")
        if any(term in scenario_text.lower() for term in ["timeline", "phase"]):
            strengths.append("Clear timeline structure")
        if any(term in scenario_text.lower() for term in technical_terms[:3]):
            strengths.append("Good use of technical frameworks")
        
        if word_count < 300:
            improvements.append("Add more detailed implementation steps")
        if "detection" not in scenario_text.lower():
            improvements.append("Include detection opportunities")
        if scores["creativity"] <= 6:
            improvements.append("Consider more innovative attack approaches")
        
        return EvaluationResult(
            scores=scores,
            overall_score=round(overall_score, 1),
            strengths=strengths or ["Basic scenario structure present"],
            improvements=improvements or ["Consider adding more specific details"],
            justification="Fallback evaluation based on text analysis and common scenario elements"
        )
    
    def _generate_recommendations(self, evaluations: List[EvaluationResult]) -> List[str]:
        """Generate recommendations based on evaluation results.
        
        Args:
            evaluations: List of evaluation results
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Analyze common weaknesses
        all_improvements = []
        for evaluation in evaluations:
            all_improvements.extend(evaluation.improvements)
        
        # Count frequency of improvements
        improvement_counts = {}
        for improvement in all_improvements:
            improvement_counts[improvement] = improvement_counts.get(improvement, 0) + 1
        
        # Generate recommendations based on most common issues
        if improvement_counts:
            most_common = max(improvement_counts, key=improvement_counts.get)
            recommendations.append(f"Focus on improving: {most_common}")
        
        # Check overall score distribution
        scores = [eval_result.overall_score for eval_result in evaluations]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        if avg_score < 6:
            recommendations.append("Consider more detailed scenario planning and technical accuracy")
        elif avg_score > 8:
            recommendations.append("Scenarios show strong quality - consider advanced variations")
        
        # Check criterion-specific patterns
        criterion_scores = {criterion: [] for criterion in self.criteria}
        for evaluation in evaluations:
            for criterion, score in evaluation.scores.items():
                if criterion in criterion_scores:
                    criterion_scores[criterion].append(score)
        
        for criterion, scores in criterion_scores.items():
            if scores and sum(scores) / len(scores) < 6:
                recommendations.append(f"Improve {criterion.replace('_', ' ')}")
        
        return recommendations or ["Scenarios meet basic quality standards"]
    
    def get_evaluation_summary(self, evaluation: EvaluationResult) -> str:
        """Generate human-readable evaluation summary.
        
        Args:
            evaluation: Evaluation result
            
        Returns:
            Formatted summary string
        """
        summary = f"""
SCENARIO EVALUATION SUMMARY
{'=' * 40}

Overall Score: {evaluation.overall_score}/10

Detailed Scores:
"""
        
        for criterion, score in evaluation.scores.items():
            criterion_name = criterion.replace('_', ' ').title()
            summary += f"  {criterion_name}: {score}/10\n"
        
        summary += f"""
Strengths:
"""
        for strength in evaluation.strengths:
            summary += f"  ✓ {strength}\n"
        
        summary += f"""
Areas for Improvement:
"""
        for improvement in evaluation.improvements:
            summary += f"  • {improvement}\n"
        
        summary += f"""
Justification:
{evaluation.justification}
"""
        
        return summary