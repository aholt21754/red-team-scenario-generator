# test_evaluator.py
"""Debug script to test evaluator functionality step by step."""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.append(str(src_path))

from evaluation.evaluator import ScenarioEvaluator
from generation.llm_client import LLMClient
from utils.logging_config import setup_logging

def test_evaluator_step_by_step():
    """Test evaluator component by component."""
    
    setup_logging()
    
    print("=== EVALUATOR DEBUG ===")
    
    # Test 1: Initialize evaluator
    print("1. Testing evaluator initialization...")
    try:
        evaluator = ScenarioEvaluator()
        print(f"✅ Evaluator initialized")
        print(f"   LLM Provider: {evaluator.llm_client.provider}")
        print(f"   Criteria: {evaluator.criteria}")
        print(f"   Scale: {evaluator.scale_min}-{evaluator.scale_max}")
    except Exception as e:
        print(f"❌ Evaluator initialization failed: {e}")
        return False
    
    # Test 2: Test LLM client separately
    print("\n2. Testing LLM client for evaluation...")
    try:
        test_prompt = "Rate this scenario from 1-10: A simple phishing test."
        response = evaluator.llm_client.generate(test_prompt, max_tokens=100)
        if response:
            print(f"✅ LLM client working")
            print(f"   Response length: {len(response)} chars")
            print(f"   Response preview: {response[:100]}...")
        else:
            print("❌ LLM client returned None")
            print("   Will use fallback evaluation")
    except Exception as e:
        print(f"❌ LLM client error: {e}")
    
    # Test 3: Test prompt building
    print("\n3. Testing evaluation prompt building...")
    try:
        from generation.prompt_builder import PromptBuilder
        prompt_builder = PromptBuilder()
        
        sample_scenario = """
# Phishing Attack Scenario
## Objective
Execute a spear-phishing campaign against corporate employees.
## Timeline
- Phase 1: Reconnaissance (30 min)
- Phase 2: Email crafting (1 hour)  
- Phase 3: Campaign execution (2 hours)
## Techniques Used
- T1566.001: Spear-phishing attachment
"""
        
        eval_prompt = prompt_builder.build_evaluation_prompt(sample_scenario)
        print(f"✅ Evaluation prompt built")
        print(f"   Prompt length: {len(eval_prompt)} chars")
        print(f"   Prompt preview:")
        print("   " + "="*50)
        print("   " + eval_prompt[:300] + "...")
        print("   " + "="*50)
        
    except Exception as e:
        print(f"❌ Prompt building failed: {e}")
        return False
    
    # Test 4: Test full evaluation with sample scenario
    print("\n4. Testing full scenario evaluation...")
    
    sample_scenario = """
# Corporate Email Phishing Exercise

## Objective
Demonstrate spear-phishing techniques in a controlled corporate environment to test defensive capabilities.

## Prerequisites
- Valid test accounts with limited privileges
- Email access to target environment
- Social engineering toolkit
- Authorization from management

## Attack Timeline
### Phase 1: Reconnaissance (30 minutes)
- Identify target employees through LinkedIn and company website
- Gather email addresses and organizational structure
- Research recent company news for pretext development

### Phase 2: Email Crafting (1 hour)
- Create convincing spear-phishing emails with malicious attachments
- Establish command and control infrastructure
- Test email delivery and evasion techniques

### Phase 3: Campaign Execution (2 hours)
- Send targeted phishing emails to identified employees
- Monitor for email opens and attachment execution
- Track successful credential harvesting or system access

## Techniques Used
- T1566.001: Spear-phishing with attachment
- T1078: Valid accounts for persistence
- T1083: File and directory discovery

## Success Metrics
- Email delivery rate above 90%
- Click-through rate of 15% or higher
- Successful credential capture from at least 3 targets
"""
    
    try:
        print("   Evaluating sample scenario...")
        evaluation = evaluator.evaluate_scenario(sample_scenario, use_fallback=True)
        
        if evaluation:
            print("✅ Evaluation completed!")
            print(f"   Overall Score: {evaluation.overall_score}/5")
            print(f"   Individual Scores:")
            for criterion, score in evaluation.scores.items():
                print(f"     {criterion}: {score}/5")
            print(f"   Strengths: {evaluation.strengths}")
            print(f"   Improvements: {evaluation.improvements}")
            print(f"   Justification: {evaluation.justification[:100]}...")
            
            return True
        else:
            print("❌ Evaluation returned None")
            return False
            
    except Exception as e:
        print(f"❌ Evaluation failed: {e}")
        import traceback
        print("   Full traceback:")
        traceback.print_exc()
        return False

def test_fallback_evaluation():
    """Test just the fallback evaluation."""
    print("\n" + "="*60)
    print("TESTING FALLBACK EVALUATION ONLY")
    print("="*60)
    
    try:
        # Create evaluator without LLM (force fallback)
        evaluator = ScenarioEvaluator()
        
        sample_text = """
        This is a detailed phishing scenario with multiple phases.
        It includes MITRE ATT&CK techniques T1566.001 and proper timeline.
        The scenario has clear objectives and detection opportunities.
        """
        
        print("Testing fallback evaluation...")
        evaluation = evaluator._fallback_evaluation(sample_text)
        
        print("✅ Fallback evaluation completed!")
        print(f"   Overall Score: {evaluation.overall_score}/10")
        print(f"   Scores: {evaluation.scores}")
        print(f"   Strengths: {evaluation.strengths}")
        print(f"   Improvements: {evaluation.improvements}")
        
    except Exception as e:
        print(f"❌ Fallback evaluation failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    success = test_evaluator_step_by_step()
    
    if not success:
        print("\nTrying fallback evaluation only...")
        test_fallback_evaluation()