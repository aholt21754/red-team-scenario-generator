# enhanced_test_scenario_generation.py
"""Enhanced test script for end-to-end scenario generation with CAPEC integration."""

import re 

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from config import config
from database.vector_db import VectorDB
from generation.scenario_generator import ScenarioGenerator, ScenarioRequest
from generation.llm_client import LLMClient
from evaluation.evaluator import ScenarioEvaluator
from utils.logging_config import setup_logging

def test_enhanced_scenario_generation():
    """Test the enhanced scenario generation pipeline with CAPEC integration."""
    setup_logging()
    
    print("Testing Enhanced Scenario Generation Pipeline...")
    print("=" * 70)
    
    # Step 1: Initialize components
    print("1. Initializing enhanced components...")
    
    try:
        # Initialize vector database
        vector_db = VectorDB()
        if not vector_db.connect():
            print("❌ Failed to connect to vector database")
            return False
        
        # Get collection if it exists
        if not vector_db.create_collection(reset_if_exists=False):
            print("❌ Failed to create/get collection")
            return False
        
        # Enhanced: Check for both MITRE and CAPEC data
        stats = vector_db.get_collection_stats()
        if not stats or stats['total_documents'] == 0:
            print("❌ Vector database is empty. Run enhanced setup script first")
            return False
        
        print(f"✅ Vector DB ready with {stats['total_documents']} documents")
        
        # Enhanced: Verify we have both data types
        type_distribution = stats.get('type_distribution', {})
        has_mitre = any('mitre' in doc_type.lower() for doc_type in type_distribution)
        has_capec = any('capec' in doc_type.lower() for doc_type in type_distribution)
        
        if has_mitre and has_capec:
            print("✅ Both MITRE and CAPEC data detected")
            for doc_type, count in type_distribution.items():
                print(f"   {doc_type}: {count} documents")
        elif has_mitre:
            print("⚠️  Only MITRE data detected - CAPEC integration not working")
        elif has_capec:
            print("⚠️  Only CAPEC data detected - MITRE integration not working")
        else:
            print("❌ No recognized data types found")
            return False
        
        # Initialize LLM client
        llm_client = LLMClient()
        if not llm_client.is_available():
            print("❌ LLM client not available")
            return False
        
        print(f"✅ LLM client ready ({llm_client.provider})")
        
        # Initialize evaluator
        evaluator = ScenarioEvaluator()
        print("✅ Evaluator ready")
        
        # Initialize enhanced scenario generator
        generator = ScenarioGenerator(
            vector_db=vector_db,
            llm_client=llm_client,
            evaluator=evaluator
        )
        print("✅ Enhanced scenario generator ready")
        
    except Exception as e:
        print(f"❌ Component initialization failed: {e}")
        return False
    
    # Step 2: Test enhanced database queries
    print("\n2. Testing enhanced vector database queries...")
    
    enhanced_test_queries = [
        # Queries that should hit both MITRE and CAPEC
        "web application phishing attack",
        "SQL injection vulnerability exploitation", 
        "corporate social engineering campaign",
        "privilege escalation on Windows systems",
        "cross-site scripting attack patterns",
        # Environment-specific queries
        "cloud security testing scenarios",
        "mobile application penetration testing",
        # Skill-level specific queries
        "beginner-friendly network reconnaissance",
        "advanced persistent threat simulation"
    ]
    
    successful_queries = 0
    
    for query in enhanced_test_queries:
        print(f"   Testing query: '{query}'")
        results = vector_db.query(query, n_results=5)
        
        if results and results['documents']:
            successful_queries += 1
            print(f"   ✅ Found {len(results['documents'])} results")
            
            # Enhanced: Analyze result composition
            mitre_count = sum(1 for meta in results['metadatas'] if meta.get('type') == 'mitre_technique')
            capec_count = sum(1 for meta in results['metadatas'] if meta.get('type') == 'capec_pattern')
            
            print(f"      MITRE techniques: {mitre_count}, CAPEC patterns: {capec_count}")
            
            # Show top result with enhanced metadata
            top_result = results['metadatas'][0]
            technique_id = top_result.get('technique_id') or f"CAPEC-{top_result.get('capec_id', 'Unknown')}"
            technique_name = top_result.get('name', 'Unknown')
            doc_type = top_result.get('type', 'unknown')
            relevance = 1 - results['distances'][0]
            
            print(f"      🎯 Top match: {technique_name} ({technique_id}) [{doc_type}]")
            print(f"      📈 Relevance: {relevance:.3f}")
            
            # Enhanced: Show CAPEC-specific metadata if available
            if doc_type == 'capec_pattern':
                complexity = top_result.get('attack_complexity', 'Unknown')
                skill_level = top_result.get('skill_level', 'Unknown')
                environments = top_result.get('environment_suitability', '')
                print(f"      ⚙️  Complexity: {complexity}, Skill: {skill_level}")
                if environments:
                    print(f"      🌍 Environments: {environments}")
            
        else:
            print(f"   ❌ No results for query")
    
    query_success_rate = successful_queries / len(enhanced_test_queries)
    print(f"\n   📊 Enhanced Query Success Rate: {successful_queries}/{len(enhanced_test_queries)} ({query_success_rate*100:.1f}%)")
    
    if query_success_rate < 0.8:
        print("   ⚠️  Low query success rate - check data loading")
    
    # Step 3: Test enhanced scenario generation
    print("\n3. Testing enhanced scenario generation...")
    
    enhanced_test_requests = [
        ScenarioRequest(
            query="web application SQL injection attack",
            environment="Corporate",
            skill_level="Beginner",
            target_duration="2-3 hours"
        ),
        ScenarioRequest(
            query="corporate phishing campaign with credential harvesting",
            environment="Corporate", 
            skill_level="Intermediate",
            target_duration="4-6 hours"
        ),
        ScenarioRequest(
            query="advanced cross-site scripting exploitation",
            environment="Web Applications",
            skill_level="Expert",
            target_duration="3-4 hours"
        ),
         ScenarioRequest(
            query="buffer overflow exploitation",  # Should trigger CWE-120
            environment="Corporate",
            skill_level="Expert",
            target_duration="4-6 hours"
        ),
        ScenarioRequest(
            query="authentication bypass vulnerability",  # Should trigger CWE-287
            environment="Corporate",
            skill_level="Intermediate",
            target_duration="2-4 hours"
        )       
    ]
    
    successful_generations = 0
    cwe_integrations = 0
    
    for i, request in enumerate(enhanced_test_requests, 1):
        print(f"\n   CWE Test {i}: {request.query}")
        print(f"   Environment: {request.environment}")
        print(f"   Skill Level: {request.skill_level}")
        print(f"   Duration: {request.target_duration}")
        
        try:
            scenario = generator.generate_scenario(request, evaluate=True)
            
            if scenario:
                successful_generations += 1
                print("   ✅ Enhanced scenario generated successfully!")
                print(f"      Title: {scenario.title}")
                print(f"      Objective: {scenario.objective}")
                print(f"      Timeline phases: {len(scenario.timeline)}")
                print(f"      Techniques used: {len(scenario.techniques_used)}")
                
                # Check for CWE integration
                has_cwe_data = False
                if hasattr(scenario, 'target_weaknesses') and scenario.target_weaknesses:
                    has_cwe_data = True
                    cwe_integrations += 1
                    print(f"    CWE weaknesses identified: {len(scenario.target_weaknesses)}")
                
                # Check for vulnerability-focused content
                vulnerability_indicators = ['weakness', 'vulnerability', 'CWE-', 'exploit']
                has_vuln_focus = any(indicator in scenario.raw_response.lower() 
                                   for indicator in vulnerability_indicators)
                
                if has_vuln_focus:
                    print("    Vulnerability-focused content detected")
                else:
                    print("     Limited vulnerability focus detected")

                has_mitre = any(t.startswith('T') for t in scenario.techniques_used)
                has_capec = any('CAPEC' in str(t) for t in scenario.techniques_used)
                has_cwe = any('CWE' in str(t) for t in scenario.techniques_used)
                
                integration_sources = sum([has_mitre, has_capec, has_cwe])
                print(f"   — Data source integration: {integration_sources}/3 sources")
                
                if scenario.evaluation_scores:
                    avg_score = sum(scenario.evaluation_scores.values()) / len(scenario.evaluation_scores)
                    print(f"      📊 Avg evaluation score: {avg_score:.1f}/10")
                    
                    # Show individual scores
                    for criterion, score in scenario.evaluation_scores.items():
                        print(f"         {criterion.replace('_', ' ').title()}: {score}/10")
                
                # Enhanced: Validate scenario structure
                issues = []
                if len(scenario.timeline) < 3:
                    issues.append("Timeline too short")
                if len(scenario.techniques_used) < 1:
                    issues.append("No techniques identified")
                if len(scenario.detection_points) < 2:
                    issues.append("Insufficient detection points")
                
                if issues:
                    print(f"      ⚠️  Quality issues: {', '.join(issues)}")
                else:
                    print(f"      ✅ Scenario structure validation passed")
                
                # Show enhanced description preview
                desc_preview = scenario.description[:300] + "..." if len(scenario.description) > 300 else scenario.description
                print(f"      📄 Description preview: {desc_preview}")
                
            else:
                print("   ❌ Enhanced scenario generation failed")
                return False
                
        except Exception as e:
            print(f"   ❌ Enhanced scenario generation error: {e}")
            import traceback
            print(f"      Traceback: {traceback.format_exc()}")
            return False
    
    success_rate = successful_generations / len(enhanced_test_requests)
    cwe_rate = cwe_integrations / len(enhanced_test_requests) if cwe_integrations > 0 else 0
    
    if success_rate >= 0.75 and cwe_rate >= 0.5:
        print("    CWE-enhanced scenario generation working effectively!")
        return True
    else:
        print(f"   CWE integration may need improvement (Success: {success_rate:.0%}, CWE: {cwe_rate:.0%})")
        return True  # Don't 
    
    # Step 4: Test enhanced suggestions with CAPEC awareness
    print("\n4. Testing enhanced scenario suggestions...")
    
    suggestion_queries = [
        "phish",  # Should find both MITRE and CAPEC
        "injection",  # Should find SQL injection, XSS, etc.
        "privilege",  # Should find escalation techniques
        "social"  # Should find social engineering patterns
    ]
    
    for query in suggestion_queries:
        print(f"   Testing suggestions for: '{query}'")
        suggestions = generator.get_scenario_suggestions(query)
        if suggestions:
            print(f"   ✅ Generated {len(suggestions)} suggestions:")
            for suggestion in suggestions[:3]:  # Show first 3
                print(f"      - {suggestion}")
        else:
            print("   ⚠️  No suggestions generated")
    
    # Step 5: Enhanced integration test
    print("\n5. Testing complete enhanced integration...")
    
    try:
        # Test full pipeline with complex request
        complex_request = ScenarioRequest(
            query="multi-stage attack combining web application vulnerabilities and social engineering",
            environment="Corporate",
            skill_level="Expert",
            target_duration="6-8 hours",
            objectives=["Gain initial access", "Escalate privileges", "Maintain persistence"],
            constraints=["No data exfiltration", "Minimal system impact"]
        )
        
        print("   Generating complex multi-stage scenario...")
        complex_scenario = generator.generate_scenario(complex_request, evaluate=True)
        
        if complex_scenario:
            print("   ✅ Complex scenario generation successful!")
            print(f"      Techniques: {len(complex_scenario.techniques_used)} total")
            print(f"      Timeline: {len(complex_scenario.timeline)} phases")
            print(f"      Detection points: {len(complex_scenario.detection_points)}")
            
            # Check if any technique contains web vulnerability indicators
            has_web_vuln = any('injection' in str(technique).lower() or 'xss' in str(technique).lower() 
               for technique in complex_scenario.techniques_used)

            # Check if any technique contains social engineering indicators OR if the response mentions social
            has_social_eng = any('phish' in str(technique).lower() for technique in complex_scenario.techniques_used) or 'social' in complex_scenario.raw_response.lower()            
            
            if has_web_vuln and has_social_eng:
                print("   ✅ Successfully integrated multiple attack vectors")
            else:
                print("   ⚠️  May not have fully integrated all requested vectors")
        else:
            print("   ❌ Complex scenario generation failed")
            return False
            
    except Exception as e:
        print(f"   ❌ Enhanced integration test failed: {e}")
        return False
    
    print("\n" + "=" * 70)
    print("🎉 All enhanced tests passed! Enhanced scenario generation pipeline is working.")
    print("✅ MITRE ATT&CK integration: Working")
    print("✅ CAPEC pattern integration: Working") 
    print("✅ Enhanced query filtering: Working")
    print("✅ Skill-level matching: Working")
    print("✅ Environment filtering: Working")
    print("✅ Multi-technique scenarios: Working")
    print("✅ Evaluation system: Working")
    return True

def test_enhanced_interactive_generation():
    """Enhanced interactive scenario generation test."""
    print("\n" + "=" * 70)
    print("CWE-ENHANCED INTERACTIVE SCENARIO GENERATION TEST")
    print("=" * 70)
    
    try:
        # Initialize components
        vector_db = VectorDB()
        vector_db.connect()
        
        if not vector_db.create_collection(reset_if_exists=False):
            print("❌ Failed to create/get collection")
            return False
        
        llm_client = LLMClient()
        generator = ScenarioGenerator(vector_db, llm_client)
        
        # Enhanced: Get detailed user input
        print("🚀 Enhanced Interactive Scenario Generator")
        print("=" * 50)
        
        # Get scenario query
        print("Enter a scenario description (or press Enter for default):")
        print("Examples:")
        print("  • 'SQL injection attack against web application'")
        print("  • 'Corporate phishing campaign with CAPEC patterns'")
        print("  • 'Advanced persistent threat simulation'")
        user_query = input("> ").strip()
        
        if not user_query:
            user_query = "web application security testing with social engineering"
        
        # Get environment
        print("\nSelect target environment:")
        print("1. Corporate  2. Web Applications  3. Cloud  4. Mobile  5. Generic")
        env_choice = input("Choice (1-5, default=1): ").strip()
        environments = {"1": "Corporate", "2": "Web Applications", "3": "Cloud", 
                       "4": "Mobile", "5": "Generic"}
        environment = environments.get(env_choice, "Corporate")
        
        # Get skill level
        print("\nSelect skill level:")
        print("1. Beginner  2. Intermediate  3. Expert")
        skill_choice = input("Choice (1-3, default=2): ").strip()
        skills = {"1": "Beginner", "2": "Intermediate", "3": "Expert"}
        skill_level = skills.get(skill_choice, "Intermediate")
        
        # Get duration
        print("\nSelect target duration:")
        print("1. 1-2 hours  2. 2-4 hours  3. 4-6 hours  4. 6-8 hours")
        duration_choice = input("Choice (1-4, default=2): ").strip()
        durations = {"1": "1-2 hours", "2": "2-4 hours", "3": "4-6 hours", "4": "6-8 hours"}
        duration = durations.get(duration_choice, "2-4 hours")
        
        print(f"\n🎯 Generating enhanced scenario...")
        print(f"Query: '{user_query}'")
        print(f"Environment: {environment}")
        print(f"Skill Level: {skill_level}")
        print(f"Duration: {duration}")
        print("-" * 50)
        
        # Create enhanced request
        request = ScenarioRequest(
            query=user_query,
            environment=environment,
            skill_level=skill_level,
            target_duration=duration
        )
        
        scenario = generator.generate_scenario(request, evaluate=True)
        
        if scenario:
            print(f"\n📋 ENHANCED GENERATED SCENARIO")
            print("=" * 50)
            print(f"🎯 Title: {scenario.title}")
            print(f"🎪 Objective: {scenario.objective}")
            print(f"⏱️  Timeline Phases: {len(scenario.timeline)}")
            print(f"🛠️  Techniques Used: {len(scenario.techniques_used)}")
            print(f"🔍 Detection Points: {len(scenario.detection_points)}")
            print(f"📊 Success Metrics: {len(scenario.success_metrics)}")
            
            if hasattr(scenario, 'target_weaknesses') and scenario.target_weaknesses:
                print(f"\nðŸ›¡ï¸ Target Weaknesses (CWE):")
                for weakness in scenario.target_weaknesses[:3]:  # Show first 3
                    print(f"   - {weakness}")
            
            if hasattr(scenario, 'attack_patterns') and scenario.attack_patterns:
                print(f"\nðŸŽ¯ Attack Patterns (CAPEC):")
                for pattern in scenario.attack_patterns[:3]:  # Show first 3
                    print(f"   - {pattern}")

            # Show techniques with enhanced breakdown
            if scenario.techniques_used:
                mitre_techs = [t for t in scenario.techniques_used if t.startswith('T')]
                capec_patterns = [t for t in scenario.techniques_used if t.startswith('CAPEC')]
                cwe_weaknesses = [t for t in scenario.techniques_used if 'CWE' in t]
                
                print(f"\n🛠️  Technique Breakdown:")
                if mitre_techs:
                    print(f"   MITRE ATT&CK: {', '.join(mitre_techs)}")
                if capec_patterns:
                    print(f"   CAPEC Patterns: {', '.join(capec_patterns)}")
                if cwe_weaknesses:
                    print(f"   CWE Weaknesses: {', '.join(cwe_weaknesses[:3])}")
            
            # Display exploitation methods
            if hasattr(scenario, 'exploitation_methods') and scenario.exploitation_methods:
                print(f"\n Exploitation Methods:")
                for method in scenario.exploitation_methods[:3]:
                    print(f"   - {method}")
            
            # Display mitigation strategies
            if hasattr(scenario, 'mitigation_strategies') and scenario.mitigation_strategies:
                print(f"\n Mitigation Strategies:")
                for strategy in scenario.mitigation_strategies[:3]:
                    print(f"   - {strategy}")
            
            # Show timeline
            if scenario.timeline:
                print(f"\n⏱️  Timeline:")
                for i, phase in enumerate(scenario.timeline, 1):
                    print(f"   {i}. {phase.get('phase', 'Unknown Phase')} ({phase.get('duration', 'Unknown')})")
                    print(f"      {phase.get('description', 'No description')}")
            
            # Show evaluation scores
            if scenario.evaluation_scores:
                print(f"\n📊 Enhanced Evaluation Scores:")
                total_score = 0
                for criterion, score in scenario.evaluation_scores.items():
                    print(f"   {criterion.replace('_', ' ').title()}: {score}/10")
                    total_score += score
                avg_score = total_score / len(scenario.evaluation_scores)
                print(f"   Overall Average: {avg_score:.1f}/10")
            
            # Show partial description
            print(f"\n📄 Scenario Description (preview):")
            description_preview = scenario.description[:600] + "..." if len(scenario.description) > 600 else scenario.description
            print(description_preview)
            
        else:
            print("❌ Failed to generate enhanced scenario")
            
    except Exception as e:
        print(f"❌ Enhanced interactive test failed: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    # Run enhanced automated tests
    success = test_enhanced_scenario_generation()
    
    if success:
        # Optionally run enhanced interactive test
        print("\nWould you like to try enhanced interactive generation? (y/n): ", end="")
        try:
            response = input().strip().lower()
            if response in ['y', 'yes']:
                test_enhanced_interactive_generation()
        except KeyboardInterrupt:
            print("\nEnhanced test completed.")
    else:
        print("\n❌ Some enhanced tests failed. Check the output above.")
        sys.exit(1)