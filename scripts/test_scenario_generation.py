# test_scenario_generation.py
"""Test script for end-to-end scenario generation."""

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

def test_scenario_generation():
    """Test the full scenario generation pipeline."""
    setup_logging()
    
    print("Testing Scenario Generation Pipeline...")
    print("=" * 60)
    
    # Step 1: Initialize components
    print("1. Initializing components...")
    
    try:
        # Initialize vector database
        vector_db = VectorDB()
        if not vector_db.connect():
            print("❌ Failed to connect to vector database")
            return False
        
        # Get collection if it exists...
        if not vector_db.create_collection(reset_if_exists=False):
            print("❌ Failed to create/get collection")
            return False
        
        # Check if collection exists and has data
        stats = vector_db.get_collection_stats()
        if not stats or stats['total_documents'] == 0:
            print("❌ Vector database is empty. Run test_vector_db.py first")
            return False
        
        print(f"✅ Vector DB ready with {stats['total_documents']} documents")
        
        # Initialize LLM client
        llm_client = LLMClient()
        if not llm_client.is_available():
            print("❌ LLM client not available")
            return False
        
        print(f"✅ LLM client ready ({llm_client.provider})")
        
        # Initialize evaluator
        evaluator = ScenarioEvaluator()
        print("✅ Evaluator ready")
        
        # Initialize scenario generator
        generator = ScenarioGenerator(
            vector_db=vector_db,
            llm_client=llm_client,
            evaluator=evaluator
        )
        print("✅ Scenario generator ready")
        
    except Exception as e:
        print(f"❌ Component initialization failed: {e}")
        return False
    
    # Step 2: Test database queries
    print("\n2. Testing vector database queries...")
    
    test_queries = [
        "phishing email attack",
        "lateral movement",
        "privilege escalation"
    ]
    
    for query in test_queries:
        print(f"   Testing query: '{query}'")
        results = vector_db.query(query, n_results=3)
        
        if results and results['documents']:
            print(f"   ✅ Found {len(results['documents'])} results")
            # Show top result
            top_result = results['metadatas'][0]
            print(f"      Top result: {top_result.get('name', 'Unknown')} ({top_result.get('technique_id', 'N/A')})")
        else:
            print(f"   ❌ No results for query")
    
    # Step 3: Test scenario generation
    print("\n3. Testing scenario generation...")
    
    test_requests = [
        ScenarioRequest(
            query="phishing attack against corporate employees",
            environment="Corporate",
            skill_level="Beginner"
        ),
        ScenarioRequest(
            query="lateral movement using valid accounts",
            environment="Corporate",
            skill_level="Intermediate"
        )
    ]
    
    for i, request in enumerate(test_requests, 1):
        print(f"\n   Test {i}: {request.query}")
        print(f"   Environment: {request.environment}")
        print(f"   Skill Level: {request.skill_level}")
        
        try:
            scenario = generator.generate_scenario(request, evaluate=True)
            
            if scenario:
                print("   ✅ Scenario generated successfully!")
                print(f"      Title: {scenario.title}")
                print(f"      Objective: {scenario.objective}")
                print(f"      Timeline phases: {len(scenario.timeline)}")
                print(f"      Techniques: {len(scenario.techniques_used)}")
                
                if scenario.evaluation_scores:
                    avg_score = sum(scenario.evaluation_scores.values()) / len(scenario.evaluation_scores)
                    print(f"      Avg evaluation score: {avg_score:.1f}/10")
                
                # Show first few lines of description
                desc_preview = scenario.description[:200] + "..." if len(scenario.description) > 200 else scenario.description
                print(f"      Description preview: {desc_preview}")
                
            else:
                print("   ❌ Scenario generation failed")
                return False
                
        except Exception as e:
            print(f"   ❌ Scenario generation error: {e}")
            return False
    
    # Step 4: Test suggestions
    print("\n4. Testing scenario suggestions...")
    
    suggestions = generator.get_scenario_suggestions("phish")
    if suggestions:
        print(f"   ✅ Generated {len(suggestions)} suggestions for 'phish':")
        for suggestion in suggestions:
            print(f"      - {suggestion}")
    else:
        print("   ⚠️  No suggestions generated")
    
    print("\n" + "=" * 60)
    print("✅ All tests passed! Scenario generation pipeline is working.")
    return True

def test_interactive_generation():
    """Test interactive scenario generation."""
    print("\n" + "=" * 60)
    print("INTERACTIVE SCENARIO GENERATION TEST")
    print("=" * 60)
    
    try:
        # Initialize components
        vector_db = VectorDB()
        vector_db.connect()
        
        # connect to collection if it exists... 
        if not vector_db.create_collection(reset_if_exists=False):
            print("❌ Failed to create/get collection")
            return False
        
        llm_client = LLMClient()
        generator = ScenarioGenerator(vector_db, llm_client)
        
        # Get user input
        print("Enter a scenario description (or press Enter for default):")
        user_query = input("> ").strip()
        
        if not user_query:
            user_query = "social engineering attack via phone calls"
        
        print(f"\nGenerating scenario for: '{user_query}'")
        print("-" * 40)
        
        request = ScenarioRequest(query=user_query)
        scenario = generator.generate_scenario(request, evaluate=True)
        
        if scenario:
            print(f"\n📋 GENERATED SCENARIO")
            print("=" * 40)
            print(f"Title: {scenario.title}")
            print(f"Objective: {scenario.objective}")
            print(f"\nDescription:")
            print(scenario.description)
            
            if scenario.evaluation_scores:
                print(f"\n📊 Evaluation Scores:")
                for criterion, score in scenario.evaluation_scores.items():
                    print(f"  {criterion.replace('_', ' ').title()}: {score}/10")
        else:
            print("❌ Failed to generate scenario")
            
    except Exception as e:
        print(f"❌ Interactive test failed: {e}")

if __name__ == "__main__":
    # Run automated tests
    success = test_scenario_generation()
    
    if success:
        # Optionally run interactive test
        print("\nWould you like to try interactive generation? (y/n): ", end="")
        try:
            response = input().strip().lower()
            if response in ['y', 'yes']:
                test_interactive_generation()
        except KeyboardInterrupt:
            print("\nTest completed.")
    else:
        sys.exit(1)