#!/usr/bin/env python3
"""
Enhanced Vector Database Test Script for Dynamic CAPEC
Tests the complete vector database system with dynamic CAPEC loading.
"""

import sys
from pathlib import Path
import time
import os

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root / "src"))

try:
    from config import config
    from database.vector_db import VectorDB
    from data_sources.mitre_attack import MitreAttackLoader
    from data_sources.capec_data import CapecDataLoader
    from utils.logging_config import setup_logging, get_logger
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running this from the project root directory")
    print("Expected structure:")
    print("  project_root/")
    print("    scripts/setup_database.py  ← Run from project_root")
    print("    src/")
    print("      config.py")
    print("      database/")
    print("      ...")
    sys.exit(1)
    
# Setup logging
setup_logging()
logger = get_logger(__name__)

def test_enhanced_vector_db_setup():
    """Test enhanced vector database setup with dynamic CAPEC."""
    print("🗄️ Testing Enhanced Vector Database Setup...")
    print("-" * 60)
    
    try:
        # Initialize database
        vector_db = VectorDB()
        
        # Test connection
        if vector_db.connect():
            print("✅ Database connection successful")
        else:
            print("❌ Database connection failed")
            return False
        
        # Test collection creation with reset
        if vector_db.create_collection(reset_if_exists=True):
            print("✅ Collection created successfully (with reset)")
        else:
            print("❌ Collection creation failed")
            return False
        
        print("✅ Enhanced vector database setup complete\n")
        return vector_db
        
    except Exception as e:
        print(f"❌ Enhanced vector database setup failed: {e}")
        return False

def test_dynamic_capec_integration(vector_db):
    """Test the new dynamic CAPEC data loading."""
    print("🔍 Testing Dynamic CAPEC Integration...")
    print("-" * 60)
    
    try:
        # Initialize dynamic CAPEC loader
        capec_loader = CapecDataLoader(cache_enabled=True, cache_duration_hours=1)
        print("✅ Dynamic CAPEC loader initialized")
        
        # Get source information
        source_info = capec_loader.get_source_info()
        print(f"📡 Data Source: {source_info.get('source_url', 'Unknown')}")
        print(f"💾 Cache Status: {source_info.get('cache_status', 'Unknown')}")
        
        # Load data (this might take a minute for first run)
        print("⏳ Loading dynamic CAPEC data... (30-60 seconds on first run)")
        start_time = time.time()
        
        capec_data = capec_loader.load_data()
        
        load_time = time.time() - start_time
        
        if not capec_data:
            print("❌ No CAPEC data loaded")
            return False
        
        print(f"✅ Loaded {len(capec_data)} CAPEC patterns in {load_time:.1f}s")
        
        # Analyze data quality compared to old system
        print(f"\n📊 Data Quality Analysis:")
        patterns_with_complexity = sum(1 for p in capec_data if p.get('attack_complexity'))
        patterns_with_environments = sum(1 for p in capec_data if p.get('environment_suitability'))
        patterns_with_attack_refs = sum(1 for p in capec_data if p.get('related_techniques'))
        patterns_with_methods = sum(1 for p in capec_data if p.get('methods'))
        patterns_with_mitigations = sum(1 for p in capec_data if p.get('mitigations'))
        
        print(f"   Complexity classification: {patterns_with_complexity}/{len(capec_data)}")
        print(f"   Environment mapping: {patterns_with_environments}/{len(capec_data)}")
        print(f"   ATT&CK technique links: {patterns_with_attack_refs}/{len(capec_data)}")
        print(f"   Attack methods: {patterns_with_methods}/{len(capec_data)}")
        print(f"   Mitigation strategies: {patterns_with_mitigations}/{len(capec_data)}")
        
        # Show improvement over old system
        if len(capec_data) > 50:
            print(f"\n🎉 Massive Improvement:")
            print(f"   Old system: ~10 hard-coded patterns")
            print(f"   New system: {len(capec_data)} official CAPEC patterns")
            print(f"   Improvement: {len(capec_data)/10:.0f}x more data!")
        
        # Validate data
        if capec_loader.validate_data(capec_data):
            print("✅ Dynamic CAPEC data validation passed")
        else:
            print("❌ Dynamic CAPEC data validation failed")
            return False
        
        # Transform for vector database
        documents, metadatas, ids = capec_loader.transform_for_vector_db(capec_data)
        print(f"✅ Transformed data: {len(documents)} documents")
        
        # Add to database
        print("⏳ Adding dynamic CAPEC data to vector database...")
        if vector_db.add_documents(documents, metadatas, ids):
            print(f"✅ Successfully added {len(documents)} CAPEC documents to database")
            return True
        else:
            print("❌ Failed to add CAPEC data to database")
            return False
            
    except Exception as e:
        print(f"❌ Dynamic CAPEC integration failed: {e}")
        return False

def test_mitre_data_loading(vector_db):
    """Test MITRE ATT&CK data loading (existing functionality)."""
    print("\n🎯 Testing MITRE ATT&CK Data Loading...")
    print("-" * 60)
    
    try:
        # Initialize MITRE loader
        mitre_loader = MitreAttackLoader()
        print("✅ MITRE loader initialized")
        
        # Load data
        print("⏳ Loading MITRE data... (this may take 30-60 seconds)")
        mitre_data = mitre_loader.load_data()
        
        if not mitre_data:
            print("❌ No MITRE data loaded")
            return False
        
        print(f"✅ Loaded {len(mitre_data)} MITRE techniques")
        
        # Validate data
        if mitre_loader.validate_data(mitre_data):
            print("✅ MITRE data validation passed")
        else:
            print("❌ MITRE data validation failed")
            return False
        
        # Transform for vector database
        documents, metadatas, ids = mitre_loader.transform_for_vector_db(mitre_data)
        print(f"✅ Transformed data: {len(documents)} documents")
        
        # Add to database
        print("⏳ Adding MITRE data to vector database...")
        if vector_db.add_documents(documents, metadatas, ids):
            print(f"✅ Successfully added {len(documents)} MITRE documents to database")
            return True
        else:
            print("❌ Failed to add MITRE data to database")
            return False
            
    except Exception as e:
        print(f"❌ MITRE data loading failed: {e}")
        return False

def test_enhanced_database_queries(vector_db):
    """Test enhanced database queries with new data."""
    print("\n🔍 Testing Enhanced Database Queries...")
    print("-" * 60)
    
    # Enhanced test queries covering both MITRE and CAPEC
    test_queries = [
        # MITRE ATT&CK focused queries
        "spear phishing email attack against corporate employees",
        "Windows privilege escalation techniques", 
        "lateral movement through network using valid accounts",
        "credential dumping from memory",
        
        # CAPEC focused queries
        "SQL injection attack patterns",
        "cross-site scripting vulnerabilities",
        "buffer overflow exploitation techniques",
        "social engineering attack methods",
        
        # Combined queries
        "web application security testing",
        "network reconnaissance and scanning",
        "malware analysis and detection evasion"
    ]
    
    successful_queries = 0
    
    for query in test_queries:
        try:
            print(f"\n🔍 Query: '{query}'")
            results = vector_db.query(query, n_results=3)
            
            if results and results['documents']:
                successful_queries += 1
                print(f"   ✅ Found {len(results['documents'])} results")
                
                # Show top result details
                top_result = results['metadatas'][0]
                technique_id = top_result.get('technique_id') or top_result.get('capec_id', 'Unknown')
                technique_name = top_result.get('name', 'Unknown')
                doc_type = top_result.get('type', 'unknown')
                relevance = 1 - results['distances'][0]
                
                print(f"   🎯 Top match: {technique_name} ({technique_id})")
                print(f"   📈 Relevance: {relevance:.3f}")
                print(f"   🏷️  Type: {doc_type}")
                
                # Show additional metadata for CAPEC patterns
                if 'capec' in doc_type.lower():
                    complexity = top_result.get('attack_complexity', 'Unknown')
                    environments = top_result.get('environment_suitability', '')
                    print(f"   ⚙️  Complexity: {complexity}")
                    if environments:
                        print(f"   🌐 Environments: {environments}")
                
                # Show tactics if available
                tactics = top_result.get('tactics', '')
                if tactics:
                    print(f"   🎯 Tactics: {tactics}")
                
            else:
                print(f"   ❌ No results found for: '{query}'")
                
        except Exception as e:
            print(f"   ❌ Query failed: {e}")
    
    print(f"\n📊 Query Success Rate: {successful_queries}/{len(test_queries)} ({successful_queries/len(test_queries)*100:.1f}%)")
    
    return successful_queries > len(test_queries) * 0.8  # 80% success rate

def test_enhanced_database_stats(vector_db):
    """Test enhanced database statistics with new data types."""
    print("\n📊 Testing Enhanced Database Statistics...")
    print("-" * 60)
    
    try:
        # Get collection stats
        stats = vector_db.get_collection_stats()
        
        if stats:
            print(f"📈 Total documents: {stats['total_documents']}")
            print(f"🏷️  Collection name: {stats['collection_name']}")
            print(f"🧠 Embedding model: {stats['embedding_model']}")
            
            if stats.get('type_distribution'):
                print("\n📋 Enhanced Document Type Distribution:")
                total_docs = stats['total_documents']
                for doc_type, count in stats['type_distribution'].items():
                    percentage = (count / total_docs) * 100
                    print(f"   {doc_type}: {count} documents ({percentage:.1f}%)")
                
                # Verify we have both MITRE and CAPEC data
                has_mitre = any('mitre' in doc_type.lower() for doc_type in stats['type_distribution'])
                has_capec = any('capec' in doc_type.lower() for doc_type in stats['type_distribution'])
                
                if has_mitre and has_capec:
                    print("✅ Both MITRE and CAPEC data types present")
                elif has_mitre:
                    print("⚠️  Only MITRE data detected")
                elif has_capec:
                    print("⚠️  Only CAPEC data detected")
                else:
                    print("❌ No recognized data types")
        
        # Enhanced health check
        print("\n🏥 Enhanced Database Health Check:")
        health = vector_db.health_check()
        
        print(f"   Client connected: {'✅' if health['client_connected'] else '❌'}")
        print(f"   Collection exists: {'✅' if health['collection_exists'] else '❌'}")
        print(f"   Document count: {health['document_count']}")
        print(f"   Can query: {'✅' if health['can_query'] else '❌'}")
        
        if health['issues']:
            print("   Issues found:")
            for issue in health['issues']:
                print(f"     ❌ {issue}")
        else:
            print("   ✅ All health checks passed")
        
        # Expected data volume check
        expected_min_docs = 100  # Should have at least 100 docs with MITRE + CAPEC
        if health['document_count'] >= expected_min_docs:
            print(f"✅ Good data volume: {health['document_count']} documents (>= {expected_min_docs})")
        else:
            print(f"⚠️  Low data volume: {health['document_count']} documents (< {expected_min_docs})")
            
        return True
            
    except Exception as e:
        print(f"❌ Enhanced statistics test failed: {e}")
        return False

def interactive_enhanced_query_test(vector_db):
    """Enhanced interactive query testing with new capabilities."""
    print("\n🎮 Enhanced Interactive Query Testing")
    print("-" * 60)
    print("Enter queries to test the enhanced vector database (or 'quit' to exit):")
    print("Try queries like:")
    print("  - 'SQL injection attack patterns'")
    print("  - 'corporate phishing scenarios'") 
    print("  - 'Windows privilege escalation'")
    print("  - 'web application security testing'")
    
    while True:
        try:
            query = input("\n🔍 Enhanced Query: ").strip()
            
            if query.lower() in ['quit', 'exit', 'q']:
                break
            
            if not query:
                continue
            
            print(f"⏳ Searching enhanced database for: '{query}'...")
            results = vector_db.query(query, n_results=5)
            
            if results and results['documents']:
                print(f"📊 Found {len(results['documents'])} results:")
                print()
                
                for i, (metadata, distance) in enumerate(zip(results['metadatas'], results['distances'])):
                    relevance = 1 - distance
                    technique_id = metadata.get('technique_id') or metadata.get('capec_id', 'N/A')
                    name = metadata.get('name', 'Unknown')
                    doc_type = metadata.get('type', 'unknown')
                    
                    print(f"   {i+1}. {name} ({technique_id}) [{doc_type}]")
                    print(f"      📈 Relevance: {relevance:.3f}")
                    
                    # Show enhanced metadata
                    if 'capec' in doc_type.lower():
                        complexity = metadata.get('attack_complexity')
                        environments = metadata.get('environment_suitability')
                        if complexity:
                            print(f"      ⚙️  Complexity: {complexity}")
                        if environments:
                            print(f"      🌐 Environments: {environments}")
                    
                    tactics = metadata.get('tactics')
                    if tactics:
                        print(f"      🎯 Tactics: {tactics}")
                    print()
            else:
                print("❌ No results found")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ Query error: {e}")
    
    print("\n👋 Enhanced interactive testing complete")

def main():
    """Main enhanced test function."""
    print("🚀 Enhanced Vector Database Test Suite")
    print("=" * 70)
    print("Testing vector database with Dynamic CAPEC integration...")
    print()
    
    # Test 1: Enhanced database setup
    vector_db = test_enhanced_vector_db_setup()
    if not vector_db:
        print("❌ Enhanced database setup failed - stopping tests")
        return False
    
    # Test 2: Dynamic CAPEC integration (NEW!)
    capec_success = test_dynamic_capec_integration(vector_db)
    if not capec_success:
        print("❌ Dynamic CAPEC integration failed")
        return False
    
    # Test 3: MITRE data loading (existing)
    mitre_success = test_mitre_data_loading(vector_db)
    if not mitre_success:
        print("❌ MITRE data loading failed")
        return False
    
    # Test 4: Enhanced query testing
    query_success = test_enhanced_database_queries(vector_db)
    if not query_success:
        print("⚠️  Enhanced query testing had issues, but continuing...")
    
    # Test 5: Enhanced database statistics
    test_enhanced_database_stats(vector_db)
    
    # Interactive testing
    print("\n" + "=" * 70)
    print("🎉 All enhanced automated tests complete!")
    print("=" * 70)
    
    choice = input("\nWould you like to run enhanced interactive query testing? (y/n): ").strip().lower()
    if choice in ['y', 'yes']:
        interactive_enhanced_query_test(vector_db)
    
    print("\n✅ Enhanced vector database testing complete!")
    print("🚀 Ready for enhanced scenario generation!")
    
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)