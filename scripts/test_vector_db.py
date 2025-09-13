#!/usr/bin/env python3
"""
Simple test script for vector database functionality.
Tests data loading, storage, and querying without LLM integration.
"""

import sys
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root / "src"))

import os
from config import config
from database.vector_db import VectorDB
from data_sources.mitre_attack import MitreAttackLoader
from data_sources.capec_data import CapecDataLoader
from utils.logging_config import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger(__name__)

def test_vector_db_setup():
    """Test basic vector database setup and connection."""
    print("🗄️ Testing Vector Database Setup...")
    print("-" * 50)
    
    try:
        # Initialize database
        vector_db = VectorDB()
        
        # Test connection
        if vector_db.connect():
            print("✅ Database connection successful")
        else:
            print("❌ Database connection failed")
            return False
        
        # Test collection creation
        if vector_db.create_collection(reset_if_exists=True):
            print("✅ Collection created successfully")
        else:
            print("❌ Collection creation failed")
            return False
        
        print("✅ Vector database setup complete\n")
        return vector_db
        
    except Exception as e:
        print(f"❌ Vector database setup failed: {e}")
        return False

def test_mitre_data_loading(vector_db):
    """Test MITRE ATT&CK data loading."""
    print("🎯 Testing MITRE ATT&CK Data Loading...")
    print("-" * 50)
    
    try:
        # Initialize MITRE loader
        mitre_loader = MitreAttackLoader()
        print("✅ MITRE loader initialized")
        
        # Load data (this might take a minute)
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
        print(f"✅ Transformed data: {len(documents)} documents, {len(metadatas)} metadata entries")
        
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

def test_capec_data_loading(vector_db):
    """Test CAPEC data loading."""
    print("\n🔍 Testing CAPEC Data Loading...")
    print("-" * 50)
    
    try:
        # Initialize CAPEC loader
        capec_loader = CapecDataLoader()
        print("✅ CAPEC loader initialized")
        
        # Load data
        capec_data = capec_loader.load_data()
        
        if not capec_data:
            print("❌ No CAPEC data loaded")
            return False
        
        print(f"✅ Loaded {len(capec_data)} CAPEC attack patterns")
        
        # Validate data
        if capec_loader.validate_data(capec_data):
            print("✅ CAPEC data validation passed")
        else:
            print("❌ CAPEC data validation failed")
            return False
        
        # Transform for vector database
        documents, metadatas, ids = capec_loader.transform_for_vector_db(capec_data)
        print(f"✅ Transformed data: {len(documents)} documents")
        
        # Add to database
        if vector_db.add_documents(documents, metadatas, ids):
            print(f"✅ Successfully added {len(documents)} CAPEC documents to database")
            return True
        else:
            print("❌ Failed to add CAPEC data to database")
            return False
            
    except Exception as e:
        print(f"❌ CAPEC data loading failed: {e}")
        return False

def test_database_queries(vector_db):
    """Test vector database queries."""
    print("\n🔍 Testing Database Queries...")
    print("-" * 50)
    
    # Test queries - these are common red team scenarios
    test_queries = [
        "phishing attack against employees",
        "privilege escalation on Windows systems", 
        "lateral movement through network",
        "credential harvesting techniques",
        "web application vulnerability exploitation"
    ]
    
    for query in test_queries:
        try:
            print(f"\n🔍 Query: '{query}'")
            results = vector_db.query(query, n_results=3)
            
            if results and results['documents']:
                print(f"   ✅ Found {len(results['documents'])} results")
                
                # Show top result details
                top_result = results['metadatas'][0]
                technique_id = top_result.get('technique_id', 'Unknown')
                technique_name = top_result.get('name', 'Unknown')
                relevance = 1 - results['distances'][0]
                
                print(f"   📊 Top match: {technique_name} ({technique_id})")
                print(f"   📈 Relevance score: {relevance:.3f}")
                
                # Show tactics if available
                tactics = top_result.get('tactics', [])
                if tactics:
                    print(f"   🎯 Tactics: {', '.join(tactics)}")
                
            else:
                print(f"   ❌ No results found for: '{query}'")
                
        except Exception as e:
            print(f"   ❌ Query failed: {e}")

def test_database_stats(vector_db):
    """Test database statistics and health."""
    print("\n📊 Testing Database Statistics...")
    print("-" * 50)
    
    try:
        # Get collection stats
        stats = vector_db.get_collection_stats()
        
        if stats:
            print(f"📈 Total documents: {stats['total_documents']}")
            print(f"🏷️  Collection name: {stats['collection_name']}")
            print(f"🧠 Embedding model: {stats['embedding_model']}")
            
            if stats.get('type_distribution'):
                print("\n📋 Document type distribution:")
                for doc_type, count in stats['type_distribution'].items():
                    print(f"   {doc_type}: {count} documents")
        
        # Health check
        print("\n🏥 Database Health Check:")
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
            
    except Exception as e:
        print(f"❌ Statistics test failed: {e}")

def interactive_query_test(vector_db):
    """Interactive query testing."""
    print("\n🎮 Interactive Query Testing")
    print("-" * 50)
    print("Enter queries to test the vector database (or 'quit' to exit):")
    print("Example queries:")
    print("  - 'email phishing attack'")
    print("  - 'Windows privilege escalation'") 
    print("  - 'network lateral movement'")
    print("  - 'credential dumping'")
    
    while True:
        try:
            query = input("\n🔍 Query: ").strip()
            
            if query.lower() in ['quit', 'exit', 'q']:
                break
            
            if not query:
                continue
            
            print(f"⏳ Searching for: '{query}'...")
            results = vector_db.query(query, n_results=5)
            
            if results and results['documents']:
                print(f"📊 Found {len(results['documents'])} results:")
                print()
                
                for i, (metadata, distance) in enumerate(zip(results['metadatas'], results['distances'])):
                    relevance = 1 - distance
                    technique_id = metadata.get('technique_id', 'N/A')
                    name = metadata.get('name', 'Unknown')
                    doc_type = metadata.get('type', 'unknown')
                    tactics = metadata.get('tactics', [])
                    
                    print(f"   {i+1}. {name} ({technique_id}) [{doc_type}]")
                    print(f"      📈 Relevance: {relevance:.3f}")
                    if tactics:
                        print(f"      🎯 Tactics: {', '.join(tactics)}")
                    print()
            else:
                print("❌ No results found")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"❌ Query error: {e}")
    
    print("\n👋 Interactive testing complete")

def main():
    """Main test function."""
    print("🚀 Vector Database Test Suite")
    print("=" * 60)
    print("Testing vector database functionality without LLM integration\n")
    
    # Test 1: Database setup
    vector_db = test_vector_db_setup()
    if not vector_db:
        print("❌ Database setup failed - stopping tests")
        return False
    
    # Test 2: MITRE data loading
    mitre_success = test_mitre_data_loading(vector_db)
    if not mitre_success:
        print("❌ MITRE data loading failed")
        return False
    
    # Test 3: CAPEC data loading
    capec_success = test_capec_data_loading(vector_db)
    if not capec_success:
        print("⚠️ CAPEC data loading failed, but continuing...")
    
    # Test 4: Query testing
    test_database_queries(vector_db)
    
    # Test 5: Database statistics
    test_database_stats(vector_db)
    
    # Interactive testing
    print("\n" + "=" * 60)
    print("🎉 All automated tests complete!")
    print("=" * 60)
    
    choice = input("\nWould you like to run interactive query testing? (y/n): ").strip().lower()
    if choice in ['y', 'yes']:
        interactive_query_test(vector_db)
    
    print("\n✅ Vector database testing complete!")
    print("🚀 Ready to proceed with full system integration")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)