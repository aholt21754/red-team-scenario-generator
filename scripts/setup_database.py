# scripts/setup_database.py
"""Enhanced setup script for the Red Team Scenario Generator with Dynamic CAPEC."""

import sys
import os
from pathlib import Path
import time

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root / "src"))

try:
    import logging
    from config import config
    from database.vector_db import VectorDB
    from data_sources.mitre_attack import MitreAttackLoader
    from data_sources.capec_data import CapecDataLoader
    from utils.logging_config import setup_logging
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
    
def setup_directories():
    """Create necessary directories."""
    directories = [
        "logs",
        "data/raw", 
        "data",  # For CAPEC caching
        "chroma_db",
        "tests"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def check_requirements():
    """Check if all required packages are installed."""
    required_packages = {
        "chromadb": "chromadb",
        "sentence-transformers": "sentence_transformers", 
        "requests": "requests",           # New: for dynamic CAPEC
        "lxml": "lxml",              # New: for XML parsing
        "python-dotenv": "dotenv",     # New: for environment config
        "anthropic": "anthropic"          # For LLM integration
    }
    
    missing_packages = []
    
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print(f"✅ {package_name} installed")
        except ImportError:
            missing_packages.append(package_name)
            print(f"❌ {package_name} missing")
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        return False
    
    return True

def test_dynamic_capec_loader():
    """Test the dynamic CAPEC loader before using it."""
    print("\n🧪 Testing Dynamic CAPEC Loader...")
    print("-" * 50)
    
    try:
        # Test basic loader functionality
        capec_loader = CapecDataLoader(cache_enabled=True, cache_duration_hours=1)
        
        # Get source info
        source_info = capec_loader.get_source_info()
        print(f"📡 CAPEC Source: {source_info.get('source_url', 'Unknown')}")
        print(f"💾 Cache Status: {source_info.get('cache_status', 'Unknown')}")
        
        # Test data loading (this may take a moment for first run)
        print("⏳ Loading CAPEC data (may take 30-60 seconds on first run)...")
        start_time = time.time()
        
        capec_data = capec_loader.load_data()
        
        load_time = time.time() - start_time
        
        if capec_data:
            print(f"✅ Loaded {len(capec_data)} CAPEC patterns in {load_time:.1f}s")
            
            # Analyze data quality
            patterns_with_attack_refs = sum(1 for p in capec_data if p.get('related_techniques'))
            patterns_with_methods = sum(1 for p in capec_data if p.get('methods'))
            patterns_with_mitigations = sum(1 for p in capec_data if p.get('mitigations'))
            
            print(f"📊 Patterns with ATT&CK references: {patterns_with_attack_refs}")
            print(f"📊 Patterns with attack methods: {patterns_with_methods}")
            print(f"📊 Patterns with mitigations: {patterns_with_mitigations}")
            
            # Test validation
            if capec_loader.validate_data(capec_data):
                print("✅ CAPEC data validation passed")
                return True
            else:
                print("❌ CAPEC data validation failed")
                return False
        else:
            print("❌ No CAPEC data loaded")
            return False
            
    except Exception as e:
        print(f"❌ Dynamic CAPEC test failed: {e}")
        return False

def main():
    """Enhanced setup function with dynamic CAPEC support."""
    print("🚀 Enhanced Red Team Scenario Generator - Database Setup")
    print("=" * 60)
    print("Setting up with Dynamic CAPEC Loader...")
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Create directories
    print("\n📁 Creating directories...")
    setup_directories()
    
    # Check requirements
    print("\n📦 Checking requirements...")
    if not check_requirements():
        print("❌ Setup failed - missing requirements")
        return False
    
    # Test dynamic CAPEC loader
    if not test_dynamic_capec_loader():
        print("⚠️  Dynamic CAPEC loader test failed")
        print("Will continue with fallback patterns...")
    
    # Initialize database
    print("\n🗄️ Setting up vector database...")
    vector_db = VectorDB()
    
    if not vector_db.connect():
        print("❌ Failed to connect to database")
        return False
    
    if not vector_db.create_collection(reset_if_exists=True):
        print("❌ Failed to create collection")
        return False
    
    print("✅ Database initialized with dynamic CAPEC support")
    
    # Load MITRE data
    print("\n🎯 Loading MITRE ATT&CK data...")
    try:
        mitre_loader = MitreAttackLoader()
        mitre_data = mitre_loader.load_data()
        
        if mitre_loader.validate_data(mitre_data):
            documents, metadatas, ids = mitre_loader.transform_for_vector_db(mitre_data)
            
            if vector_db.add_documents(documents, metadatas, ids):
                print(f"✅ Loaded {len(documents)} MITRE techniques")
            else:
                print("❌ Failed to add MITRE data to database")
                return False
        else:
            print("❌ MITRE data validation failed")
            return False
            
    except Exception as e:
        print(f"❌ MITRE data loading failed: {e}")
        return False
    
    # Load Enhanced CAPEC data
    print("\n🔍 Loading Enhanced CAPEC data...")
    try:
        capec_loader = CapecDataLoader(cache_enabled=True)
        capec_data = capec_loader.load_data()
        
        if capec_loader.validate_data(capec_data):
            documents, metadatas, ids = capec_loader.transform_for_vector_db(capec_data)
            
            if vector_db.add_documents(documents, metadatas, ids):
                print(f"✅ Loaded {len(documents)} CAPEC attack patterns")
                
                # Show improvement over old system
                if len(documents) > 50:
                    print(f"🎉 Massive improvement: {len(documents)} patterns vs ~10 hard-coded!")
                
            else:
                print("❌ Failed to add CAPEC data to database")
                return False
        else:
            print("❌ CAPEC data validation failed")
            return False
            
    except Exception as e:
        print(f"❌ CAPEC data loading failed: {e}")
        return False
    
    # Final validation
    print("\n🔍 Validating enhanced setup...")
    health = vector_db.health_check()
    
    if health['client_connected'] and health['collection_exists'] and health['document_count'] > 0:
        print("✅ Enhanced database setup completed successfully!")
        print(f"📊 Total documents: {health['document_count']}")
        
        # Get collection stats
        stats = vector_db.get_collection_stats()
        if stats and stats.get('type_distribution'):
            print("\n📋 Document distribution:")
            for doc_type, count in stats['type_distribution'].items():
                print(f"   {doc_type}: {count} documents")
        
        # Show quick test
        print("\n🧪 Running quick enhanced test...")
        test_queries = [
            "phishing attack",
            "lateral movement", 
            "privilege escalation"
        ]
        
        for query in test_queries:
            test_result = vector_db.query(query, n_results=1)
            if test_result and test_result['documents']:
                top_result = test_result['metadatas'][0]
                technique_name = top_result.get('name', 'Unknown')
                doc_type = top_result.get('type', 'unknown')
                print(f"   ✅ '{query}' → {technique_name} ({doc_type})")
            else:
                print(f"   ⚠️  '{query}' → No results")
        
        print(f"\n🎉 Enhanced setup complete!")
        
        return True
    else:
        print("❌ Enhanced setup validation failed")
        if health['issues']:
            for issue in health['issues']:
                print(f"  - {issue}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)