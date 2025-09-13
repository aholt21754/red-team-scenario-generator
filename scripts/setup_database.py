# scripts/setup_database.py
"""Quick setup script for the Red Team Scenario Generator database."""

import sys
import os
from pathlib import Path

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root / "src"))

import logging
from src.config import config
from src.database.vector_db import VectorDB
from src.data_sources.mitre_attack import MitreAttackLoader
from src.data_sources.capec_data import CapecDataLoader
from src.utils.logging_config import setup_logging

def setup_directories():
    """Create necessary directories."""
    directories = [
        "logs",
        "data/raw", 
        "chroma_db",
        "tests"
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def check_requirements():
    """Check if all required packages are installed."""
    required_packages = [
        "chromadb",
        "sentence_transformers", 
        "mitreattack",
        "pandas",
        "python-dotenv"
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package} installed")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} missing")
    
    if missing_packages:
        print(f"\nMissing packages: {', '.join(missing_packages)}")
        print("Install with: pip install " + " ".join(missing_packages))
        return False
    
    return True

def main():
    """Main setup function."""
    print("🚀 Red Team Scenario Generator - Database Setup")
    print("=" * 50)
    
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
    
    # Initialize database
    print("\n🗄️ Setting up vector database...")
    vector_db = VectorDB()
    
    if not vector_db.connect():
        print("❌ Failed to connect to database")
        return False
    
    if not vector_db.create_collection():
        print("❌ Failed to create collection")
        return False
    
    print("✅ Database initialized")
    
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
    
    # Load CAPEC data
    print("\n🔍 Loading CAPEC data...")
    try:
        capec_loader = CapecDataLoader()
        capec_data = capec_loader.load_data()
        
        if capec_loader.validate_data(capec_data):
            documents, metadatas, ids = capec_loader.transform_for_vector_db(capec_data)
            
            if vector_db.add_documents(documents, metadatas, ids):
                print(f"✅ Loaded {len(documents)} CAPEC patterns")
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
    print("\n🔍 Validating setup...")
    health = vector_db.health_check()
    
    if health['client_connected'] and health['collection_exists'] and health['document_count'] > 0:
        print("✅ Database setup completed successfully!")
        print(f"📊 Total documents: {health['document_count']}")
        
        # Show quick test
        print("\n🧪 Running quick test...")
        test_result = vector_db.query("phishing attack", n_results=1)
        if test_result and test_result['documents']:
            print("✅ Query test passed")
            print(f"Sample result: {test_result['metadatas'][0].get('name', 'Unknown')}")
        else:
            print("❌ Query test failed")
            return False
        
        print("\n🎉 Setup complete! Run 'python main.py --interactive' to start")
        return True
    else:
        print("❌ Setup validation failed")
        if health['issues']:
            for issue in health['issues']:
                print(f"  - {issue}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)