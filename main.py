# main.py
"""Main application entry point for Red Team Scenario Generator."""

import sys
import argparse
from pathlib import Path

# Add src to path for imports
sys.path.append(str(Path(__file__).parent / "src"))

from config import config
from database.vector_db import VectorDB
from data_sources.mitre_attack import MitreAttackLoader
from data_sources.capec_data import CapecDataLoader
from generation.scenario_generator import ScenarioGenerator, ScenarioRequest
from generation.llm_client import LLMClient
from evaluation.evaluator import ScenarioEvaluator
from utils.logging_config import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger(__name__)

class RedTeamApp:
    """Main application class."""
    
    def __init__(self):
        """Initialize the application."""
        self.vector_db = None
        self.scenario_generator = None
        
    def setup_database(self, reset: bool = False) -> bool:
        """Set up the vector database.
        
        Args:
            reset: Whether to reset existing database
            
        Returns:
            bool: True if setup successful
        """
        logger.info("Setting up vector database...")
        
        try:
            # Initialize database
            self.vector_db = VectorDB()
            
            if not self.vector_db.connect():
                logger.error("Failed to connect to database")
                return False
            
            if not self.vector_db.create_collection(reset_if_exists=reset):
                logger.error("Failed to create collection")
                return False
            
            # Check if database already has data and reset not requested
            stats = self.vector_db.get_collection_stats()
            if stats and stats['total_documents'] > 0 and not reset:
                logger.info(f"Database already contains {stats['total_documents']} documents")
                return True
            
            # Load data
            success = self.load_all_data()
            if success:
                logger.info("Database setup completed successfully")
            
            return success
            
        except Exception as e:
            logger.error(f"Database setup failed: {e}")
            return False
    
    def load_all_data(self) -> bool:
        """Load all data sources into the database.
        
        Returns:
            bool: True if all data loaded successfully
        """
        success = True
        
        # Load MITRE ATT&CK data
        if not self.load_mitre_data():
            logger.error("Failed to load MITRE data")
            success = False
        
        # Load CAPEC data
        if not self.load_capec_data():
            logger.error("Failed to load CAPEC data")
            success = False
        
        return success
    
    def load_mitre_data(self) -> bool:
        """Load MITRE ATT&CK data.
        
        Returns:
            bool: True if successful
        """
        try:
            logger.info("Loading MITRE ATT&CK data...")
            
            # Initialize loader
            mitre_loader = MitreAttackLoader()
            
            # Load and validate data
            data = mitre_loader.load_data()
            if not mitre_loader.validate_data(data):
                logger.error("MITRE data validation failed")
                return False
            
            # Transform for vector database
            documents, metadatas, ids = mitre_loader.transform_for_vector_db(data)
            
            # Add to database
            success = self.vector_db.add_documents(documents, metadatas, ids)
            
            if success:
                logger.info(f"Successfully loaded {len(documents)} MITRE techniques")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to load MITRE data: {e}")
            return False
    
    def load_capec_data(self) -> bool:
        """Load CAPEC data.
        
        Returns:
            bool: True if successful
        """
        try:
            logger.info("Loading CAPEC data...")
            
            # Initialize loader
            capec_loader = CapecDataLoader()
            
            # Load and validate data
            data = capec_loader.load_data()
            if not capec_loader.validate_data(data):
                logger.error("CAPEC data validation failed")
                return False
            
            # Transform for vector database
            documents, metadatas, ids = capec_loader.transform_for_vector_db(data)
            
            # Add to database
            success = self.vector_db.add_documents(documents, metadatas, ids)
            
            if success:
                logger.info(f"Successfully loaded {len(documents)} CAPEC patterns")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to load CAPEC data: {e}")
            return False
    
    def initialize_generator(self) -> bool:
        """Initialize the scenario generator.
        
        Returns:
            bool: True if successful
        """
        try:
            if not self.vector_db:
                logger.error("Vector database not initialized")
                return False
            
            # Initialize components
            llm_client = LLMClient()
            evaluator = ScenarioEvaluator()
            
            # Create scenario generator
            self.scenario_generator = ScenarioGenerator(
                vector_db=self.vector_db,
                llm_client=llm_client,
                evaluator=evaluator
            )
            
            logger.info("Scenario generator initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize generator: {e}")
            return False
    
    def validate_system(self) -> bool:
        """Validate the entire system.
        
        Returns:
            bool: True if system is healthy
        """
        logger.info("Validating system...")
        
        # Database health check
        if not self.vector_db:
            logger.error("Vector database not initialized")
            return False
        
        health = self.vector_db.health_check()
        
        if not health['client_connected']:
            logger.error("Database client not connected")
            return False
        
        if not health['collection_exists']:
            logger.error("Database collection does not exist")
            return False
        
        if health['document_count'] == 0:
            logger.error("Database contains no documents")
            return False
        
        if not health['can_query']:
            logger.error("Database queries not working")
            return False
        
        if health['issues']:
            for issue in health['issues']:
                logger.warning(f"Health check issue: {issue}")
        
        # Test scenario generation
        if self.scenario_generator:
            try:
                test_request = ScenarioRequest(
                    query="test phishing scenario",
                    environment="Corporate"
                )
                
                # Test query only (not full generation to save API calls)
                results = self.vector_db.query("phishing", n_results=1)
                if not results or not results['documents']:
                    logger.error("Test query returned no results")
                    return False
                
                logger.info("Scenario generation system ready")
                
            except Exception as e:
                logger.error(f"Scenario generation test failed: {e}")
                return False
        
        logger.info("System validation completed successfully")
        return True
    
    def interactive_mode(self):
        """Run interactive testing mode."""
        logger.info("Starting interactive mode...")
        print("\n" + "="*60)
        print("RED TEAM SCENARIO GENERATOR - Interactive Mode")
        print("="*60)
        print("Commands:")
        print("  generate <query>  - Generate a scenario")
        print("  query <text>      - Search for techniques")
        print("  stats             - Show database statistics")
        print("  health            - Show system health")
        print("  quit              - Exit interactive mode")
        print("="*60)
        
        while True:
            try:
                user_input = input("\n> ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                
                parts = user_input.split(' ', 1)
                command = parts[0].lower()
                args = parts[1] if len(parts) > 1 else ""
                
                if command == 'generate':
                    if not args:
                        print("Usage: generate <scenario description>")
                        continue
                    
                    if not self.scenario_generator:
                        print("Scenario generator not initialized")
                        continue
                    
                    self._handle_generate_command(args)
                
                elif command == 'query':
                    if not args:
                        print("Usage: query <search text>")
                        continue
                    
                    self._handle_query_command(args)
                
                elif command == 'stats':
                    self._handle_stats_command()
                
                elif command == 'health':
                    self._handle_health_command()
                
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Interactive mode error: {e}")
                print(f"Error: {e}")
        
        print("\nExiting interactive mode...")
    
    def _handle_generate_command(self, query: str):
        """Handle scenario generation command."""
        print(f"\nGenerating scenario for: '{query}'")
        
        try:
            request = ScenarioRequest(query=query)
            scenario = self.scenario_generator.generate_scenario(request)
            
            print(f"\n{'='*50}")
            print(f"GENERATED SCENARIO")
            print(f"{'='*50}")
            print(f"Title: {scenario.title}")
            print(f"Objective: {scenario.objective}")
            print(f"Environment: {request.environment}")
            print(f"\nDescription:")
            print(scenario.description)
            
            if scenario.evaluation_scores:
                print(f"\nEvaluation Scores:")
                for criterion, score in scenario.evaluation_scores.items():
                    print(f"  {criterion.replace('_', ' ').title()}: {score}/10")
            
        except Exception as e:
            print(f"Generation failed: {e}")
    
    def _handle_query_command(self, query: str):
        """Handle database query command."""
        print(f"\nSearching for: '{query}'")
        
        try:
            results = self.vector_db.query(query, n_results=5)
            
            if results and results['documents']:
                print(f"\nFound {len(results['documents'])} results:")
                for i, (doc, metadata) in enumerate(zip(results['documents'], results['metadatas'])):
                    print(f"\n{i+1}. {metadata.get('name', 'Unknown')} ({metadata.get('technique_id', 'N/A')})")
                    print(f"   Type: {metadata.get('type', 'Unknown')}")
                    print(f"   Relevance: {1-results['distances'][i]:.3f}")
                    
                    if metadata.get('tactics'):
                        print(f"   Tactics: {', '.join(metadata['tactics'])}")
            else:
                print("No results found")
                
        except Exception as e:
            print(f"Query failed: {e}")
    
    def _handle_stats_command(self):
        """Handle database statistics command."""
        try:
            stats = self.vector_db.get_collection_stats()
            
            if stats:
                print(f"\nDatabase Statistics:")
                print(f"  Total documents: {stats['total_documents']}")
                print(f"  Collection: {stats['collection_name']}")
                print(f"  Embedding model: {stats['embedding_model']}")
                
                if stats['type_distribution']:
                    print(f"  Document types:")
                    for doc_type, count in stats['type_distribution'].items():
                        print(f"    {doc_type}: {count}")
            else:
                print("Failed to get database statistics")
                
        except Exception as e:
            print(f"Stats command failed: {e}")
    
    def _handle_health_command(self):
        """Handle system health command."""
        try:
            health = self.vector_db.health_check()
            
            print(f"\nSystem Health:")
            print(f"  Client connected: {'✅' if health['client_connected'] else '❌'}")
            print(f"  Collection exists: {'✅' if health['collection_exists'] else '❌'}")
            print(f"  Document count: {health['document_count']}")
            print(f"  Can query: {'✅' if health['can_query'] else '❌'}")
            
            if health['issues']:
                print(f"  Issues:")
                for issue in health['issues']:
                    print(f"    ❌ {issue}")
            else:
                print(f"  Status: ✅ Healthy")
                
        except Exception as e:
            print(f"Health check failed: {e}")

def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description="Red Team Scenario Generator")
    parser.add_argument("--reset", action="store_true", help="Reset database")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--validate-only", action="store_true", help="Only validate system")
    parser.add_argument("--setup-only", action="store_true", help="Only setup database")
    
    args = parser.parse_args()
    
    # Initialize application
    app = RedTeamApp()
    
    # Setup database
    if not app.setup_database(reset=args.reset):
        logger.error("Database setup failed")
        sys.exit(1)
    
    if args.setup_only:
        logger.info("Database setup completed")
        sys.exit(0)
    
    # Initialize generator
    if not app.initialize_generator():
        logger.error("Generator initialization failed")
        sys.exit(1)
    
    # Validate system
    if not app.validate_system():
        logger.error("System validation failed")
        sys.exit(1)
    
    if args.validate_only:
        logger.info("System validation completed")
        sys.exit(0)
    
    # Run interactive mode
    if args.interactive:
        app.interactive_mode()
    else:
        # Default: run validation and show ready message
        print("\n" + "="*60)
        print("RED TEAM SCENARIO GENERATOR")
        print("="*60)
        print("✅ System initialized and validated")
        print("✅ Database ready with techniques loaded")
        print("✅ Scenario generation system ready")
        print("\nRun with --interactive flag for interactive mode")
        print("Example: python main.py --interactive")
        print("="*60)

if __name__ == "__main__":
    main()