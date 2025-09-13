# src/database/vector_db.py
"""Core vector database operations using ChromaDB."""

import chromadb
from chromadb.config import Settings
from typing import List, Dict, Any, Optional
from sentence_transformers import SentenceTransformer

from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class VectorDB:
    """Vector database interface for red team scenarios."""
    
    def __init__(self, db_path: str = None, collection_name: str = None):
        """Initialize vector database.
        
        Args:
            db_path: Path to database storage (optional, uses config default)
            collection_name: Name of collection (optional, uses config default)
        """
        self.db_path = db_path or config.VECTOR_DB_PATH
        self.collection_name = collection_name or config.COLLECTION_NAME
        self.client = None
        self.collection = None
        self.model = SentenceTransformer(config.EMBEDDING_MODEL)
        
        logger.info(f"Initializing VectorDB with path: {self.db_path}")
    
    def connect(self) -> bool:
        """Establish database connection.
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            self.client = chromadb.PersistentClient(path=self.db_path)
            logger.info("Database client connected successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def create_collection(self, reset_if_exists: bool = False) -> bool:
        """Create or get collection.
        
        Args:
            reset_if_exists: If True, delete existing collection first
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if not self.client:
                logger.error("Database client not connected")
                return False
            
            # Handle existing collection
            if reset_if_exists:
                try:
                    self.client.delete_collection(name=self.collection_name)
                    logger.info(f"Deleted existing collection: {self.collection_name}")
                except Exception:
                    logger.info("No existing collection to delete")
            
            # Create or get collection
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            
            logger.info(f"Collection '{self.collection_name}' ready")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create collection: {e}")
            return False
    
    def add_documents(self, documents: List[str], metadatas: List[Dict], 
                     ids: List[str], batch_size: int = None) -> bool:
        """Add documents to the collection.
        
        Args:
            documents: List of document texts
            metadatas: List of metadata dictionaries
            ids: List of unique document IDs
            batch_size: Size of batches for processing (optional)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.collection:
            logger.error("Collection not initialized")
            return False
        
        if len(documents) != len(metadatas) != len(ids):
            logger.error("Mismatched lengths for documents, metadatas, and ids")
            return False
        
        batch_size = batch_size or config.BATCH_SIZE
        
        try:
            # Process in batches
            for i in range(0, len(documents), batch_size):
                end_idx = min(i + batch_size, len(documents))
                batch_docs = documents[i:end_idx]
                batch_meta = metadatas[i:end_idx]
                batch_ids = ids[i:end_idx]
                
                self.collection.add(
                    documents=batch_docs,
                    metadatas=batch_meta,
                    ids=batch_ids
                )
                
                logger.info(f"Added batch {i//batch_size + 1}/{(len(documents)-1)//batch_size + 1}")
            
            logger.info(f"Successfully added {len(documents)} documents")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False
    
    def query(self, query_text: str, n_results: int = None, 
             where_filter: Dict = None) -> Optional[Dict[str, Any]]:
        """Query the vector database.
        
        Args:
            query_text: Text to search for
            n_results: Number of results to return (optional)
            where_filter: Metadata filter (optional)
            
        Returns:
            Dict containing query results or None if failed
        """
        if not self.collection:
            logger.error("Collection not initialized")
            return None
        
        n_results = n_results or config.DEFAULT_N_RESULTS
        n_results = min(n_results, config.MAX_N_RESULTS)
        
        try:
            results = self.collection.query(
                query_texts=[query_text],
                n_results=n_results,
                where=where_filter
            )
            
            # Flatten results for easier use
            flattened = {
                'documents': results['documents'][0] if results['documents'] else [],
                'metadatas': results['metadatas'][0] if results['metadatas'] else [],
                'distances': results['distances'][0] if results['distances'] else [],
                'ids': results['ids'][0] if results['ids'] else []
            }
            
            logger.info(f"Query '{query_text}' returned {len(flattened['documents'])} results")
            return flattened
            
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return None
    
    def get_collection_stats(self) -> Optional[Dict[str, Any]]:
        """Get collection statistics.
        
        Returns:
            Dict with collection statistics or None if failed
        """
        if not self.collection:
            return None
        
        try:
            count = self.collection.count()
            
            # Get sample of data for type analysis
            sample = self.collection.get(limit=min(100, count))
            
            # Analyze data types
            type_counts = {}
            if sample and sample['metadatas']:
                for metadata in sample['metadatas']:
                    doc_type = metadata.get('type', 'unknown')
                    type_counts[doc_type] = type_counts.get(doc_type, 0) + 1
            
            return {
                'total_documents': count,
                'collection_name': self.collection_name,
                'type_distribution': type_counts,
                'embedding_model': config.EMBEDDING_MODEL
            }
            
        except Exception as e:
            logger.error(f"Failed to get collection stats: {e}")
            return None
    
    def delete_collection(self) -> bool:
        """Delete the current collection.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if self.client and self.collection:
                self.client.delete_collection(name=self.collection_name)
                self.collection = None
                logger.info(f"Deleted collection: {self.collection_name}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete collection: {e}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the database.
        
        Returns:
            Dict with health check results
        """
        health = {
            'client_connected': self.client is not None,
            'collection_exists': self.collection is not None,
            'document_count': 0,
            'can_query': False,
            'issues': []
        }
        
        try:
            if self.collection:
                health['document_count'] = self.collection.count()
                
                # Test query
                if health['document_count'] > 0:
                    test_result = self.query("test query", n_results=1)
                    health['can_query'] = test_result is not None
                else:
                    health['issues'].append("No documents in collection")
            else:
                health['issues'].append("Collection not initialized")
                
        except Exception as e:
            health['issues'].append(f"Health check error: {e}")
        
        return health

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        # ChromaDB handles cleanup automatically
        pass