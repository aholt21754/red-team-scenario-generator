# src/data_sources/base_loader.py
"""Abstract base class for data loaders."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

class BaseDataLoader(ABC):
    """Abstract base class for all data loaders."""
    
    @abstractmethod
    def load_data(self) -> List[Dict[str, Any]]:
        """Load data from the source.
        
        Returns:
            List of processed documents ready for vector database
        """
        pass
    
    @abstractmethod
    def validate_data(self, data: List[Dict]) -> bool:
        """Validate the loaded data.
        
        Args:
            data: List of documents to validate
            
        Returns:
            bool: True if data is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def get_data_type(self) -> str:
        """Get the data type identifier for this loader.
        
        Returns:
            String identifier for the data type
        """
        pass
    
    def transform_for_vector_db(self, data: List[Dict]) -> tuple:
        """Transform data into format required by vector database.
        
        Args:
            data: List of processed documents
            
        Returns:
            Tuple of (documents, metadatas, ids) for vector DB
        """
        documents = []
        metadatas = []
        ids = []
        
        for item in data:
            if 'document_text' in item and 'metadata' in item and 'id' in item:
                documents.append(item['document_text'])
                metadatas.append(item['metadata'])
                ids.append(item['id'])
        
        return documents, metadatas, ids