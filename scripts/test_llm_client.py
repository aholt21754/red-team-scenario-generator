# test_llm_client.py
"""Test script for LLM client functionality."""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent / "src"))

from generation.llm_client import LLMClient
from utils.logging_config import setup_logging

def test_llm_client():
    """Test basic LLM client functionality."""
    setup_logging()
    
    print("Testing LLM Client...")
    print("=" * 50)
    
    # Initialize client
    llm_client = LLMClient()
    
    # Check provider info
    provider_info = llm_client.get_provider_info()
    print(f"Provider: {provider_info['provider']}")
    print(f"Available: {provider_info['available']}")
    print(f"Client Type: {provider_info['client_type']}")
    
    # Test simple generation
    test_prompt = """Generate a brief red team scenario description for:
    
    Scenario: Email phishing attack targeting corporate employees
    Environment: Corporate office with standard security measures
    
    Please provide a 2-3 sentence scenario description."""
    
    print("\nTesting generation...")
    print("-" * 30)
    
    response = llm_client.generate(
        prompt=test_prompt,
        max_tokens=200,
        temperature=0.7
    )
    
    if response:
        print("✅ Generation successful!")
        print(f"Response length: {len(response)} characters")
        print("\nGenerated content:")
        print("-" * 30)
        print(response)
        print("-" * 30)
    else:
        print("❌ Generation failed!")
    
    return response is not None

if __name__ == "__main__":
    success = test_llm_client()
    if success:
        print("\n✅ LLM Client test passed!")
    else:
        print("\n❌ LLM Client test failed!")
        sys.exit(1)