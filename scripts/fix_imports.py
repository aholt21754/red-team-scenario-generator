# fix_imports.py
"""Quick fix for import issues in the codebase."""

import sys
from pathlib import Path

def fix_import_paths():
    """Add src directory to Python path."""
    src_path = Path(__file__).parent.parent / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))
    
    # Also add parent directory
    parent_path = Path(__file__).parent
    if str(parent_path) not in sys.path:
        sys.path.insert(0, str(parent_path))



# Apply fixes
fix_import_paths()

# Test imports
try:
    from config import config
    print("✅ Config import successful")
except ImportError as e:
    print(f"❌ Config import failed: {e}")

try:
    from database.vector_db import VectorDB
    print("✅ VectorDB import successful")
except ImportError as e:
    print(f"❌ VectorDB import failed: {e}")

try:
    from generation.llm_client import LLMClient
    print("✅ LLMClient import successful")
except ImportError as e:
    print(f"❌ LLMClient import failed: {e}")

try:
    from generation.scenario_generator import ScenarioGenerator
    print("✅ ScenarioGenerator import successful")
except ImportError as e:
    print(f"❌ ScenarioGenerator import failed: {e}")

print("\nIf any imports failed, you may need to adjust your PYTHONPATH or file structure.")