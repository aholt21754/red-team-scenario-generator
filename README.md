## Setup

### Virtual Environment
```python
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Install packages:

```bash
pip install -r requirements.txt
```

### Configure .env
Create the .env file and add the appropriate information below
```bash
# .env file
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here

# Optional: Custom database path
VECTOR_DB_PATH=./chroma_db
COLLECTION_NAME=redteam_scenarios
```

### Setup and test the Vector DB
Expected output:
🚀 Vector Database Test Suite
============================================================

🗄️ Testing Vector Database Setup...
✅ Database connection successful      ← Creates fresh database
✅ Collection created successfully     ← Sets up collections

🎯 Testing MITRE ATT&CK Data Loading...
⏳ Loading MITRE data...              ← Downloads and processes MITRE data
✅ Successfully added 600+ documents   ← Loads into database

🔍 Testing Database Queries...         ← Tests search functionality
📊 Found results for test queries      ← Validates everything works


