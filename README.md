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
ANTHROPIC_API_KEY=your_anthropic_key_here
ANTHROPIC_MODEL=claude-sonnet-4-20250514

# Optional: Custom database path
VECTOR_DB_PATH=./chroma_db
COLLECTION_NAME=redteam_scenarios
```

### Setup and test the Vector DB
Run test_vector_db.py
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

### Test LLM Configuration
Run test_llm_client.py
Expected output:
Testing LLM Client...
==================================================
2025-09-19 20:42:59,751 - generation.llm_client - INFO - Available LLM providers: ['anthropic', 'mock']
2025-09-19 20:42:59,820 - generation.llm_client - INFO - Anthropic client initialized with model: claude-sonnet-4-20250514
2025-09-19 20:42:59,820 - generation.llm_client - INFO - LLM client initialized with provider: anthropic
2025-09-19 20:43:01,243 - httpx - INFO - HTTP Request: POST https://api.anthropic.com/v1/messages "HTTP/1.1 200 OK"
Provider: anthropic
Available: True
Client Type: AnthropicClient

Testing generation...
------------------------------
2025-09-19 20:43:05,592 - httpx - INFO - HTTP Request: POST https://api.anthropic.com/v1/messages "HTTP/1.1 200 OK"
2025-09-19 20:43:05,593 - generation.llm_client - INFO - Anthropic generation successful (744 characters)
✅ Generation successful!
Response length: 744 characters

Generated content:
------------------------------
**Red Team Scenario: Corporate Email Phishing Campaign**

The red team will conduct a spear-phishing attack against corporate employees by crafting convincing emails that appear to originate from trusted internal sources (HR, IT department, or executive leadership) containing malicious links or attachments designed to harvest credentials or establish initial system access. The attack will test employees' security awareness and the organization's email filtering capabilities, technical controls, and incident response procedures. Success will be measured by the number of employees who interact with malicious content and whether the team can escalate privileges or move laterally through the corporate network following initial compromise.
------------------------------

✅ LLM Client test passed!

### Test LLM With Vector DB
Run test_scenario_generation.py
This will run the scenario generation end to end and test

### Test Evaluator
Run test_evaluator.py

### Running Application
#### Commandline
interactive/chatbot.py

#### StreamLit
```bash
pip install streamlit
streamlit run streamlit_app.py
```

