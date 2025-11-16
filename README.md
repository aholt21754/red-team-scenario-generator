## Overview
LLM based chatbot to help generate red team scenarios utilizing ATT&CK, CAPEC, and CWE.

```mermaid
---
config:
  layout: dagre
---
flowchart TB
 subgraph subGraph0["Data Sources"]
        A1["MITRE ATT&amp;CK API<br>Enterprise Techniques"]
        A2["CAPEC XML<br>Attack Patterns<br>capec.mitre.org"]
        A3["CWE XML<br>Weakness Enumeration<br>cwe.mitre.org"]
  end
  subgraph subGraph7["Streamlit UI"]
        BA["User"]
        BB["Request Query"]
        BC["Environment"]
        BD["Skill Level"]
  end
       U["AnthropicClient<br>claude-3-sonnet-20240229"]
       AB["Generated Scenario"]
       AH["Evaluation Scores:<br>- level_of_detail<br>- technical_accuracy<br>- realism<br>- creativity<br>- alignment"]
       AC["Final Result with Generated Scenario and Evaluation"]
A1 --> U
A2 --> U
A3 --> U
BA --> BB
BA --> BC
BA --> BD
BB --> U
BC --> U
BD --> U
AH --> U
U --> AB
AB --> AH
U --> AC
    style AC fill:#99ff99
    style A1 fill:#99ccff
    style U fill:#ff9999
    style BA fill:#ffcc99
    style A2 fill:#99ccff
    style A3 fill:#99ccff
    style AH fill:#ffcc99
```

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

### Test LLM Configuration

Run test_llm_client.py

### Test LLM With Vector DB
Run test_scenario_generation.py - This will run the scenario generation end to end and test

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

