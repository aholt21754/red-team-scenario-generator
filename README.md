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
```bash
# .env file
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here

# Optional: Custom database path
VECTOR_DB_PATH=./chroma_db
COLLECTION_NAME=redteam_scenarios
```


