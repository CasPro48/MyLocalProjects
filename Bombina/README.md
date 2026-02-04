# 🐸 Bombina - Cybersecurity AI Assistant

A locally-hosted, fine-tuned LLM specialized in cybersecurity, pentesting, and exploit development.

## Architecture

```
Bombina/
├── configs/
│   └── modelfile              # Ollama model configuration
├── data/
│   ├── training/              # Fine-tuning datasets
│   │   └── cybersecurity_training.jsonl
│   ├── rag/                   # RAG knowledge base
│   │   └── security_basics.md
│   └── chroma_db/             # Vector database (auto-created)
├── models/
│   ├── embeddings/            # Local embedding model cache
│   └── bombina-finetuned/     # Fine-tuned model weights
├── scripts/
│   ├── run_bombina.sh         # Quick launcher (CLI)
│   ├── rag_system.py          # RAG-enhanced chat
│   └── finetune.py            # Fine-tuning script
└── venv/                      # Python virtual environment
```

## Quick Start

### 1. CLI Chat (Basic)
```bash
ollama run bombina
```

### 2. Web UI (Open WebUI) 🌐
```bash
# Already running at:
http://localhost:3000
```

### 3. RAG-Enhanced Chat (with knowledge base)
```bash
cd ~/MyLocalProjects/Bombina
source venv/bin/activate
python scripts/rag_system.py
```

### 4. Fine-tune on Custom Data
```bash
cd ~/MyLocalProjects/Bombina
source venv/bin/activate
# Add your training data to data/training/
python scripts/finetune.py
```

## Current Setup

| Component | Status | Details |
|-----------|--------|---------|
| Base Model | ✅ | qwen2.5-coder:3b |
| Ollama | ✅ | Running on localhost:11434 |
| Open WebUI | ✅ | http://localhost:3000 |
| RAG System | ✅ | LlamaIndex + ChromaDB |
| Fine-tuning | ✅ | Unsloth + LoRA ready |
| GPU | ✅ | Quadro M1000M (4GB VRAM) |

## Adding Knowledge (RAG)

Add documents to `data/rag/` folder:
- `.txt`, `.md`, `.pdf` files supported
- Security docs, CVE descriptions, tool manuals
- The RAG system will automatically index them

## Fine-tuning

1. Add training examples to `data/training/cybersecurity_training.jsonl`:
```json
{"instruction": "Your question/task", "output": "Expected response"}
```

2. Run fine-tuning:
```bash
python scripts/finetune.py
```

3. The fine-tuned model will be exported to GGUF format for Ollama

## API Usage

### Ollama API
```python
import requests

response = requests.post('http://localhost:11434/api/generate', json={
    'model': 'bombina',
    'prompt': 'Write a port scanner in Python',
    'stream': False
})
print(response.json()['response'])
```

### RAG Query (Python)
```python
from scripts.rag_system import setup_bombina_rag, load_existing_index, query_bombina

storage_context, _ = setup_bombina_rag()
index = load_existing_index(storage_context)
response = query_bombina("Explain SQL injection", index)
print(response)
```

## Ports & Services

| Service | Port | URL |
|---------|------|-----|
| Ollama API | 11434 | http://localhost:11434 |
| Open WebUI | 3000 | http://localhost:3000 |

## License

For educational and authorized security testing only.
