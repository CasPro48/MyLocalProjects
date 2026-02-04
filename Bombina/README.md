# 🐸 Bombina - Cybersecurity AI Assistant

A locally-hosted, fine-tuned LLM specialized in cybersecurity, pentesting, and exploit development.

## Architecture

```
Bombina/
├── configs/
│   └── modelfile          # Ollama model configuration
├── data/
│   ├── training/          # Fine-tuning datasets (CVEs, exploits, writeups)
│   └── rag/               # RAG knowledge base documents
├── models/                # Custom model weights (after fine-tuning)
└── scripts/
    └── run_bombina.sh     # Quick launcher
```

## Quick Start

```bash
# Run Bombina
./scripts/run_bombina.sh

# Or directly with Ollama
ollama run bombina
```

## Current Setup

| Component | Status |
|-----------|--------|
| Base Model | qwen2.5-coder:3b |
| Runner | Ollama |
| GPU | Quadro M1000M (4GB VRAM) |
| System Prompt | Security-focused |

## Next Steps

1. **Fine-tuning**: Add training data for cybersecurity domain
   - CVE descriptions and exploits
   - Pentest reports
   - CTF writeups
   
2. **RAG Integration**: Add knowledge base
   - OWASP documentation
   - Security tool manuals
   - Vulnerability databases

3. **Self-learning**: Implement feedback loop
   - Save successful interactions
   - Continuous improvement

## API Usage

```python
import requests

response = requests.post('http://localhost:11434/api/generate', json={
    'model': 'bombina',
    'prompt': 'Write a port scanner in Python',
    'stream': False
})
print(response.json()['response'])
```

## License

For educational and authorized security testing only.
