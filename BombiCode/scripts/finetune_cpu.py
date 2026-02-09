#!/usr/bin/env python3
"""
Bombina Fine-tuning Script - CPU Version
For systems where GPU is unavailable or incompatible

Uses standard transformers + peft without GPU-specific optimizations
Training will be slower but functional

Run: python finetune_cpu.py
"""

import os
import sys
import yaml
from pathlib import Path
from datetime import datetime
from datasets import load_dataset
import torch

# Force CPU
os.environ["CUDA_VISIBLE_DEVICES"] = ""

# Paths
BASE_DIR = Path(__file__).parent.parent
CONFIG_FILE = BASE_DIR / "configs" / "lora_config.yaml"
LORA_DIR = BASE_DIR / "lora"

def load_config():
    """Load LoRA configuration from YAML."""
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def format_prompt(example):
    """Format training examples into instruction format."""
    instruction = example.get('instruction', '')
    input_text = example.get('input', '')
    output = example.get('output', '')
    
    if input_text:
        return f"""### Instruction:
{instruction}

### Input:
{input_text}

### Response:
{output}"""
    else:
        return f"""### Instruction:
{instruction}

### Response:
{output}"""

def prepare_dataset():
    """Load and prepare training dataset."""
    training_file = BASE_DIR / "data" / "train.jsonl"
    
    if not training_file.exists():
        print(f"❌ Training file not found: {training_file}")
        print("   Run: python pipeline/combine_datasets.py first!")
        sys.exit(1)
    
    print(f"📂 Loading dataset from {training_file}")
    dataset = load_dataset('json', data_files=str(training_file), split='train')
    
    print(f"   Found {len(dataset)} training samples")
    return dataset

def finetune_bombina():
    """Main fine-tuning function for CPU."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA FINE-TUNING - CPU Version
   Will train on CPU (slower but compatible)
═══════════════════════════════════════════════════════════════════
""")
    
    print(f"🖥️  Device: CPU")
    print(f"💾 RAM: {os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024**3):.1f} GB")
    
    # Load config
    config = load_config()
    print(f"\n📋 Config loaded: {CONFIG_FILE}")
    
    # Load dataset
    dataset = prepare_dataset()
    
    # Import dependencies
    try:
        from transformers import (
            AutoModelForCausalLM, 
            AutoTokenizer, 
            TrainingArguments,
            Trainer,
            DataCollatorForLanguageModeling
        )
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("   Install with: pip install transformers peft datasets accelerate")
        sys.exit(1)
    
    # Load base model from config
    model_name = config.get('model_name', "Qwen/Qwen2.5-0.5B-Instruct")
    print(f"\n🔄 Loading base model: {model_name}")
    if "0.5B" in model_name:
        print("   (Using smaller model for CPU training)")
    else:
        print("   (Note: Large model on CPU will be slow)")
    
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,  # Use FP16 if GPU available
        device_map="auto" if torch.cuda.is_available() else "cpu",
        trust_remote_code=True
    )
    
    # Configure LoRA
    print("🔧 Adding LoRA adapters...")
    lora_config = LoraConfig(
        r=config['lora_r'],
        lora_alpha=config['lora_alpha'],
        lora_dropout=config['lora_dropout'],
        target_modules=config['target_modules'],
        bias="none",
        task_type="CAUSAL_LM"
    )
    
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    
    # Prepare dataset
    def tokenize_and_format(examples):
        texts = []
        for i in range(len(examples['instruction'])):
            example = {
                'instruction': examples['instruction'][i],
                'input': examples.get('input', [''] * len(examples['instruction']))[i] if 'input' in examples else '',
                'output': examples['output'][i]
            }
            texts.append(format_prompt(example) + tokenizer.eos_token)
        
        tokenized = tokenizer(
            texts,
            truncation=True,
            max_length=config.get('max_seq_length', 512),
            padding="max_length"
        )
        tokenized["labels"] = tokenized["input_ids"].copy()
        return tokenized
    
    print("\n📊 Tokenizing dataset...")
    tokenized_dataset = dataset.map(
        tokenize_and_format, 
        batched=True, 
        remove_columns=dataset.column_names,
        desc="Tokenizing"
    )
    
    # Split for eval
    split = tokenized_dataset.train_test_split(test_size=0.05, seed=42)
    
    # Training arguments (optimized for CPU)
    version = datetime.now().strftime("%Y%m%d_%H%M")
    output_dir = LORA_DIR / f"cpu_v_{version}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check for existing checkpoints to resume
    resume_from_checkpoint = None
    if output_dir.exists():
        checkpoints = [d for d in output_dir.iterdir() if d.is_dir() and d.name.startswith("checkpoint-")]
        if checkpoints:
            # Find the latest checkpoint by step number
            checkpoints.sort(key=lambda x: int(x.name.split("-")[1]))
            resume_from_checkpoint = str(checkpoints[-1])
            print(f"📍 Resuming from checkpoint: {resume_from_checkpoint}")
        else:
            # Check other cpu_v directories for latest checkpoint
            all_versions = [d for d in LORA_DIR.iterdir() if d.is_dir() and d.name.startswith("cpu_v_")]
            if all_versions:
                all_versions.sort(key=lambda x: x.stat().st_mtime, reverse=True)
                latest_version = all_versions[0]
                checkpoints = [d for d in latest_version.iterdir() if d.is_dir() and d.name.startswith("checkpoint-")]
                if checkpoints:
                    checkpoints.sort(key=lambda x: int(x.name.split("-")[1]))
                    resume_from_checkpoint = str(checkpoints[-1])
                    output_dir = latest_version  # Use the existing directory
                    print(f"📍 Resuming from latest checkpoint: {resume_from_checkpoint}")
    
    use_gpu = torch.cuda.is_available()
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        per_device_train_batch_size=config.get('per_device_train_batch_size', 1),
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=config.get('gradient_accumulation_steps', 16),
        warmup_ratio=config.get('warmup_ratio', 0.05),
        num_train_epochs=config.get('num_train_epochs', 1),
        learning_rate=config.get('learning_rate', 2e-4),
        logging_steps=config.get('logging_steps', 50),
        save_steps=config.get('save_steps', 500),
        save_total_limit=2,
        eval_strategy=config.get('eval_strategy', 'steps'),
        eval_steps=config.get('eval_steps', 500),
        load_best_model_at_end=True,
        optim=config.get('optim', 'adamw_torch'),
        lr_scheduler_type=config.get('lr_scheduler_type', 'cosine'),
        seed=42,
        report_to="none",
        use_cpu=not use_gpu,
        fp16=use_gpu,  # Enable FP16 on GPU
        bf16=config.get('bf16', False),
    )
    
    # Data collator
    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer,
        mlm=False
    )
    
    # Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=split["train"],
        eval_dataset=split["test"],
        data_collator=data_collator,
    )
    
    # Train
    device_type = "GPU" if torch.cuda.is_available() else "CPU"
    print(f"\n🚀 Starting {device_type} fine-tuning...")
    print(f"   Output: {output_dir}")
    print(f"   Epochs: {config.get('num_train_epochs', 1)}")
    if resume_from_checkpoint:
        print(f"   Resuming from: {resume_from_checkpoint}")
    print(f"   This will be {'faster' if torch.cuda.is_available() else 'slow'} on {device_type}...")
    print("-" * 50)
    
    trainer.train(resume_from_checkpoint=resume_from_checkpoint)
    
    # Save the model
    print("\n💾 Saving fine-tuned model...")
    model.save_pretrained(output_dir / "lora_adapter")
    tokenizer.save_pretrained(output_dir / "lora_adapter")
    
    print(f"""
✅ ═══════════════════════════════════════════════════════════════
   CPU FINE-TUNING COMPLETE
═══════════════════════════════════════════════════════════════════

📁 Output: {output_dir}

⚠️  Note: This trained a smaller model (0.5B) for CPU compatibility.
    For production, consider:
    1. Using cloud GPU for training
    2. Using a pre-quantized model
    3. Fine-tuning the full 3B model with GPU

📊 Next steps:
   1. Test the adapter
   2. If results are good, try longer training
""")

if __name__ == "__main__":
    finetune_bombina()
