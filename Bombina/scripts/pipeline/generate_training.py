#!/usr/bin/env python3
"""
Training Data Generator for Bombina
Converts raw writeups/blogs into reasoning-focused training samples
Uses local Ollama LLM for transformation

Usage: python generate_training.py [input_dir]
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import time

# Paths
BASE_DIR = Path(__file__).parent.parent.parent
PROMPTS_DIR = Path(__file__).parent / "prompts"
RAW_DIR = BASE_DIR / "data" / "raw"
OUTPUT_DIR = BASE_DIR / "data" / "datasets"
LOGS_DIR = BASE_DIR / "data" / "logs" / "pipeline"

# Config
DEFAULT_MODEL = "bombina"  # Use Bombina itself for transformation
FALLBACK_MODEL = "qwen2.5-coder:3b"
MAX_CHUNK_SIZE = 3000  # Characters per chunk
RETRY_ATTEMPTS = 3
RETRY_DELAY = 2


def load_prompt_template() -> str:
    """Load the reasoning extraction prompt."""
    prompt_file = PROMPTS_DIR / "reasoning_extract.txt"
    
    if not prompt_file.exists():
        print(f"❌ Prompt template not found: {prompt_file}")
        sys.exit(1)
    
    with open(prompt_file, 'r') as f:
        return f.read()


def check_ollama() -> Optional[str]:
    """Check if Ollama is running and return available model."""
    try:
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            return None
        
        models = result.stdout.lower()
        
        if DEFAULT_MODEL in models:
            return DEFAULT_MODEL
        elif FALLBACK_MODEL.split(':')[0] in models:
            return FALLBACK_MODEL
        else:
            # Return first available model
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            if lines:
                return lines[0].split()[0]
        
        return None
        
    except Exception as e:
        print(f"❌ Ollama check failed: {e}")
        return None


def call_llm(prompt: str, model: str) -> Optional[str]:
    """Call Ollama LLM and get response."""
    for attempt in range(RETRY_ATTEMPTS):
        try:
            result = subprocess.run(
                ["ollama", "run", model],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            
            print(f"  ⚠️ Attempt {attempt + 1} failed: {result.stderr[:100]}")
            
        except subprocess.TimeoutExpired:
            print(f"  ⚠️ Attempt {attempt + 1} timed out")
        except Exception as e:
            print(f"  ⚠️ Attempt {attempt + 1} error: {e}")
        
        if attempt < RETRY_ATTEMPTS - 1:
            time.sleep(RETRY_DELAY)
    
    return None


def clean_raw_text(text: str) -> str:
    """Clean raw text from writeups."""
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Remove URLs
    text = re.sub(r'https?://\S+', '[URL]', text)
    
    # Remove code blocks but note their presence
    text = re.sub(r'```[\s\S]*?```', '[CODE_BLOCK]', text)
    
    # Remove inline code
    text = re.sub(r'`[^`]+`', '[COMMAND]', text)
    
    # Normalize whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {2,}', ' ', text)
    
    return text.strip()


def chunk_text(text: str, max_size: int = MAX_CHUNK_SIZE) -> List[str]:
    """Split text into chunks for processing."""
    # Try to split on paragraph boundaries
    paragraphs = text.split('\n\n')
    
    chunks = []
    current_chunk = ""
    
    for para in paragraphs:
        if len(current_chunk) + len(para) < max_size:
            current_chunk += para + "\n\n"
        else:
            if current_chunk:
                chunks.append(current_chunk.strip())
            current_chunk = para + "\n\n"
    
    if current_chunk:
        chunks.append(current_chunk.strip())
    
    # Filter out very short chunks
    chunks = [c for c in chunks if len(c) > 200]
    
    return chunks


def parse_llm_response(response: str) -> Optional[Dict]:
    """Parse LLM response into training sample."""
    if not response:
        return None
    
    # Try to find JSON in response
    # Look for JSON object pattern
    json_match = re.search(r'\{[^{}]*"instruction"[^{}]*"input"[^{}]*"output"[^{}]*\}', response, re.DOTALL)
    
    if not json_match:
        # Try alternative pattern
        json_match = re.search(r'\{[\s\S]*?\}', response)
    
    if json_match:
        try:
            data = json.loads(json_match.group())
            
            # Validate required fields
            if all(k in data for k in ["instruction", "input", "output"]):
                # Clean up values
                for key in ["instruction", "input", "output"]:
                    if isinstance(data[key], str):
                        data[key] = data[key].strip()
                
                return data
        except json.JSONDecodeError:
            pass
    
    # Try to extract fields manually
    instruction_match = re.search(r'"instruction"\s*:\s*"([^"]+)"', response)
    input_match = re.search(r'"input"\s*:\s*"([^"]+)"', response)
    output_match = re.search(r'"output"\s*:\s*"([^"]+)"', response)
    
    if instruction_match and output_match:
        return {
            "instruction": instruction_match.group(1),
            "input": input_match.group(1) if input_match else "",
            "output": output_match.group(1)
        }
    
    return None


def process_file(file_path: Path, model: str, prompt_template: str) -> List[Dict]:
    """Process a single file and generate training samples."""
    samples = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"  ❌ Error reading {file_path}: {e}")
        return []
    
    # Clean text
    content = clean_raw_text(content)
    
    if len(content) < 200:
        print(f"  ⏭️ Skipping {file_path.name} (too short)")
        return []
    
    # Chunk if needed
    chunks = chunk_text(content)
    
    print(f"  📄 Processing {file_path.name} ({len(chunks)} chunks)")
    
    for i, chunk in enumerate(chunks):
        # Build prompt
        prompt = prompt_template + chunk
        
        # Call LLM
        response = call_llm(prompt, model)
        
        if response:
            sample = parse_llm_response(response)
            
            if sample:
                sample["_meta"] = {
                    "source_file": file_path.name,
                    "chunk": i + 1,
                    "generated_at": datetime.now().isoformat()
                }
                samples.append(sample)
                print(f"    ✅ Chunk {i + 1}/{len(chunks)}: Generated sample")
            else:
                print(f"    ⚠️ Chunk {i + 1}/{len(chunks)}: Failed to parse response")
        else:
            print(f"    ❌ Chunk {i + 1}/{len(chunks)}: No response from LLM")
    
    return samples


def categorize_sample(sample: Dict, source_file: str) -> str:
    """Guess category based on content and filename."""
    text = (sample.get("instruction", "") + " " + 
            sample.get("output", "")).lower()
    source = source_file.lower()
    
    # Check keywords
    if any(w in text for w in ["initial access", "phishing", "exploit", "entry point"]):
        return "initial_access"
    elif any(w in text for w in ["privilege", "escalat", "root", "admin", "sudo"]):
        return "privilege_escalation"
    elif any(w in text for w in ["lateral", "movement", "pivot", "spread"]):
        return "lateral_movement"
    elif any(w in text for w in ["evasion", "stealth", "bypass", "detection"]):
        return "evasion"
    elif any(w in text for w in ["persist", "backdoor", "maintain"]):
        return "persistence"
    elif any(w in text for w in ["c2", "exfil", "command and control", "beacon"]):
        return "c2_exfil"
    elif any(w in text for w in ["fail", "error", "wrong", "mistake"]):
        return "failure_analysis"
    elif any(w in text for w in ["blue team", "defend", "detect", "monitor"]):
        return "blue_team"
    elif any(w in text for w in ["web", "sql", "xss", "injection"]):
        return "web_attacks"
    elif any(w in text for w in ["active directory", "kerberos", "ldap", "domain"]):
        return "ad_attacks"
    elif any(w in text for w in ["cloud", "aws", "azure", "gcp"]):
        return "cloud_attacks"
    
    return "initial_access"  # Default


def save_samples(samples: List[Dict], output_name: str = "generated"):
    """Save samples organized by category."""
    if not samples:
        print("No samples to save")
        return
    
    categorized = {}
    
    for sample in samples:
        source = sample.get("_meta", {}).get("source_file", "unknown")
        category = categorize_sample(sample, source)
        
        if category not in categorized:
            categorized[category] = []
        
        # Remove meta for training
        clean_sample = {
            "instruction": sample["instruction"],
            "input": sample["input"],
            "output": sample["output"]
        }
        categorized[category].append(clean_sample)
    
    # Save to category files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    for category, cat_samples in categorized.items():
        output_dir = OUTPUT_DIR / category
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / f"{output_name}_{timestamp}.jsonl"
        
        with open(output_file, 'w') as f:
            for sample in cat_samples:
                f.write(json.dumps(sample) + '\n')
        
        print(f"  📁 {category}: {len(cat_samples)} samples → {output_file.name}")
    
    return categorized


def main():
    """Main generation pipeline."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA TRAINING DATA GENERATOR
   Converting writeups to reasoning samples
═══════════════════════════════════════════════════════════════════
""")
    
    # Check Ollama
    model = check_ollama()
    if not model:
        print("❌ Ollama not available. Start with: ollama serve")
        sys.exit(1)
    
    print(f"🤖 Using model: {model}")
    
    # Load prompt
    prompt_template = load_prompt_template()
    print("📝 Prompt template loaded")
    
    # Determine input directory
    input_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else RAW_DIR
    
    if not input_dir.exists():
        print(f"❌ Input directory not found: {input_dir}")
        print(f"   Create it and add .txt or .md files")
        sys.exit(1)
    
    # Find input files
    input_files = list(input_dir.glob("*.txt")) + list(input_dir.glob("*.md"))
    
    if not input_files:
        print(f"❌ No .txt or .md files found in {input_dir}")
        print("""
To use this generator:
  1. Add writeups/blogs to: {RAW_DIR}
  2. Supported formats: .txt, .md
  3. Run this script again
  
Example sources:
  - HTB writeups
  - CTF walkthroughs
  - Blog posts (copy as text)
""")
        sys.exit(1)
    
    print(f"📂 Found {len(input_files)} files in {input_dir}")
    
    # Process files
    all_samples = []
    
    for file_path in input_files:
        samples = process_file(file_path, model, prompt_template)
        all_samples.extend(samples)
    
    # Save results
    if all_samples:
        print(f"\n📊 Generated {len(all_samples)} total samples")
        print("\n📁 Saving by category:")
        save_samples(all_samples)
    else:
        print("\n❌ No samples generated")
    
    print(f"""
═══════════════════════════════════════════════════════════════
✅ GENERATION COMPLETE

Next steps:
  1. Run quality scorer: python quality_scorer.py
  2. Review samples in data/datasets/
  3. Combine: python ../curate_dataset.py (option 2)
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
