#!/usr/bin/env python3
"""
MITRE ATT&CK Extractor for Bombina
Extracts technique reasoning from MITRE ATT&CK framework
Generates high-quality training samples automatically

Usage: python extract_mitre.py
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Paths
BASE_DIR = Path(__file__).parent.parent.parent
DATA_DIR = BASE_DIR / "data"
MITRE_DIR = DATA_DIR / "mitre"
OUTPUT_DIR = DATA_DIR / "datasets"

# MITRE ATT&CK Categories mapping to our dataset structure
TACTIC_MAPPING = {
    "initial-access": "initial_access",
    "execution": "initial_access",
    "persistence": "persistence",
    "privilege-escalation": "privilege_escalation",
    "defense-evasion": "evasion",
    "credential-access": "privilege_escalation",
    "discovery": "lateral_movement",
    "lateral-movement": "lateral_movement",
    "collection": "c2_exfil",
    "command-and-control": "c2_exfil",
    "exfiltration": "c2_exfil",
    "impact": "failure_analysis",
}


def download_mitre_data():
    """Download MITRE ATT&CK data from GitHub."""
    import subprocess
    
    mitre_repo = "https://github.com/mitre/cti.git"
    mitre_path = MITRE_DIR / "cti"
    
    if mitre_path.exists():
        print(f"📂 MITRE data already exists at {mitre_path}")
        return mitre_path
    
    print("📥 Downloading MITRE ATT&CK data...")
    MITRE_DIR.mkdir(parents=True, exist_ok=True)
    
    result = subprocess.run(
        ["git", "clone", "--depth", "1", mitre_repo, str(mitre_path)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"❌ Failed to clone MITRE repo: {result.stderr}")
        return None
    
    print("✅ MITRE data downloaded")
    return mitre_path


def clean_text(text: str) -> str:
    """Clean and normalize text."""
    if not text:
        return ""
    
    # Remove citations like (Citation: ...)
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    
    # Remove markdown links but keep text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    
    # Remove code blocks
    text = re.sub(r'```[^`]*```', '', text)
    text = re.sub(r'`[^`]+`', '', text)
    
    # Clean whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return text


def extract_technique_reasoning(technique: Dict) -> Optional[Dict]:
    """Extract reasoning-focused training sample from a technique."""
    
    # Get basic info
    name = technique.get("name", "")
    description = technique.get("description", "")
    
    if not name or not description:
        return None
    
    # Clean description
    description = clean_text(description)
    
    if len(description) < 100:
        return None
    
    # Get tactics (categories)
    kill_chain_phases = technique.get("kill_chain_phases", [])
    tactics = [p.get("phase_name", "") for p in kill_chain_phases]
    
    # Get detection info
    detection = ""
    for ref in technique.get("x_mitre_detection", []) if isinstance(technique.get("x_mitre_detection"), list) else []:
        detection += clean_text(ref) + " "
    
    # Also check direct detection field
    if technique.get("x_mitre_detection") and isinstance(technique.get("x_mitre_detection"), str):
        detection = clean_text(technique.get("x_mitre_detection"))
    
    # Get platforms
    platforms = technique.get("x_mitre_platforms", [])
    platform_str = ", ".join(platforms) if platforms else "various systems"
    
    # Get data sources (what defenders monitor)
    data_sources = technique.get("x_mitre_data_sources", [])
    
    # Build training sample focused on REASONING
    instruction = f"Analyze the use of {name} technique in a penetration test."
    
    # Build context-aware input
    input_parts = []
    if platforms:
        input_parts.append(f"Target environment: {platform_str}")
    if tactics:
        input_parts.append(f"Attack phase: {', '.join(tactics)}")
    input_parts.append("Assume standard enterprise security controls are in place.")
    
    input_text = ". ".join(input_parts)
    
    # Build reasoning-focused output
    output_parts = []
    
    # Core reasoning from description (truncate if too long)
    reasoning = description[:800] if len(description) > 800 else description
    output_parts.append(f"Technique overview: {reasoning}")
    
    # Add detection awareness
    if detection:
        detection_short = detection[:300] if len(detection) > 300 else detection
        output_parts.append(f"Detection considerations: {detection_short}")
    elif data_sources:
        output_parts.append(f"Defenders may monitor: {', '.join(data_sources[:5])}. Plan accordingly to minimize artifacts.")
    
    # Add tactical reasoning
    if tactics:
        output_parts.append(f"This technique serves the {', '.join(tactics)} phase(s). Consider sequencing with complementary techniques for a complete attack chain.")
    
    output_text = " ".join(output_parts)
    
    # Quality check - must have substantial reasoning
    if len(output_text) < 200:
        return None
    
    return {
        "instruction": instruction,
        "input": input_text,
        "output": output_text,
        "_meta": {
            "source": "mitre_attack",
            "technique_name": name,
            "tactics": tactics,
            "platforms": platforms
        }
    }


def extract_from_mitre_bundle(bundle_path: Path) -> List[Dict]:
    """Extract techniques from a MITRE STIX bundle."""
    samples = []
    
    try:
        with open(bundle_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"  ⚠️ Error loading {bundle_path}: {e}")
        return []
    
    objects = data.get("objects", [])
    
    for obj in objects:
        # Only process attack-pattern (techniques)
        if obj.get("type") != "attack-pattern":
            continue
        
        # Skip revoked or deprecated
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        
        sample = extract_technique_reasoning(obj)
        if sample:
            samples.append(sample)
    
    return samples


def categorize_sample(sample: Dict) -> str:
    """Determine which dataset category a sample belongs to."""
    tactics = sample.get("_meta", {}).get("tactics", [])
    
    for tactic in tactics:
        if tactic in TACTIC_MAPPING:
            return TACTIC_MAPPING[tactic]
    
    return "initial_access"  # Default


def save_samples_by_category(samples: List[Dict]):
    """Save samples to appropriate category files."""
    categorized = {}
    
    for sample in samples:
        category = categorize_sample(sample)
        if category not in categorized:
            categorized[category] = []
        
        # Remove meta before saving
        clean_sample = {
            "instruction": sample["instruction"],
            "input": sample["input"],
            "output": sample["output"]
        }
        categorized[category].append(clean_sample)
    
    # Save to files
    for category, cat_samples in categorized.items():
        output_dir = OUTPUT_DIR / category
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / "mitre_samples.jsonl"
        
        with open(output_file, 'w') as f:
            for sample in cat_samples:
                f.write(json.dumps(sample) + '\n')
        
        print(f"  📁 {category}: {len(cat_samples)} samples → {output_file.name}")
    
    return categorized


def main():
    """Main extraction pipeline."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA MITRE ATT&CK EXTRACTOR
   Extracting reasoning-focused training data
═══════════════════════════════════════════════════════════════════
""")
    
    # Download MITRE data
    mitre_path = download_mitre_data()
    if not mitre_path:
        print("❌ Failed to get MITRE data")
        return
    
    # Find enterprise attack data
    enterprise_path = mitre_path / "enterprise-attack" / "enterprise-attack.json"
    
    if not enterprise_path.exists():
        print(f"❌ Enterprise ATT&CK file not found: {enterprise_path}")
        return
    
    print(f"\n📂 Processing: {enterprise_path}")
    
    # Extract samples
    samples = extract_from_mitre_bundle(enterprise_path)
    print(f"✅ Extracted {len(samples)} technique samples")
    
    if not samples:
        print("❌ No samples extracted")
        return
    
    # Save by category
    print("\n📁 Saving by category:")
    categorized = save_samples_by_category(samples)
    
    # Summary
    total = sum(len(s) for s in categorized.values())
    print(f"""
═══════════════════════════════════════════════════════════════
✅ EXTRACTION COMPLETE

Total samples: {total}
Categories: {len(categorized)}

Breakdown:
""")
    for cat, samples in sorted(categorized.items()):
        print(f"  • {cat}: {len(samples)}")
    
    print(f"""
Next steps:
  1. Run quality scorer: python quality_scorer.py
  2. Combine datasets: python ../curate_dataset.py (option 2)
  3. Fine-tune: python ../finetune_v2.py
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
