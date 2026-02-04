#!/usr/bin/env python3
"""
Merge all datasets and create final training file
Combines: existing + elite + elite2 + elite_unique + massive = 15,000+ samples
"""

import json
import random
from pathlib import Path

base_dir = Path(__file__).parent.parent / "data"
output_dir = base_dir / "final"
output_dir.mkdir(parents=True, exist_ok=True)

print("="*60)
print("BOMBINA DATASET MERGER - Elite Tier (15,000+)")
print("="*60)

all_samples = []

# 1. Load existing processed data
existing_file = base_dir / "processed" / "train.jsonl"
if existing_file.exists():
    with open(existing_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded existing data: {count} samples")

# 2. Load elite dataset
elite_file = base_dir / "generated" / "elite" / "elite_combined.jsonl"
if elite_file.exists():
    with open(elite_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded elite data: {count} samples")

# 3. Load elite2 dataset
elite2_file = base_dir / "generated" / "elite2" / "elite2_combined.jsonl"
if elite2_file.exists():
    with open(elite2_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded elite2 data: {count} samples")

# 4. Load elite_unique dataset
elite_unique_file = base_dir / "generated" / "elite_unique" / "elite_unique_combined.jsonl"
if elite_unique_file.exists():
    with open(elite_unique_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded elite_unique data: {count} samples")

# 5. Load massive dataset
massive_file = base_dir / "generated" / "massive" / "massive_combined.jsonl"
if massive_file.exists():
    with open(massive_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded massive data: {count} samples")

# 6. Load extra dataset
extra_file = base_dir / "generated" / "extra" / "extra_combined.jsonl"
if extra_file.exists():
    with open(extra_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded extra data: {count} samples")

# 7. Load final push dataset
final_push_file = base_dir / "generated" / "final_push" / "final_push_combined.jsonl"
if final_push_file.exists():
    with open(final_push_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded final_push data: {count} samples")

# 8. Load bonus dataset
bonus_file = base_dir / "generated" / "bonus" / "bonus_combined.jsonl"
if bonus_file.exists():
    with open(bonus_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded bonus data: {count} samples")

# 9. Load final_15k dataset
final_15k_file = base_dir / "generated" / "final_15k" / "final_15k_combined.jsonl"
if final_15k_file.exists():
    with open(final_15k_file) as f:
        count = 0
        for line in f:
            all_samples.append(json.loads(line))
            count += 1
    print(f"✓ Loaded final_15k data: {count} samples")

# Deduplicate (based on instruction+input hash)
print("\nDeduplicating...")
seen = set()
unique_samples = []
for sample in all_samples:
    key = hash(sample.get("instruction", "") + sample.get("input", ""))
    if key not in seen:
        seen.add(key)
        unique_samples.append(sample)

print(f"✓ Removed {len(all_samples) - len(unique_samples)} duplicates")
all_samples = unique_samples

# Shuffle
random.shuffle(all_samples)

# Split into train/val (95/5)
split_idx = int(len(all_samples) * 0.95)
train_samples = all_samples[:split_idx]
val_samples = all_samples[split_idx:]

# Save files
train_file = output_dir / "train.jsonl"
val_file = output_dir / "val.jsonl"

with open(train_file, "w") as f:
    for sample in train_samples:
        f.write(json.dumps(sample) + "\n")

with open(val_file, "w") as f:
    for sample in val_samples:
        f.write(json.dumps(sample) + "\n")

print("\n" + "="*60)
print("✅ FINAL DATASET READY FOR FINE-TUNING!")
print("="*60)
print(f"   Train samples: {len(train_samples)}")
print(f"   Val samples:   {len(val_samples)}")
print(f"   TOTAL:         {len(all_samples)}")
print(f"\n   Output directory: {output_dir}")
print(f"   - train.jsonl")
print(f"   - val.jsonl")
print("="*60)

# Print category breakdown
print("\nSample categories breakdown:")
categories = {}
for sample in all_samples:
    inst = sample.get("instruction", "").lower()
    if "active directory" in inst or " ad " in inst:
        cat = "Active Directory"
    elif "cloud" in inst or "aws" in inst or "azure" in inst or "gcp" in inst:
        cat = "Cloud Security"
    elif "web" in inst or "sql" in inst or "xss" in inst:
        cat = "Web Security"
    elif "network" in inst or "nmap" in inst:
        cat = "Network Security"
    elif "malware" in inst or "evasion" in inst:
        cat = "Malware/Evasion"
    elif "forensic" in inst or "incident" in inst:
        cat = "Forensics/IR"
    elif "exploit" in inst or "buffer" in inst:
        cat = "Exploitation"
    elif "pentest" in inst or "report" in inst:
        cat = "Pentest Methodology"
    elif "mitre" in inst or "att&ck" in inst:
        cat = "MITRE ATT&CK"
    elif "opsec" in inst or "stealth" in inst:
        cat = "OPSEC"
    else:
        cat = "General Security"
    
    categories[cat] = categories.get(cat, 0) + 1

for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"   {cat}: {count}")
