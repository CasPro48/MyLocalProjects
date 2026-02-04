#!/usr/bin/env python3
"""
Quality Scorer for Bombina Training Data
Automatically scores and filters training samples
Keeps only high-quality reasoning-focused data

Usage: python quality_scorer.py
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

# Paths
BASE_DIR = Path(__file__).parent.parent.parent
DATASETS_DIR = BASE_DIR / "data" / "datasets"
REJECTED_DIR = BASE_DIR / "retrain" / "rejected"

# Scoring weights
REASONING_KEYWORDS = [
    ("because", 2),
    ("therefore", 2),
    ("however", 1),
    ("risk", 2),
    ("tradeoff", 3),
    ("trade-off", 3),
    ("detection", 2),
    ("avoid", 1),
    ("alternative", 2),
    ("instead", 1),
    ("consider", 1),
    ("prioritize", 2),
    ("likelihood", 2),
    ("probability", 1),
    ("constraint", 2),
    ("limitation", 1),
    ("decision", 2),
    ("choose", 1),
    ("prefer", 1),
    ("recommend", 1),
    ("stealth", 2),
    ("evasion", 2),
    ("monitor", 1),
    ("defender", 2),
    ("blue team", 2),
    ("failure", 2),
    ("fallback", 2),
]

# Negative indicators (reduce score)
COMMAND_PATTERNS = [
    (r'\bnmap\s+-', -2),
    (r'\bsudo\s+\w+', -1),
    (r'\bwget\s+', -1),
    (r'\bcurl\s+', -1),
    (r'```', -3),  # Code blocks
    (r'\$\(', -2),  # Command substitution
    (r'\bexec\s*\(', -2),
    (r'0x[0-9a-fA-F]+', -1),  # Hex values
    (r'\b(?:bash|sh|zsh)\s+-c', -2),
]

# Minimum thresholds
MIN_SCORE = 4
MIN_OUTPUT_LENGTH = 150
MAX_OUTPUT_LENGTH = 2000


def score_sample(sample: Dict) -> Tuple[int, List[str]]:
    """
    Score a training sample based on reasoning quality.
    Returns (score, list of reasons).
    """
    score = 0
    reasons = []
    
    output_text = sample.get("output", "").lower()
    full_text = (sample.get("instruction", "") + " " + 
                 sample.get("input", "") + " " + 
                 sample.get("output", "")).lower()
    
    # Length checks
    output_len = len(sample.get("output", ""))
    
    if output_len < MIN_OUTPUT_LENGTH:
        score -= 3
        reasons.append(f"Output too short ({output_len} chars)")
    elif output_len > MAX_OUTPUT_LENGTH:
        score -= 1
        reasons.append(f"Output very long ({output_len} chars)")
    else:
        score += 1
        reasons.append(f"Good length ({output_len} chars)")
    
    # Check for reasoning keywords
    keyword_count = 0
    for keyword, weight in REASONING_KEYWORDS:
        if keyword in output_text:
            score += weight
            keyword_count += 1
    
    if keyword_count >= 5:
        reasons.append(f"Strong reasoning ({keyword_count} keywords)")
    elif keyword_count >= 3:
        reasons.append(f"Moderate reasoning ({keyword_count} keywords)")
    else:
        reasons.append(f"Weak reasoning ({keyword_count} keywords)")
    
    # Check for command patterns (negative)
    command_count = 0
    for pattern, penalty in COMMAND_PATTERNS:
        matches = len(re.findall(pattern, full_text))
        if matches:
            score += penalty * matches
            command_count += matches
    
    if command_count > 0:
        reasons.append(f"Contains commands ({command_count} patterns)")
    
    # Check for structure
    if sample.get("input") and len(sample.get("input", "")) > 20:
        score += 1
        reasons.append("Has meaningful input context")
    
    # Check for numbered points or structure
    if re.search(r'\d\)', output_text) or re.search(r'\d\.', output_text):
        score += 1
        reasons.append("Has structured points")
    
    # Bonus for detection awareness
    if any(word in output_text for word in ["detect", "monitor", "alert", "log"]):
        score += 2
        reasons.append("Detection-aware")
    
    # Bonus for alternatives mentioned
    if any(word in output_text for word in ["alternatively", "another approach", "fallback"]):
        score += 2
        reasons.append("Mentions alternatives")
    
    return score, reasons


def process_category(category_dir: Path) -> Dict:
    """Process all samples in a category directory."""
    results = {
        "kept": [],
        "rejected": [],
        "scores": []
    }
    
    for jsonl_file in category_dir.glob("*.jsonl"):
        samples = []
        
        with open(jsonl_file, 'r') as f:
            for line in f:
                try:
                    sample = json.loads(line)
                    samples.append(sample)
                except json.JSONDecodeError:
                    continue
        
        for sample in samples:
            score, reasons = score_sample(sample)
            
            results["scores"].append(score)
            
            if score >= MIN_SCORE:
                results["kept"].append({
                    "sample": sample,
                    "score": score,
                    "reasons": reasons,
                    "source": jsonl_file.name
                })
            else:
                results["rejected"].append({
                    "sample": sample,
                    "score": score,
                    "reasons": reasons,
                    "source": jsonl_file.name
                })
    
    return results


def save_quality_results(category: str, results: Dict):
    """Save quality scoring results."""
    category_dir = DATASETS_DIR / category
    
    # Save kept samples back (overwrite with quality-filtered)
    if results["kept"]:
        output_file = category_dir / "quality_filtered.jsonl"
        
        with open(output_file, 'w') as f:
            for item in results["kept"]:
                f.write(json.dumps(item["sample"]) + '\n')
    
    # Save rejected for review
    if results["rejected"]:
        reject_dir = REJECTED_DIR / category
        reject_dir.mkdir(parents=True, exist_ok=True)
        
        reject_file = reject_dir / f"rejected_{datetime.now().strftime('%Y%m%d')}.jsonl"
        
        with open(reject_file, 'w') as f:
            for item in results["rejected"]:
                entry = {
                    "sample": item["sample"],
                    "score": item["score"],
                    "reasons": item["reasons"]
                }
                f.write(json.dumps(entry) + '\n')


def print_score_distribution(all_scores: List[int]):
    """Print ASCII histogram of scores."""
    if not all_scores:
        return
    
    min_score = min(all_scores)
    max_score = max(all_scores)
    
    print("\n📊 Score Distribution:")
    print("-" * 50)
    
    for score in range(min_score, max_score + 1):
        count = all_scores.count(score)
        bar = "█" * min(count, 40)
        status = "✅" if score >= MIN_SCORE else "❌"
        print(f"  {score:3d} {status} │{bar} ({count})")
    
    print("-" * 50)


def main():
    """Main quality scoring pipeline."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA QUALITY SCORER
   Filtering training data for reasoning quality
═══════════════════════════════════════════════════════════════════
""")
    
    print(f"⚙️ Minimum score threshold: {MIN_SCORE}")
    print(f"📏 Output length range: {MIN_OUTPUT_LENGTH}-{MAX_OUTPUT_LENGTH} chars\n")
    
    total_kept = 0
    total_rejected = 0
    all_scores = []
    
    # Process each category
    for category_dir in DATASETS_DIR.iterdir():
        if not category_dir.is_dir():
            continue
        
        category = category_dir.name
        results = process_category(category_dir)
        
        if not results["scores"]:
            continue
        
        kept = len(results["kept"])
        rejected = len(results["rejected"])
        total = kept + rejected
        
        total_kept += kept
        total_rejected += rejected
        all_scores.extend(results["scores"])
        
        # Calculate average score
        avg_score = sum(results["scores"]) / len(results["scores"]) if results["scores"] else 0
        
        print(f"📁 {category}:")
        print(f"   Total: {total} | Kept: {kept} | Rejected: {rejected} | Avg score: {avg_score:.1f}")
        
        # Save results
        save_quality_results(category, results)
        
        # Show some rejected reasons
        if results["rejected"][:2]:
            print(f"   Sample rejections:")
            for item in results["rejected"][:2]:
                print(f"      Score {item['score']}: {', '.join(item['reasons'][:3])}")
        print()
    
    # Print distribution
    print_score_distribution(all_scores)
    
    # Summary
    total = total_kept + total_rejected
    keep_rate = (total_kept / total * 100) if total > 0 else 0
    
    print(f"""
═══════════════════════════════════════════════════════════════
✅ QUALITY SCORING COMPLETE

Total samples:    {total}
Kept (≥{MIN_SCORE}):       {total_kept} ({keep_rate:.1f}%)
Rejected (<{MIN_SCORE}):   {total_rejected}

Quality-filtered samples saved to: data/datasets/*/quality_filtered.jsonl
Rejected samples saved to: retrain/rejected/

Next steps:
  1. Review rejected samples (optional): retrain/rejected/
  2. Combine datasets: python ../curate_dataset.py (option 2)
  3. Fine-tune: python ../finetune_v2.py
═══════════════════════════════════════════════════════════════
""")


if __name__ == "__main__":
    main()
