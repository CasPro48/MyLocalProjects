#!/usr/bin/env python3
"""
Bombina Data Pipeline Orchestrator
Runs the complete data collection and processing pipeline

Usage: python pipeline.py [command]

Commands:
  mitre     - Extract from MITRE ATT&CK
  generate  - Generate from raw writeups
  score     - Score and filter all datasets
  all       - Run complete pipeline
  stats     - Show dataset statistics
"""

import sys
import subprocess
from pathlib import Path
from datetime import datetime

# Paths
BASE_DIR = Path(__file__).parent.parent.parent
PIPELINE_DIR = Path(__file__).parent
DATASETS_DIR = BASE_DIR / "data" / "datasets"


def run_script(script_name: str, args: list = None) -> bool:
    """Run a pipeline script."""
    script_path = PIPELINE_DIR / script_name
    
    if not script_path.exists():
        print(f"❌ Script not found: {script_path}")
        return False
    
    cmd = [sys.executable, str(script_path)]
    if args:
        cmd.extend(args)
    
    result = subprocess.run(cmd)
    return result.returncode == 0


def count_samples() -> dict:
    """Count samples in each category."""
    counts = {}
    total = 0
    
    for category_dir in DATASETS_DIR.iterdir():
        if not category_dir.is_dir():
            continue
        
        count = 0
        for jsonl_file in category_dir.glob("*.jsonl"):
            with open(jsonl_file, 'r') as f:
                count += sum(1 for _ in f)
        
        counts[category_dir.name] = count
        total += count
    
    counts["_total"] = total
    return counts


def show_stats():
    """Display dataset statistics."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA DATASET STATISTICS
═══════════════════════════════════════════════════════════════════
""")
    
    counts = count_samples()
    total = counts.pop("_total", 0)
    
    print("📊 Samples by category:\n")
    
    # Sort by count
    for category, count in sorted(counts.items(), key=lambda x: -x[1]):
        bar = "█" * min(count // 5, 30)
        print(f"  {category:25s} {count:5d}  {bar}")
    
    print(f"\n{'─' * 50}")
    print(f"  {'TOTAL':25s} {total:5d}")
    
    # Quality assessment
    print("\n📈 Quality Assessment:")
    if total < 500:
        print(f"  ⚠️  Below minimum (500). Need {500 - total} more samples.")
    elif total < 1500:
        print(f"  📝 Getting there. First usable model at 1,500 samples.")
    elif total < 3000:
        print(f"  ✅ Minimum viable dataset. Consider adding more for strength.")
    elif total < 5000:
        print(f"  💪 Strong dataset. Good for fine-tuning.")
    else:
        print(f"  🏆 Excellent dataset size!")
    
    # Target breakdown
    target = 500
    print(f"\n🎯 Target ({target} samples):")
    
    ideal = {
        "initial_access": 80,
        "privilege_escalation": 80,
        "lateral_movement": 80,
        "evasion": 80,
        "persistence": 40,
        "failure_analysis": 80,
        "blue_team": 60,
    }
    
    for category, target_count in ideal.items():
        current = counts.get(category, 0)
        status = "✅" if current >= target_count else "❌"
        diff = current - target_count
        diff_str = f"+{diff}" if diff >= 0 else str(diff)
        print(f"  {status} {category:25s} {current:3d}/{target_count:3d} ({diff_str})")


def run_pipeline_all():
    """Run complete pipeline."""
    print("""
🐸 ═══════════════════════════════════════════════════════════════
   BOMBINA COMPLETE PIPELINE
   Running all data collection and processing
═══════════════════════════════════════════════════════════════════
""")
    
    start_time = datetime.now()
    
    # Step 1: MITRE extraction
    print("\n" + "=" * 60)
    print("STEP 1: MITRE ATT&CK Extraction")
    print("=" * 60)
    
    if not run_script("extract_mitre.py"):
        print("⚠️ MITRE extraction had issues, continuing...")
    
    # Step 2: Quality scoring
    print("\n" + "=" * 60)
    print("STEP 2: Quality Scoring")
    print("=" * 60)
    
    if not run_script("quality_scorer.py"):
        print("⚠️ Quality scoring had issues, continuing...")
    
    # Step 3: Show stats
    print("\n" + "=" * 60)
    print("STEP 3: Final Statistics")
    print("=" * 60)
    
    show_stats()
    
    # Duration
    duration = datetime.now() - start_time
    print(f"\n⏱️ Pipeline completed in {duration.seconds} seconds")
    
    print("""
═══════════════════════════════════════════════════════════════
✅ PIPELINE COMPLETE

Next steps:
  1. Add more raw writeups to data/raw/ and run:
     python pipeline.py generate
  
  2. Combine all datasets:
     python scripts/curate_dataset.py (option 2)
  
  3. Fine-tune when you have 500+ samples:
     python scripts/finetune_v2.py
═══════════════════════════════════════════════════════════════
""")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print(__doc__)
        print("\nCurrent stats:")
        show_stats()
        return
    
    command = sys.argv[1].lower()
    
    if command == "mitre":
        run_script("extract_mitre.py")
    
    elif command == "generate":
        args = sys.argv[2:] if len(sys.argv) > 2 else None
        run_script("generate_training.py", args)
    
    elif command == "score":
        run_script("quality_scorer.py")
    
    elif command == "all":
        run_pipeline_all()
    
    elif command == "stats":
        show_stats()
    
    else:
        print(f"Unknown command: {command}")
        print(__doc__)


if __name__ == "__main__":
    main()
