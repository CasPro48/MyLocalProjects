#!/usr/bin/env python3
"""
Bombina Dataset Quality Audit Tool
Analyzes and scores training samples for quality
Identifies weak samples that should be improved or removed
"""

import json
import re
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple
from collections import Counter
from datetime import datetime

@dataclass
class QualityScore:
    sample_id: str
    total_score: float
    reasoning_depth: int
    detection_awareness: int
    trade_off_analysis: int
    actionability: int
    length_score: int
    issues: List[str]
    grade: str

class DatasetAuditor:
    """Audit dataset quality and identify weak samples"""
    
    # Keywords indicating good reasoning
    REASONING_KEYWORDS = [
        "because", "therefore", "however", "alternatively", "instead",
        "risk", "trade-off", "detection", "stealth", "consider",
        "if", "when", "depending", "prioritize", "avoid", "prefer",
        "likelihood", "impact", "mitigation", "constraint", "limitation"
    ]
    
    # Keywords indicating detection awareness
    DETECTION_KEYWORDS = [
        "edr", "siem", "alert", "log", "monitor", "detect", "trigger",
        "noise", "stealth", "opsec", "signature", "behavioral", "anomaly",
        "crowdstrike", "defender", "sentinel", "splunk", "elastic"
    ]
    
    # Red flags - samples that just list commands
    COMMAND_ONLY_PATTERNS = [
        r"^run\s+\w+$",
        r"^use\s+\w+$",
        r"^nmap\s+-",
        r"^msfconsole",
        r"^sudo\s+",
        r"^\$\s*\w+",
        r"^#\s*\w+\s*$"
    ]
    
    # Keywords indicating shallow/bad samples
    SHALLOW_INDICATORS = [
        "just run", "simply use", "execute the command", "type this",
        "copy paste", "easy", "simple", "just do"
    ]
    
    def __init__(self, dataset_path: str):
        self.dataset_path = Path(dataset_path)
        self.samples = []
        self.scores = []
        self.load_dataset()
    
    def load_dataset(self):
        """Load all samples from dataset"""
        if self.dataset_path.is_file():
            with open(self.dataset_path) as f:
                for i, line in enumerate(f):
                    sample = json.loads(line)
                    sample['_id'] = f"sample_{i}"
                    self.samples.append(sample)
        elif self.dataset_path.is_dir():
            for jsonl_file in self.dataset_path.glob("*.jsonl"):
                with open(jsonl_file) as f:
                    for i, line in enumerate(f):
                        sample = json.loads(line)
                        sample['_id'] = f"{jsonl_file.stem}_{i}"
                        self.samples.append(sample)
        
        print(f"Loaded {len(self.samples)} samples")
    
    def score_sample(self, sample: Dict) -> QualityScore:
        """Score a single sample for quality"""
        output = sample.get('output', '').lower()
        instruction = sample.get('instruction', '').lower()
        input_text = sample.get('input', '').lower()
        full_text = f"{instruction} {input_text} {output}"
        
        issues = []
        
        # 1. Reasoning Depth (0-25)
        reasoning_count = sum(1 for kw in self.REASONING_KEYWORDS if kw in output)
        reasoning_depth = min(25, reasoning_count * 3)
        
        if reasoning_count < 2:
            issues.append("Low reasoning depth - lacks explanation of why")
        
        # 2. Detection Awareness (0-25)
        detection_count = sum(1 for kw in self.DETECTION_KEYWORDS if kw in full_text)
        detection_awareness = min(25, detection_count * 5)
        
        if detection_count == 0:
            issues.append("No detection awareness - should mention risks")
        
        # 3. Trade-off Analysis (0-25)
        trade_off_indicators = [
            "vs", "versus", "trade-off", "tradeoff", "balance",
            "pro", "con", "advantage", "disadvantage", "but",
            "however", "although", "while", "whereas"
        ]
        trade_off_count = sum(1 for kw in trade_off_indicators if kw in output)
        trade_off_analysis = min(25, trade_off_count * 5)
        
        if trade_off_count < 2:
            issues.append("Missing trade-off analysis")
        
        # 4. Actionability (0-15)
        actionability = 0
        if any(word in output for word in ["step", "first", "then", "next", "1.", "2."]):
            actionability += 8
        if any(word in output for word in ["command", "tool", "technique", "method"]):
            actionability += 7
        
        # 5. Length Score (0-10)
        output_length = len(output)
        if output_length < 100:
            length_score = 2
            issues.append("Output too short - lacks detail")
        elif output_length < 200:
            length_score = 5
        elif output_length < 500:
            length_score = 8
        else:
            length_score = 10
        
        # Check for red flags
        for pattern in self.COMMAND_ONLY_PATTERNS:
            if re.match(pattern, output.strip(), re.IGNORECASE):
                issues.append("CRITICAL: Command-only output - teaches nothing")
                reasoning_depth = 0
                break
        
        for indicator in self.SHALLOW_INDICATORS:
            if indicator in output:
                issues.append(f"Shallow language detected: '{indicator}'")
                reasoning_depth = max(0, reasoning_depth - 5)
        
        # Calculate total
        total_score = reasoning_depth + detection_awareness + trade_off_analysis + actionability + length_score
        
        # Determine grade
        if total_score >= 80:
            grade = "A"
        elif total_score >= 65:
            grade = "B"
        elif total_score >= 50:
            grade = "C"
        elif total_score >= 35:
            grade = "D"
        else:
            grade = "F"
        
        return QualityScore(
            sample_id=sample.get('_id', 'unknown'),
            total_score=total_score,
            reasoning_depth=reasoning_depth,
            detection_awareness=detection_awareness,
            trade_off_analysis=trade_off_analysis,
            actionability=actionability,
            length_score=length_score,
            issues=issues,
            grade=grade
        )
    
    def audit_all(self) -> Dict:
        """Audit entire dataset"""
        print("\nAuditing dataset quality...")
        print("="*60)
        
        self.scores = []
        grade_counts = Counter()
        all_issues = Counter()
        
        for sample in self.samples:
            score = self.score_sample(sample)
            self.scores.append((sample, score))
            grade_counts[score.grade] += 1
            for issue in score.issues:
                all_issues[issue] += 1
        
        # Sort by score (worst first for review)
        self.scores.sort(key=lambda x: x[1].total_score)
        
        # Calculate statistics
        total_samples = len(self.scores)
        avg_score = sum(s[1].total_score for s in self.scores) / total_samples
        
        # Identify samples to review
        critical_samples = [s for s in self.scores if s[1].grade == "F"]
        weak_samples = [s for s in self.scores if s[1].grade == "D"]
        good_samples = [s for s in self.scores if s[1].grade in ["A", "B"]]
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "total_samples": total_samples,
            "average_score": round(avg_score, 2),
            "grade_distribution": dict(grade_counts),
            "common_issues": dict(all_issues.most_common(10)),
            "critical_count": len(critical_samples),
            "weak_count": len(weak_samples),
            "good_count": len(good_samples),
            "quality_percentage": round(len(good_samples) / total_samples * 100, 1)
        }
        
        return results
    
    def export_for_review(self, output_dir: str, max_samples: int = 100):
        """Export worst samples for human review"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Export critical samples (grade F)
        critical_file = output_path / "critical_review.jsonl"
        critical_samples = [s for s in self.scores if s[1].grade == "F"][:max_samples]
        
        with open(critical_file, "w") as f:
            for sample, score in critical_samples:
                review_item = {
                    "sample": sample,
                    "score": score.total_score,
                    "grade": score.grade,
                    "issues": score.issues,
                    "action": "REMOVE or REWRITE"
                }
                f.write(json.dumps(review_item) + "\n")
        
        # Export weak samples (grade D)
        weak_file = output_path / "weak_review.jsonl"
        weak_samples = [s for s in self.scores if s[1].grade == "D"][:max_samples]
        
        with open(weak_file, "w") as f:
            for sample, score in weak_samples:
                review_item = {
                    "sample": sample,
                    "score": score.total_score,
                    "grade": score.grade,
                    "issues": score.issues,
                    "action": "IMPROVE"
                }
                f.write(json.dumps(review_item) + "\n")
        
        # Export good samples as examples
        good_file = output_path / "good_examples.jsonl"
        good_samples = [s for s in self.scores if s[1].grade == "A"][:50]
        
        with open(good_file, "w") as f:
            for sample, score in good_samples:
                f.write(json.dumps(sample) + "\n")
        
        print(f"\nExported for review:")
        print(f"  - Critical (F): {len(critical_samples)} samples → {critical_file}")
        print(f"  - Weak (D): {len(weak_samples)} samples → {weak_file}")
        print(f"  - Good (A): {len(good_samples)} examples → {good_file}")
    
    def filter_dataset(self, min_grade: str = "C") -> Tuple[List[Dict], List[Dict]]:
        """Filter dataset, returning (kept, removed) samples"""
        grade_order = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
        min_grade_value = grade_order.get(min_grade, 3)
        
        kept = []
        removed = []
        
        for sample, score in self.scores:
            if grade_order.get(score.grade, 0) >= min_grade_value:
                kept.append(sample)
            else:
                removed.append(sample)
        
        return kept, removed
    
    def save_filtered_dataset(self, output_path: str, min_grade: str = "C"):
        """Save filtered dataset with only quality samples"""
        kept, removed = self.filter_dataset(min_grade)
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            for sample in kept:
                # Remove internal ID before saving
                clean_sample = {k: v for k, v in sample.items() if not k.startswith('_')}
                f.write(json.dumps(clean_sample) + "\n")
        
        print(f"\n✅ Filtered dataset saved: {output_file}")
        print(f"   Kept: {len(kept)} samples (grade {min_grade} or better)")
        print(f"   Removed: {len(removed)} samples")
        
        return len(kept), len(removed)


def main():
    """Run audit on Bombina dataset"""
    base_dir = Path("/home/redbend/MyLocalProjects/Bombina/scripts/data")
    
    # Audit main training dataset
    train_file = base_dir / "final" / "train.jsonl"
    
    if not train_file.exists():
        print(f"Dataset not found: {train_file}")
        return
    
    auditor = DatasetAuditor(str(train_file))
    results = auditor.audit_all()
    
    # Print results
    print("\n" + "="*60)
    print("📊 DATASET QUALITY AUDIT RESULTS")
    print("="*60)
    print(f"Total samples: {results['total_samples']}")
    print(f"Average score: {results['average_score']}/100")
    print(f"Quality rate: {results['quality_percentage']}% (A+B grades)")
    
    print("\n📈 Grade Distribution:")
    for grade in ["A", "B", "C", "D", "F"]:
        count = results['grade_distribution'].get(grade, 0)
        pct = count / results['total_samples'] * 100
        bar = "█" * int(pct / 2)
        print(f"  {grade}: {count:5d} ({pct:5.1f}%) {bar}")
    
    print("\n⚠️ Common Issues:")
    for issue, count in results['common_issues'].items():
        print(f"  - {issue}: {count}")
    
    # Export for review
    review_dir = base_dir / "audit_review"
    auditor.export_for_review(str(review_dir))
    
    # Save filtered dataset (optional)
    print("\n" + "="*60)
    print("💾 FILTERED DATASET OPTIONS")
    print("="*60)
    print("To create a filtered dataset with only quality samples:")
    print("  auditor.save_filtered_dataset('path/to/filtered.jsonl', min_grade='C')")
    
    # Save audit report
    report_file = review_dir / "audit_report.json"
    with open(report_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n📄 Full report saved: {report_file}")


if __name__ == "__main__":
    main()
