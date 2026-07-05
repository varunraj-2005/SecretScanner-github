import argparse
import os
import sys
from typing import List

from secretscanner.scanner import scan_working_tree, scan_git_history, Finding
from secretscanner.allowlist import load_baseline, save_baseline, is_allowlisted
from secretscanner.report import to_text, to_json, to_sarif

# Severity/confidence hierarchy for easy filtering
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]
CONFIDENCE_LEVELS = ["possible", "likely", "confirmed"]

def filter_findings(
    findings: List[Finding],
    min_severity: str,
    min_confidence: str,
    baseline: dict,
    repo_root: str,
    skip_baseline_filter: bool = False
) -> List[Finding]:
    """Filters findings based on severity, confidence, and baseline exclusions."""
    filtered = []
    
    min_sev_idx = SEVERITY_LEVELS.index(min_severity.lower())
    min_conf_idx = CONFIDENCE_LEVELS.index(min_confidence.lower())
    
    for f in findings:
        # 1. Filter by severity
        sev_idx = SEVERITY_LEVELS.index(f.severity.lower())
        if sev_idx < min_sev_idx:
            continue
            
        # 2. Filter by confidence
        conf_idx = CONFIDENCE_LEVELS.index(f.confidence.lower())
        if conf_idx < min_conf_idx:
            continue
            
        # 3. Filter by baseline if applicable
        if not skip_baseline_filter and baseline:
            if is_allowlisted(f.secret_value, f.file_path, f.line_number, repo_root, baseline):
                continue
                
        filtered.append(f)
        
    return filtered

def main():
    parser = argparse.ArgumentParser(
        description="secretscanner: Scan codebases and git history for leaked credentials, private keys, and tokens."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan (directory or single file). Defaults to current directory."
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Scan all git commits in history in addition to the working tree."
    )
    parser.add_argument(
        "--history-only",
        action="store_true",
        help="Scan git commits only (skip the working tree scan)."
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="Maximum number of commits to scan in git history."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Format for outputting scan results (default: text)."
    )
    parser.add_argument(
        "-o",
        "--output",
        help="File path to write output results to. Prints to stdout if not specified."
    )
    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_LEVELS,
        default="low",
        help="Minimum severity level to report (default: low)."
    )
    parser.add_argument(
        "--min-confidence",
        choices=CONFIDENCE_LEVELS,
        default="possible",
        help="Minimum confidence level to report (default: possible)."
    )
    parser.add_argument(
        "--baseline",
        help="Path to baseline file containing previously flagged and ignored secrets."
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Generate or update a baseline file with all current secrets found (skips reporting)."
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console text output."
    )
    parser.add_argument(
        "--fail-on",
        choices=["any", "confirmed", "never"],
        default="never",
        help="Policy to fail with exit code 1. 'any': any finding; 'confirmed': confirmed finding; 'never': exit code 0."
    )
    
    args = parser.parse_args()
    
    # Resolve scan path and repo root
    target_path = os.path.abspath(args.path)
    if os.path.isdir(target_path):
        repo_root = target_path
    else:
        repo_root = os.path.dirname(target_path)
        if not repo_root:
            repo_root = os.getcwd()
            
    # Perform scan
    findings = []
    
    # Determine baseline path
    baseline_file = args.baseline
    update_baseline = args.update_baseline
    
    # Define baseline default path if update requested but not path specified
    if not baseline_file:
        baseline_file = os.path.join(repo_root, ".secretscanner-baseline.json")
        
    # Load baseline if scanning (and NOT updating baseline)
    baseline = {}
    if not update_baseline and args.baseline:
        baseline = load_baseline(args.baseline)
    elif not update_baseline and os.path.exists(baseline_file):
        # Auto-load baseline if default file exists
        baseline = load_baseline(baseline_file)
        
    # Execute working tree scan
    if not args.history_only:
        findings.extend(scan_working_tree(target_path))
        
    # Execute git history scan
    if args.history or args.history_only:
        findings.extend(scan_git_history(repo_root, max_commits=args.max_commits))
        
    # If update baseline requested, write out baseline and terminate
    if update_baseline:
        # Convert findings to dictionary for allowlist module
        finding_dicts = []
        for f in findings:
            finding_dicts.append({
                "secret_value": f.secret_value,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "detector_id": f.detector_id
            })
        save_baseline(baseline_file, finding_dicts, repo_root)
        print(f"Baseline updated successfully. Saved to {baseline_file}")
        sys.exit(0)
        
    # Filter findings
    filtered_findings = filter_findings(
        findings=findings,
        min_severity=args.min_severity,
        min_confidence=args.min_confidence,
        baseline=baseline,
        repo_root=repo_root
    )
    
    # Render report
    if args.format == "json":
        report_out = to_json(filtered_findings)
    elif args.format == "sarif":
        report_out = to_sarif(filtered_findings, repo_root)
    else:
        # Text output (colorized unless --no-color or writing to file)
        use_color = not args.no_color and not args.output
        report_out = to_text(filtered_findings, repo_root, use_color=use_color)
        
    # Write to output file or print
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report_out)
                if args.format == "text":
                    f.write("\n")
            print(f"Results written to {args.output}")
        except Exception as e:
            print(f"Error writing to output file {args.output}: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(report_out)
        
    # Apply exit code policy for CI gating
    if filtered_findings:
        if args.fail_on == "any":
            sys.exit(1)
        elif args.fail_on == "confirmed":
            if any(f.confidence == "confirmed" for f in filtered_findings):
                sys.exit(1)
                
    sys.exit(0)

if __name__ == "__main__":
    main()
