import json
import os
from typing import List, Dict, Any
from colorama import Fore, Style, init

from secretscanner.scanner import Finding
from secretscanner.detectors import DETECTORS
from secretscanner.allowlist import get_relative_path

# Initialize colorama
init(autoreset=True)

def map_severity_color(severity: str, use_color: bool) -> str:
    if not use_color:
        return ""
    sev = severity.lower()
    if sev == "critical":
        return Fore.RED + Style.BRIGHT
    elif sev == "high":
        return Fore.RED
    elif sev == "medium":
        return Fore.YELLOW
    elif sev == "low":
        return Fore.CYAN
    return ""

def map_confidence_color(confidence: str, use_color: bool) -> str:
    if not use_color:
        return ""
    conf = confidence.lower()
    if conf == "confirmed":
        return Fore.GREEN + Style.BRIGHT
    elif conf == "likely":
        return Fore.GREEN
    elif conf == "possible":
        return Fore.BLUE
    return ""

def to_text(findings: List[Finding], repo_root: str, use_color: bool = True) -> str:
    """Renders findings to ANSI colorized (or plain) text format grouped by severity."""
    if not findings:
        return "No secrets detected."

    # Group by severity: critical, high, medium, low
    severity_order = ["critical", "high", "medium", "low"]
    grouped: Dict[str, List[Finding]] = {sev: [] for sev in severity_order}
    
    for f in findings:
        sev = f.severity.lower()
        if sev not in grouped:
            grouped[sev] = []
        grouped[sev].append(f)
        
    lines = []
    
    for sev in severity_order:
        sev_findings = grouped[sev]
        if not sev_findings:
            continue
            
        sev_color = map_severity_color(sev, use_color)
        reset = Style.RESET_ALL if use_color else ""
        bold = Style.BRIGHT if use_color else ""
        
        lines.append(f"{sev_color}=== {sev.upper()} SEVERITY FINDINGS ({len(sev_findings)}) ==={reset}\n")
        
        for f in sev_findings:
            conf_color = map_confidence_color(f.confidence, use_color)
            rel_path = get_relative_path(f.file_path, repo_root)
            
            commit_info = f" [Commit: {f.commit_hash[:8]}]" if f.commit_hash else ""
            header = f"{bold}{f.detector_name}{reset} (Confidence: {conf_color}{f.confidence}{reset}){commit_info}"
            lines.append(header)
            
            lines.append(f"  File:     {rel_path}:{f.line_number}")
            lines.append(f"  Value:    {f.redacted_value}")
            lines.append(f"  Preview:  {f.line_content}")
            lines.append("  Reasons:")
            for reason in f.reasons:
                lines.append(f"    - {reason}")
            lines.append("") # empty line spacing
            
    return "\n".join(lines)

def to_json(findings: List[Finding]) -> str:
    """Serializes findings directly into JSON string format."""
    return json.dumps([f.to_dict() for f in findings], indent=2)

def to_sarif(findings: List[Finding], repo_root: str) -> str:
    """Generates valid SARIF 2.1.0 report for upload to GitHub scanning alerts."""
    # Map detector details to rules list
    rules_dict = {}
    
    # Pre-populate rules from DETECTORS
    for d in DETECTORS:
        rules_dict[d.id] = {
            "id": d.id,
            "shortDescription": {"text": d.name},
            "fullDescription": {"text": d.description},
            "defaultConfiguration": {
                "level": "error" if d.severity in ("critical", "high") else (
                    "warning" if d.severity == "medium" else "note"
                )
            }
        }
        
    # Include an explicit rule for entropy detector
    if "entropy" not in rules_dict:
        rules_dict["entropy"] = {
            "id": "entropy",
            "shortDescription": {"text": "High Entropy Candidate"},
            "fullDescription": {"text": "Shannon entropy scoring candidate matching high-randomness patterns."},
            "defaultConfiguration": {"level": "warning"}
        }
        
    rules_list = list(rules_dict.values())
    
    results = []
    for f in findings:
        rel_path = get_relative_path(f.file_path, repo_root)
        
        # Severity mappings: critical/high -> error, medium -> warning, low -> note
        level = "error" if f.severity in ("critical", "high") else (
            "warning" if f.severity == "medium" else "note"
        )
        
        result_item = {
            "ruleId": f.detector_id,
            "level": level,
            "message": {
                "text": f"Potential leak of {f.detector_name} (Confidence: {f.confidence})."
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": rel_path
                        },
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": 1
                        }
                    }
                }
            ],
            "properties": {
                "confidence": f.confidence,
                "reasons": f.reasons,
                "redacted_value": f.redacted_value
            }
        }
        
        if f.commit_hash:
            result_item["properties"]["commit_hash"] = f.commit_hash
            
        results.append(result_item)
        
    sarif_data = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secretscanner",
                        "version": "0.1.0",
                        "rules": rules_list
                    }
                },
                "results": results
            }
        ]
    }
    
    return json.dumps(sarif_data, indent=2)
