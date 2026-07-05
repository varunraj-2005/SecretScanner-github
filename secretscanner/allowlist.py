import hashlib
import json
import os
from typing import Dict, Any, List

def compute_hash(value: str) -> str:
    """Computes the SHA-256 hash of a string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def get_relative_path(file_path: str, repo_root: str) -> str:
    """Converts an absolute file path to a relative path from the repository root."""
    try:
        # Standardize separators
        abs_path = os.path.abspath(file_path)
        root_path = os.path.abspath(repo_root)
        rel = os.path.relpath(abs_path, root_path)
        return rel.replace("\\", "/")
    except Exception:
        return file_path.replace("\\", "/")

def load_baseline(baseline_path: str) -> Dict[str, Any]:
    """Loads the baseline dictionary from a JSON file. Returns an empty dict if the file doesn't exist."""
    if not baseline_path or not os.path.exists(baseline_path):
        return {}
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Ensure it has the correct layout
            return data.get("baseline", {})
    except Exception:
        # Return empty dict if corrupt or unreadable
        return {}

def is_allowlisted(
    secret_value: str,
    file_path: str,
    line_number: int,
    repo_root: str,
    baseline: Dict[str, Any]
) -> bool:
    """
    Checks if a finding is already present in the baseline.
    The key is sha256(secret_value):relative_file_path:line_number.
    """
    rel_path = get_relative_path(file_path, repo_root)
    sec_hash = compute_hash(secret_value)
    key = f"{sec_hash}:{rel_path}:{line_number}"
    return key in baseline

def save_baseline(
    baseline_path: str,
    findings: List[Dict[str, Any]],
    repo_root: str
) -> None:
    """
    Saves new findings to the baseline file without storing the plaintext secrets.
    """
    # Load existing baseline first so we merge instead of completely blowing away
    existing_baseline = load_baseline(baseline_path)
    
    for f in findings:
        secret_val = f.get("secret_value", "")
        file_path = f.get("file_path", "")
        line_num = f.get("line_number", 0)
        detector_id = f.get("detector_id", "")
        
        rel_path = get_relative_path(file_path, repo_root)
        sec_hash = compute_hash(secret_val)
        key = f"{sec_hash}:{rel_path}:{line_num}"
        
        existing_baseline[key] = {
            "detector_id": detector_id,
            "file_path": rel_path,
            "line_number": line_num
        }
        
    try:
        with open(baseline_path, "w", encoding="utf-8") as f:
            json.dump({"baseline": existing_baseline}, f, indent=2)
    except Exception as e:
        print(f"Error saving baseline to {baseline_path}: {e}")
