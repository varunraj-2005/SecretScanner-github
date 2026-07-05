import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

from secretscanner.detectors import DETECTORS, Detector
from secretscanner.entropy import extract_candidates
from secretscanner.context import assess_hit

@dataclass
class Finding:
    detector_id: str
    detector_name: str
    severity: str
    confidence: str
    reasons: List[str]
    file_path: str
    line_number: int
    secret_value: str
    redacted_value: str
    line_content: str
    commit_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector_id": self.detector_id,
            "detector_name": self.detector_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "redacted_value": self.redacted_value,
            "line_content": self.line_content,
            "commit_hash": self.commit_hash
        }

def redact_secret(secret: str) -> str:
    """Redacts the middle portion of a secret for safe printing."""
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}****...****{secret[-4:]}"

def is_binary_file(file_path: str) -> bool:
    """Checks if a file is binary by looking for null bytes in its first block."""
    try:
        if not os.path.exists(file_path):
            return False
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\x00" in chunk
    except Exception:
        return True

def should_skip_path(path: str) -> bool:
    """Checks if a file path should be ignored based on common patterns."""
    # Normalize separators
    norm_path = path.replace("\\", "/").lower()
    parts = norm_path.split("/")
    
    ignore_dirs = {
        ".git", "node_modules", "vendor", "build", "dist", "target", "out", 
        ".venv", "venv", "env", "egg-info", "__pycache__", ".pytest_cache"
    }
    
    # Skip if any path segment matches ignore_dirs
    if any(p in ignore_dirs for p in parts):
        return True
        
    # Ignore typical binary extensions or design assets
    ignore_exts = {
        ".pyc", ".pyo", ".pyd", ".exe", ".dll", ".so", ".dylib", ".bin", ".tar", ".gz",
        ".zip", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".woff", ".woff2", ".eot", ".ttf",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".db", ".sqlite", ".iso", ".dmg", ".ico"
    }
    _, ext = os.path.splitext(norm_path)
    if ext in ignore_exts:
        return True
        
    # Ignore baseline files
    filename = parts[-1] if parts else ""
    if filename == ".secretscanner-baseline.json" or filename.endswith("baseline.json"):
        return True
        
    return False

def scan_line(line: str, line_num: int, file_path: str, repo_root: str) -> List[Finding]:
    """Scans a single line with detectors and entropy checks."""
    findings = []
    structural_fired = False
    
    # 1. Structural Detectors (excluding generic-assignment first)
    for detector in DETECTORS:
        if detector.id == "generic-assignment":
            continue
            
        matches = list(detector.pattern.finditer(line))
        for match in matches:
            secret_val = match.group(1) if match.groups() else match.group(0)
            
            # Assess context/confidence
            confidence, reasons = assess_hit(secret_val, line, file_path, detector.id)
            if confidence == "suppressed":
                continue
                
            redacted = redact_secret(secret_val)
            findings.append(Finding(
                detector_id=detector.id,
                detector_name=detector.name,
                severity=detector.severity,
                confidence=confidence,
                reasons=reasons,
                file_path=file_path,
                line_number=line_num,
                secret_value=secret_val,
                redacted_value=redacted,
                line_content=line.strip()
            ))
            structural_fired = True
            
    # 2. If no structural detector fired, run Generic Assignment and Entropy checks
    if not structural_fired:
        generic_detector = next(d for d in DETECTORS if d.id == "generic-assignment")
        generic_matches = list(generic_detector.pattern.finditer(line))
        generic_fired = False
        
        for match in generic_matches:
            secret_val = match.group(1) if match.groups() else match.group(0)
            confidence, reasons = assess_hit(secret_val, line, file_path, generic_detector.id)
            if confidence == "suppressed":
                continue
                
            redacted = redact_secret(secret_val)
            findings.append(Finding(
                detector_id=generic_detector.id,
                detector_name=generic_detector.name,
                severity=generic_detector.severity,
                confidence=confidence,
                reasons=reasons,
                file_path=file_path,
                line_number=line_num,
                secret_value=secret_val,
                redacted_value=redacted,
                line_content=line.strip()
            ))
            generic_fired = True
            
        # Entropy check
        candidates = extract_candidates(line)
        for candidate, score, tok_type in candidates:
            # Avoid reporting candidate if it's already caught in generic/structural findings
            if any(candidate in f.secret_value for f in findings):
                continue
                
            confidence, reasons = assess_hit(candidate, line, file_path, "entropy")
            if confidence == "suppressed":
                continue
                
            redacted = redact_secret(candidate)
            findings.append(Finding(
                detector_id="entropy",
                detector_name=f"High Entropy String ({tok_type.upper()})",
                severity="medium" if tok_type == "hex" else "high",
                confidence=confidence,
                reasons=reasons + [f"Shannon entropy: {score:.2f}"],
                file_path=file_path,
                line_number=line_num,
                secret_value=candidate,
                redacted_value=redacted,
                line_content=line.strip()
            ))
            
    return findings

def scan_working_tree(repo_root: str) -> List[Finding]:
    """Walks the working tree and scans matching files."""
    all_findings = []
    
    for root, dirs, files in os.walk(repo_root):
        # Modify dirs in-place to skip ignored folders
        dirs[:] = [d for d in dirs if not should_skip_path(os.path.join(root, d))]
        
        for file in files:
            file_path = os.path.join(root, file)
            if should_skip_path(file_path):
                continue
                
            # Skip if file size is > 5MB
            try:
                if os.path.getsize(file_path) > 5242880:
                    continue
            except OSError:
                continue
                
            # Skip binary files
            if is_binary_file(file_path):
                continue
                
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line_num, line in enumerate(f, 1):
                        findings = scan_line(line, line_num, file_path, repo_root)
                        all_findings.extend(findings)
            except Exception:
                continue
                
    return all_findings

def scan_git_history(repo_root: str, max_commits: Optional[int] = None) -> List[Finding]:
    """Scans added lines in git history commits."""
    all_findings = []
    
    # 1. Get commit hashes
    cmd_log = ["git", "log", "--all", "--format=%H"]
    if max_commits is not None:
        cmd_log.append(f"-n {max_commits}")
        
    try:
        result = subprocess.run(
            cmd_log,
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True
        )
        commits = [c.strip() for c in result.stdout.strip().split("\n") if c.strip()]
    except Exception as e:
        # Not a git repo or git not available
        print(f"Warning: Failed to fetch git history. Is it a git repository? Error: {e}")
        return []
        
    # Chunk header regex matching: @@ -start,len +start,len @@
    chunk_header_pattern = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@")
    
    for commit in commits:
        # Run git show per commit to scan diffs
        cmd_show = ["git", "show", "--unified=0", "--no-prefix", commit]
        try:
            res_show = subprocess.run(
                cmd_show,
                cwd=repo_root,
                capture_output=True,
                text=True,
                check=True
            )
            diff_output = res_show.stdout
        except Exception:
            continue
            
        current_file = ""
        skip_current_file = False
        current_line_num = 0
        
        for line in diff_output.splitlines():
            # Parse diff header to extract file path
            if line.startswith("+++ "):
                # Skip header indicator line '+++ b/path/to/file'
                # (since we passed --no-prefix, it's just '+++ path/to/file')
                path_candidate = line[4:].strip()
                if path_candidate == "/dev/null":
                    current_file = ""
                    skip_current_file = True
                else:
                    current_file = path_candidate
                    skip_current_file = should_skip_path(current_file)
                continue
            
            if skip_current_file or not current_file:
                continue
                
            # Parse chunk header
            if line.startswith("@@"):
                match = chunk_header_pattern.match(line)
                if match:
                    current_line_num = int(match.group(1))
                continue
                
            # Parse added lines
            if line.startswith("+") and not line.startswith("+++"):
                added_line_content = line[1:]
                
                # Scan the line
                # Note: file_path passed to scan_line is absolute path
                abs_file_path = os.path.join(repo_root, current_file)
                findings = scan_line(added_line_content, current_line_num, abs_file_path, repo_root)
                
                for f in findings:
                    f.commit_hash = commit
                    all_findings.append(f)
                    
                current_line_num += 1
                
    return all_findings
