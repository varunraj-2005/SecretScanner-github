import math
import re
from typing import List, Tuple

# Base64 / urlsafe run: letters, digits, _, -, +, =, /
BASE64_RUN_PATTERN = re.compile(r"[A-Za-z0-9_\-\+=/]+")

def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon entropy of a string.
    Formula: -sum(p(c) * log2(p(c)))
    """
    if not text:
        return 0.0
    length = len(text)
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_hex(text: str) -> bool:
    """Returns True if the text contains only hex characters."""
    return all(c in "0123456789abcdefABCDEF" for c in text)

def extract_candidates(line: str) -> List[Tuple[str, float, str]]:
    """
    Extracts high-entropy candidate tokens from a line.
    Returns a list of tuples: (candidate_string, entropy_score, token_type)
    where token_type is either 'hex' or 'base64'.
    """
    candidates = []
    # Find all contiguous blocks matching base64 characters
    runs = BASE64_RUN_PATTERN.findall(line)
    
    for run in runs:
        # Strip outer punctuation if matched by accident (e.g. at start or end of string)
        # to ensure we don't inflate entropy with quote marks, etc.
        run_clean = run.strip("'\"=+,/-_")
        
        run_len = len(run_clean)
        if run_len < 20:
            continue
            
        entropy = calculate_entropy(run_clean)
        
        if is_hex(run_clean):
            # Hex runs must be at least 32 characters and clear 3.0 entropy
            if run_len >= 32 and entropy >= 3.0:
                candidates.append((run_clean, entropy, "hex"))
        else:
            # Base64/urlsafe runs must be at least 20 characters and clear 4.3 entropy
            if run_len >= 20 and entropy >= 4.3:
                candidates.append((run_clean, entropy, "base64"))
                
    return candidates
