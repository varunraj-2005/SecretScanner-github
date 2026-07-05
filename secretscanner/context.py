import re
from typing import List, Tuple

# Placeholder regex patterns
PLACEHOLDER_SUBSTRINGS = ["test", "dummy", "fake", "changeme", "your-api-key-here", "placeholder", "example"]
REPEATED_CHARS_PATTERN = re.compile(r"(.)\1{7,}")  # 8+ repeated characters (e.g., xxxxxxxx)

# Test/fixture paths check
TEST_PATH_PATTERNS = ["/tests/", "/fixtures/", "/mocks/", ".env.example", "\\tests\\", "\\fixtures\\", "\\mocks\\"]

# Credential-like variable names
CRED_VAR_KEYWORDS = ["api_key", "apikey", "secret", "token", "password", "passwd", "credential", "auth"]

def is_in_comment(line: str, match_value: str) -> bool:
    """
    Heuristic to check if the matched value starts after a comment indicator.
    """
    start_idx = line.find(match_value)
    if start_idx == -1:
        return False
    
    pre_match = line[:start_idx]
    # Check common line comment characters.
    # Check if a comment character exists and is not enclosed in matching quotes.
    for sym in ["#", "//", "--"]:
        idx = pre_match.find(sym)
        while idx != -1:
            before_sym = pre_match[:idx]
            # If the quote counts before the symbol are even, the symbol is likely not inside a string literal.
            single_quotes = before_sym.count("'")
            double_quotes = before_sym.count('"')
            if single_quotes % 2 == 0 and double_quotes % 2 == 0:
                return True
            idx = pre_match.find(sym, idx + 1)
            
    # Also check if it's inside /* ... */ style block in the line
    # (very simple check: if /* is before the match and no */ is between /* and the match)
    open_idx = pre_match.rfind("/*")
    if open_idx != -1:
        close_idx = pre_match.find("*/", open_idx)
        if close_idx == -1 or close_idx > start_idx:
            return True
            
    return False

def assess_hit(
    value: str,
    line: str,
    file_path: str,
    detector_id: str
) -> Tuple[str, List[str]]:
    """
    Validates a raw hit and returns a confidence verdict ('confirmed', 'likely', 'possible', 'suppressed')
    and a list of reasons for the decision.
    """
    reasons = []
    
    # 1. AWS Convention check
    # Any value containing the literal substring "EXAMPLE" is a placeholder.
    if "EXAMPLE" in value:
        return "suppressed", ["AWS convention placeholder ('EXAMPLE') detected"]
        
    # 2. Obvious Placeholder value checks
    val_lower = value.lower()
    for placeholder in PLACEHOLDER_SUBSTRINGS:
        if placeholder in val_lower:
            return "suppressed", [f"Obvious placeholder substring '{placeholder}' detected"]
            
    if REPEATED_CHARS_PATTERN.search(value):
        return "suppressed", ["Obvious placeholder pattern (repeated characters) detected"]
        
    # 3. Low character variety
    if len(set(value)) <= 4:
        return "suppressed", ["Low character variety (<= 4 unique characters)"]
        
    # Determine base confidence
    is_generic_or_entropy = detector_id in ("generic-assignment", "entropy")
    
    if is_generic_or_entropy:
        confidence = "possible"
    else:
        confidence = "confirmed"
        
    # 4. Path Check
    # Normalize path separators for checking
    normalized_path = file_path.replace("\\", "/").lower()
    is_test_path = False
    for pat in TEST_PATH_PATTERNS:
        normalized_pat = pat.replace("\\", "/").lower()
        if normalized_pat in normalized_path:
            is_test_path = True
            break
            
    if is_test_path:
        if is_generic_or_entropy:
            return "suppressed", ["Generic/entropy hit suppressed in test/fixture path"]
        else:
            confidence = "likely"
            reasons.append("Structural hit in test/fixture path (downgraded to likely)")
            
    # 5. Comment Check
    in_comment = is_in_comment(line, value)
    if in_comment:
        reasons.append("Hit is inside a comment (downgraded)")
        if confidence == "confirmed":
            confidence = "likely"
        elif confidence == "likely":
            confidence = "possible"
            
    # 6. Variable Name Boost (only applies to non-suppressed hits that aren't already confirmed)
    # Check if a credential keyword is in the line (excluding the secret value itself)
    line_without_value = line.replace(value, "")
    line_lower = line_without_value.lower()
    has_cred_var = any(kw in line_lower for kw in CRED_VAR_KEYWORDS)
    
    if has_cred_var:
        # Boost if not already at maximum possible confidence (or capped by constraints)
        # Note: A structural hit with a test path caveat caps at 'likely', never 'confirmed'.
        if confidence == "possible":
            confidence = "likely"
            reasons.append("Credential-like variable name in proximity (boosted to likely)")
        elif confidence == "likely" and not is_test_path and not in_comment and not is_generic_or_entropy:
            confidence = "confirmed"
            reasons.append("Credential-like variable name in proximity (boosted to confirmed)")
            
    # Clean up reasons if empty
    if not reasons:
        reasons.append("Clean match with no suppressing or boosting factors")
        
    return confidence, reasons
