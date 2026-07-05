import pytest
from secretscanner.entropy import calculate_entropy, extract_candidates

def test_entropy_calculation():
    # Repeated character string should have exactly 0.0 entropy
    assert calculate_entropy("a" * 40) == 0.0
    assert calculate_entropy("1" * 20) == 0.0
    
    # Alternating characters (limited unique chars)
    # Entropy should be low: - (2 * 0.5 * log2(0.5)) = 1.0
    assert calculate_entropy("abababab") == 1.0
    
    # Random 40-char hex string (higher entropy)
    # 0123456789abcdef distributed evenly has high entropy (up to 4.0)
    rand_hex = "f9a2b53c7d6e8109a2b53c7d6e8109a2b53c7d6e"
    assert calculate_entropy(rand_hex) > 3.0
    
    # Random 40-char base64-like string
    rand_b64 = "wJalrXUtnFEMIKMDENGbPxRfiCYzEXAMPLEKEY99"
    assert calculate_entropy(rand_b64) > 4.3

def test_extract_candidates_length_constraints():
    # Short token regardless of randomness (e.g. 15 chars) should NOT be extracted
    short_rand = "xY9+pQ2-rM4_tK"
    assert extract_candidates(f"my_key = '{short_rand}'") == []
    
    # Repeated-character long run should NOT clear the entropy threshold
    repeated_long = "a" * 40
    assert extract_candidates(f"my_key = '{repeated_long}'") == []
    
    # Valid high-entropy base64 run (>=20 chars) should be extracted
    b64_val = "wJalrXUtnFEMIKMDENGbPxRfiCYz" # 28 chars
    candidates = extract_candidates(f"token = '{b64_val}'")
    assert len(candidates) == 1
    assert candidates[0][0] == b64_val
    assert candidates[0][2] == "base64"
    
    # Valid high-entropy hex run (>=32 chars) should be extracted
    hex_val = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" # 32 chars
    candidates = extract_candidates(f"hex_key = '{hex_val}'")
    assert len(candidates) == 1
    assert candidates[0][0] == hex_val
    assert candidates[0][2] == "hex"
    
    # A hex run of length 25 (>= 20 and < 32)
    # It cannot clear hex threshold length (32) and its maximum possible entropy is ~3.5
    # so it won't clear base64 threshold of 4.3 either, and should not be extracted.
    hex_25 = "a1b2c3d4e5f6a1b2c3d4e5f6a"
    assert extract_candidates(f"val = '{hex_25}'") == []
