import pytest
from secretscanner.context import assess_hit, is_in_comment

def test_aws_example_convention():
    # Structural match containing "EXAMPLE" should be suppressed
    conf, reasons = assess_hit("AKIAIOSFODNN7EXAMPLE", "key = 'AKIAIOSFODNN7EXAMPLE'", "prod/main.py", "aws-access-key")
    assert conf == "suppressed"
    assert "EXAMPLE" in reasons[0]

def test_placeholder_suppression():
    # Value containing "dummy"
    conf, reasons = assess_hit("dummy_key_value_123456789", "key = 'dummy_key_value_123456789'", "prod/main.py", "generic-assignment")
    assert conf == "suppressed"
    
    # Value containing "test"
    conf, reasons = assess_hit("test-api-token-value-here", "token: 'test-api-token-value-here'", "prod/main.py", "generic-assignment")
    assert conf == "suppressed"
    
    # Repeated characters
    conf, reasons = assess_hit("a" * 20, "key = 'aaaaaaaaaaaaaaaaaaaa'", "prod/main.py", "generic-assignment")
    assert conf == "suppressed"

def test_low_variety_suppression():
    # Value with <= 4 unique characters
    conf, reasons = assess_hit("ababababcdcdcdcdabab", "key = 'ababababcdcdcdcdabab'", "prod/main.py", "generic-assignment")
    assert conf == "suppressed"

def test_test_paths():
    # Structural detector in test path -> downgraded to likely
    token_value = "ghp_" + "sampletoken1234567890abcdefghijklmnopqrstuv"
    conf, reasons = assess_hit(token_value, "token = '" + token_value + "'", "/tests/test_auth.py", "github-pat")
    assert conf == "likely"
    
    # Generic/entropy in test path -> suppressed
    conf, reasons = assess_hit("some_random_high_entropy_secret_string", "key = 'some_random_high_entropy_secret_string'", "/tests/test_auth.py", "generic-assignment")
    assert conf == "suppressed"
    
    # Same generic in prod path -> possible (or likely if boosted)
    conf, reasons = assess_hit("some_random_high_entropy_secret_string", "val = 'some_random_high_entropy_secret_string'", "/prod/main.py", "generic-assignment")
    assert conf == "possible"

def test_comment_checks():
    # In comment check helper
    assert is_in_comment("# key = 'AKIAIOSFODNN7EXAMPLE'", "AKIAIOSFODNN7EXAMPLE") is True
    assert is_in_comment("key = 'AKIAIOSFODNN7EXAMPLE'  # inline comment", "AKIAIOSFODNN7EXAMPLE") is False
    assert is_in_comment("url = 'https://example.com/#anchor'", "https://example.com/#anchor") is False
    
    # Downgrade in comments
    token_value = "ghp_" + "sampletoken1234567890abcdefghijklmnopqrstuv"
    conf, reasons = assess_hit(token_value, "# " + token_value, "prod/main.py", "github-pat")
    assert conf == "likely" # Confirmed -> likely
    
    conf, reasons = assess_hit("some_random_high_entropy_secret_string", "# val = 'some_random_high_entropy_secret_string'", "prod/main.py", "generic-assignment")
    # Starts possible -> remains possible (cannot go below possible without being suppressed)
    # Actually, let's verify if 'possible' hit inside comment is possible or suppressed.
    # Our context code says:
    # "elif confidence == 'likely': confidence = 'possible'"
    # So if it was possible, it stays possible.
    assert conf == "possible"

def test_variable_name_boost():
    # Generic assignment starts as possible
    conf, reasons = assess_hit("some_random_high_entropy_secret_string", "val = 'some_random_high_entropy_secret_string'", "prod/main.py", "generic-assignment")
    assert conf == "possible"
    
    # Boosted to likely due to 'secret' keyword in line
    conf_boosted, reasons_boosted = assess_hit("some_random_high_entropy_secret_string", "my_secret = 'some_random_high_entropy_secret_string'", "prod/main.py", "generic-assignment")
    assert conf_boosted == "likely"
    assert "Credential-like variable name" in reasons_boosted[-1]
