import re
import pytest
from secretscanner.detectors import DETECTORS

def get_detector(detector_id: str):
    return next(d for d in DETECTORS if d.id == detector_id)

def test_aws_access_key():
    detector = get_detector("aws-access-key")
    
    # Valid AWS Access Key ID (20 chars starting with AKIA/ASIA/etc)
    valid_key = "AKIA" + "IOSFODNN7EXAMPLE"
    assert detector.pattern.search(valid_key) is not None
    assert detector.pattern.search(valid_key).group(0) == valid_key
    
    valid_key_asia = "ASIA" + "IOSFODNN7EXAMPLE"
    assert detector.pattern.search(valid_key_asia) is not None
    
    # Invalid key (too short, wrong prefix)
    invalid_key = "BKIA" + "IOSFODNN7EXAMPLE"
    assert detector.pattern.search(invalid_key) is None
    
    # Too short key
    too_short = "AKIA" + "IOSFODNN7EXAM"
    assert detector.pattern.search(too_short) is None

def test_aws_secret_key():
    detector = get_detector("aws-secret-key")
    
    # Valid variable assignment with 40-char base64
    base_secret = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYzEXAMPLEKE"
    valid_line = 'aws_secret_access_key = "' + base_secret + '"'
    match = detector.pattern.search(valid_line)
    assert match is not None
    assert match.group(1) == base_secret
    
    # Case insensitivity and colon assignment
    valid_colon = 'secret_key: "' + base_secret + '"'
    match = detector.pattern.search(valid_colon)
    assert match is not None
    
    # Incorrect character length (39 characters)
    invalid_len = 'aws_secret = "' + base_secret[:-1] + '"'
    assert detector.pattern.search(invalid_len) is None

def test_github_pat():
    detector = get_detector("github-pat")
    
    # Suffix must be at least 36 characters (40 chars total)
    valid_pat = "ghp_" + "xYz1234567890abcdefghijklmnopqrstuvw"
    assert detector.pattern.search(valid_pat) is not None
    
    # Near miss
    invalid_pat = "ghx_" + "xYz1234567890abcdefghijklmnopqrstuvw"
    assert detector.pattern.search(invalid_pat) is None

def test_stripe_key():
    detector = get_detector("stripe-key")
    
    valid_live = "sk_live_" + "51Mza89F3n8D79m6A8v123456"
    assert detector.pattern.search(valid_live) is not None
    
    valid_test = "rk_test_" + "51Mza89F3n8D79m6A8v123456"
    assert detector.pattern.search(valid_test) is not None
    
    invalid = "pk_live_" + "51Mza89F3n8D79m6A8v123456"
    assert detector.pattern.search(invalid) is None

def test_google_api_key():
    detector = get_detector("google-api-key")
    
    valid = "AIza" + "SyD-aBc123_xYz456-7890123456789abcd"
    assert detector.pattern.search(valid) is not None
    
    invalid = "BIza" + "SyD-aBc123_xYz456-7890123456789abcd"
    assert detector.pattern.search(invalid) is None

def test_gcp_service_account():
    detector = get_detector("gcp-service-account")
    
    line = '"type": "service_account"'
    assert detector.pattern.search(line) is not None
    
    # Case insensitivity
    line_caps = '"TYPE": "SERVICE_ACCOUNT"'
    assert detector.pattern.search(line_caps) is not None

def test_pem_private_key():
    detector = get_detector("pem-private-key")
    
    line = "-----BEGIN RSA PRIVATE KEY-----"
    assert detector.pattern.search(line) is not None
    
    invalid = "-----BEGIN RSA PUBLIC KEY-----"
    assert detector.pattern.search(invalid) is None

def test_jwt_token():
    detector = get_detector("jwt-token")
    
    # Valid JWT shape (3 parts)
    valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert detector.pattern.search(valid_jwt) is not None
    
    # Only 2 parts (invalid format)
    invalid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkw"
    assert detector.pattern.search(invalid_jwt) is None

def test_db_connection_string():
    detector = get_detector("db-connection-string")
    
    valid_pg = "postgres://root:" + "supersecretpassword" + "@localhost:5432/my_db"
    assert detector.pattern.search(valid_pg) is not None
    
    valid_mongo = "mongodb://user:" + "pass" + "@127.0.0.1/auth_db"
    assert detector.pattern.search(valid_mongo) is not None
    
    # No credentials (should not fire structural DB regex as it requires user:pass)
    no_creds = "postgresql://localhost:5432/db"
    assert detector.pattern.search(no_creds) is None

def test_generic_assignment():
    detector = get_detector("generic-assignment")
    
    valid = 'api_key = "some_random_value"'
    match = detector.pattern.search(valid)
    assert match is not None
    assert match.group(1) == "some_random_value"
    
    valid_pw = 'password = "foo"'
    match = detector.pattern.search(valid_pw)
    assert match is not None
    assert match.group(1) == "foo"
    
    # Not matching non-credential assignment
    non_cred = 'var_name = "secret_value"'
    assert detector.pattern.search(non_cred) is None
