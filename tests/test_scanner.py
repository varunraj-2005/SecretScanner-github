import os
import pytest
from secretscanner.scanner import scan_working_tree, scan_line, is_binary_file, should_skip_path

def test_should_skip_path():
    assert should_skip_path("node_modules/package/index.js") is True
    assert should_skip_path(".git/config") is True
    assert should_skip_path("src/index.pyc") is True
    assert should_skip_path("src/assets/logo.png") is True
    assert should_skip_path("src/main.py") is False

def test_is_binary_file(tmp_path):
    # Test text file
    txt_file = tmp_path / "test.txt"
    txt_file.write_text("This is clean text.")
    assert is_binary_file(str(txt_file)) is False
    
    # Test binary file with a null byte
    bin_file = tmp_path / "test.bin"
    bin_file.write_bytes(b"This is text\x00with null byte")
    assert is_binary_file(str(bin_file)) is True

def test_scan_line_no_duplicate_reporting():
    # If a line contains a structural match (like GitHub PAT) and a high-entropy string,
    # it should only report the structural one.
    token = "ghp_" + "xYz1234567890abcdefghijklmnopqrstuvw"
    line = 'github_pat = "' + token + '"'
    findings = scan_line(line, 1, "main.py", "/app")
    
    # Only one finding (github-pat) should be reported, and NOT entropy
    assert len(findings) == 1
    assert findings[0].detector_id == "github-pat"

def test_scan_working_tree_exclusions(tmp_path):
    # Create directory structure
    repo_dir = tmp_path / "my_repo"
    repo_dir.mkdir()
    
    # 1. Standard python file with secret
    src_dir = repo_dir / "src"
    src_dir.mkdir()
    py_file = src_dir / "app.py"
    secret = "sk_live_" + "51Mza89F3n8D79m6A8v123456"
    py_file.write_text('stripe_key = "' + secret + '"')
    
    # 2. Ignored directory file
    nm_dir = repo_dir / "node_modules"
    nm_dir.mkdir()
    js_file = nm_dir / "index.js"
    js_file.write_text('stripe_key = "' + secret + '"')
    
    # 3. Binary file
    bin_file = src_dir / "logo.png"
    bin_file.write_bytes(b"PNG header\x00" + secret.encode("utf-8"))
    
    # 4. Large file (>5MB)
    large_file = src_dir / "large.txt"
    try:
        # Create a file just over 5MB
        with open(large_file, "wb") as f:
            f.seek(5 * 1024 * 1024 + 100)
            f.write(f'stripe_key = "{secret}"'.encode("utf-8"))
    except Exception:
        pass # ignore if disk/temp error
        
    findings = scan_working_tree(str(repo_dir))
    
    # Check that only the app.py finding is reported!
    # node_modules and binary/large files should be skipped.
    assert len(findings) == 1
    assert findings[0].detector_id == "stripe-key"
    assert "app.py" in findings[0].file_path.replace("\\", "/")
