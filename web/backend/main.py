"""
SecretScanner Web Backend
FastAPI application that wraps the secretscanner CLI modules and
exposes scan results over HTTP + Server-Sent Events.
"""

import sys
import os
import json
import uuid
import re
import zipfile
import tempfile
import shutil
import threading
import subprocess
import time
from typing import Optional, Dict, Any, List
from pathlib import Path

# Ensure the secretscanner package (sibling of web/) is importable
ROOT = Path(__file__).parent.parent.parent  # E:/ss
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from secretscanner.scanner import scan_working_tree, scan_git_history, Finding
from secretscanner.allowlist import load_baseline, save_baseline, is_allowlisted, get_relative_path
from secretscanner.report import to_json, to_sarif

# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────
app = FastAPI(title="SecretScanner Web API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files at root
FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# ─────────────────────────────────────────────
# In-memory scan job store
# ─────────────────────────────────────────────
# scan_id -> { status, progress_messages, findings, error, path, temp_dir }
SCANS: Dict[str, Dict[str, Any]] = {}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
CONFIDENCE_ORDER = {"confirmed": 3, "likely": 2, "possible": 1}

# ─────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    path: str
    scan_history: bool = False
    history_only: bool = False
    max_commits: Optional[int] = None
    min_severity: str = "low"
    min_confidence: str = "possible"
    baseline_path: Optional[str] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str


# ─────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────

GITHUB_URL_RE = re.compile(
    r'^(https?://(www\.)?github\.com/[\w.\-]+/[\w.\-]+(/.*)?)'
    r'|^(git@github\.com:[\w.\-]+/[\w.\-]+(\.git)?)$',
    re.IGNORECASE
)

def is_github_url(path: str) -> bool:
    """Returns True if the given string looks like a GitHub repo URL."""
    p = path.strip()
    return bool(GITHUB_URL_RE.match(p)) or (
        p.startswith('https://github.com') or
        p.startswith('http://github.com') or
        p.startswith('git@github.com')
    )


def clone_github_repo(url: str, push_fn) -> str:
    """
    Clones a GitHub repository URL into a temp directory.
    Returns the path to the cloned directory.
    Raises RuntimeError if cloning fails.
    """
    # Normalise: strip trailing slashes/extra paths for cloning
    # We always clone the root of the repo (no subdirectory support)
    clean_url = url.strip().rstrip('/')
    # Strip .git suffix if present to normalise, then add it back for git clone
    if not clean_url.endswith('.git'):
        clone_url = clean_url + '.git'
    else:
        clone_url = clean_url

    tmp_dir = tempfile.mkdtemp(prefix='secretscanner_gh_')
    push_fn(f'📡 Cloning repository: {clean_url}  …')
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth=50', clone_url, tmp_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            stderr = result.stderr.strip()
            raise RuntimeError(
                f'git clone failed (exit {result.returncode}): {stderr}'
            )
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError('git clone timed out after 120 seconds')
    except FileNotFoundError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(
            'git is not installed or not on PATH. '
            'Please install Git: https://git-scm.com/downloads'
        )

    push_fn(f'  ✔ Clone successful → {tmp_dir}')
    return tmp_dir


def filter_findings(
    findings: List[Finding],
    min_severity: str,
    min_confidence: str,
    baseline: dict,
    repo_root: str,
) -> List[Finding]:
    min_sev = SEVERITY_ORDER.get(min_severity.lower(), 1)
    min_conf = CONFIDENCE_ORDER.get(min_confidence.lower(), 1)
    filtered = []
    for f in findings:
        if SEVERITY_ORDER.get(f.severity.lower(), 0) < min_sev:
            continue
        if CONFIDENCE_ORDER.get(f.confidence.lower(), 0) < min_conf:
            continue
        if baseline and is_allowlisted(f.secret_value, f.file_path, f.line_number, repo_root, baseline):
            continue
        filtered.append(f)
    return filtered


def run_scan_job(scan_id: str, config: dict):
    """Runs in a background thread. Streams progress via SCANS dict."""
    job = SCANS[scan_id]
    job["status"] = "running"

    def push(msg: str):
        job["progress_messages"].append(msg)

    try:
        raw_target = config["path"].strip()
        cloned_tmp = None

        # ── GitHub URL → clone first ──────────────────────────
        if is_github_url(raw_target):
            cloned_tmp = clone_github_repo(raw_target, push)
            target = cloned_tmp
            job["temp_dir"] = cloned_tmp  # will be cleaned up in finally
        else:
            target = raw_target
            if not os.path.exists(target):
                raise FileNotFoundError(
                    f"Path not found: {target}\n\n"
                    f"💡 Tip: To scan a GitHub repo, paste the full URL — e.g. "
                    f"https://github.com/owner/repo"
                )

        repo_root = target if os.path.isdir(target) else os.path.dirname(target)
        findings: List[Finding] = []

        # Load baseline if provided
        baseline_path = config.get("baseline_path") or os.path.join(repo_root, ".secretscanner-baseline.json")
        baseline = load_baseline(baseline_path)

        # Working tree scan
        if not config.get("history_only", False):
            push("📂 Scanning working tree…")
            tree_findings = scan_working_tree(target)
            push(f"  ✔ Working tree: {len(tree_findings)} raw hits found")
            findings.extend(tree_findings)

        # Git history scan
        if config.get("scan_history", False) or config.get("history_only", False):
            push("📜 Scanning git history (this may take a moment)…")
            max_c = config.get("max_commits")
            hist_findings = scan_git_history(repo_root, max_commits=max_c)
            push(f"  ✔ Git history: {len(hist_findings)} raw hits found")
            findings.extend(hist_findings)

        # Apply filters
        push("🔍 Applying confidence & severity filters…")
        filtered = filter_findings(
            findings,
            min_severity=config.get("min_severity", "low"),
            min_confidence=config.get("min_confidence", "possible"),
            baseline=baseline,
            repo_root=repo_root,
        )

        push(f"✅ Scan complete — {len(filtered)} findings after filtering")
        job["findings"] = [f.to_dict() for f in filtered]
        job["raw_findings"] = filtered          # keep Finding objects for export
        job["repo_root"] = repo_root
        job["status"] = "done"

    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
        job["progress_messages"].append(f"❌ Error: {exc}")
    finally:
        # Clean up extracted zip temp dir if any
        tmp = job.get("temp_dir")
        if tmp and os.path.exists(tmp):
            shutil.rmtree(tmp, ignore_errors=True)


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/")
async def serve_frontend():
    return FileResponse(str(FRONTEND_DIR / "index.html"))


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    """Start a scan job on a local directory path."""
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = {
        "status": "queued",
        "progress_messages": [],
        "findings": [],
        "raw_findings": [],
        "error": None,
        "repo_root": req.path,
        "temp_dir": None,
    }
    config = req.model_dump()
    t = threading.Thread(target=run_scan_job, args=(scan_id, config), daemon=True)
    t.start()
    return ScanResponse(scan_id=scan_id, status="queued")


@app.post("/api/scan/upload", response_model=ScanResponse)
async def start_scan_upload(
    file: UploadFile = File(...),
    scan_history: bool = Form(False),
    min_severity: str = Form("low"),
    min_confidence: str = Form("possible"),
):
    """Accept a zip file upload, extract it, and start a scan."""
    scan_id = str(uuid.uuid4())
    tmp_dir = tempfile.mkdtemp(prefix="secretscanner_")

    # Save uploaded zip
    zip_path = os.path.join(tmp_dir, "upload.zip")
    with open(zip_path, "wb") as zf:
        content = await file.read()
        zf.write(content)

    # Extract
    extract_dir = os.path.join(tmp_dir, "repo")
    os.makedirs(extract_dir, exist_ok=True)
    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(extract_dir)
    except zipfile.BadZipFile:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.")

    SCANS[scan_id] = {
        "status": "queued",
        "progress_messages": [f"📦 ZIP uploaded: {file.filename}"],
        "findings": [],
        "raw_findings": [],
        "error": None,
        "repo_root": extract_dir,
        "temp_dir": tmp_dir,
    }
    config = {
        "path": extract_dir,
        "scan_history": scan_history,
        "history_only": False,
        "max_commits": None,
        "min_severity": min_severity,
        "min_confidence": min_confidence,
    }
    t = threading.Thread(target=run_scan_job, args=(scan_id, config), daemon=True)
    t.start()
    return ScanResponse(scan_id=scan_id, status="queued")


@app.get("/api/scan/{scan_id}/stream")
async def stream_progress(scan_id: str, request: Request):
    """Server-Sent Events endpoint for live scan progress."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")

    async def event_generator():
        sent_index = 0
        while True:
            if await request.is_disconnected():
                break
            job = SCANS.get(scan_id, {})
            msgs = job.get("progress_messages", [])
            while sent_index < len(msgs):
                yield f"data: {json.dumps({'message': msgs[sent_index]})}\n\n"
                sent_index += 1
            status = job.get("status", "queued")
            if status in ("done", "error"):
                payload = {"status": status}
                if status == "error":
                    payload["error"] = job.get("error", "Unknown error")
                yield f"data: {json.dumps(payload)}\n\n"
                break
            await _async_sleep(0.3)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def _async_sleep(seconds: float):
    import asyncio
    await asyncio.sleep(seconds)


@app.get("/api/scan/{scan_id}/results")
async def get_results(scan_id: str):
    """Return the completed scan findings as JSON."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    job = SCANS[scan_id]
    if job["status"] == "error":
        raise HTTPException(status_code=500, detail=job.get("error", "Scan failed"))
    if job["status"] != "done":
        raise HTTPException(status_code=202, detail="Scan still in progress")

    findings = job.get("findings", [])
    # Build summary stats
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    confidence_counts = {"confirmed": 0, "likely": 0, "possible": 0}
    detector_counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "low").lower()
        conf = f.get("confidence", "possible").lower()
        did = f.get("detector_id", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
        detector_counts[did] = detector_counts.get(did, 0) + 1

    return {
        "scan_id": scan_id,
        "total": len(findings),
        "severity_counts": severity_counts,
        "confidence_counts": confidence_counts,
        "detector_counts": detector_counts,
        "findings": findings,
    }


@app.get("/api/scan/{scan_id}/export/{fmt}")
async def export_results(scan_id: str, fmt: str):
    """Download findings as JSON or SARIF."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    job = SCANS[scan_id]
    if job["status"] != "done":
        raise HTTPException(status_code=202, detail="Scan still in progress")

    raw = job.get("raw_findings", [])
    repo_root = job.get("repo_root", ".")

    if fmt == "json":
        content = to_json(raw)
        filename = f"secretscanner-{scan_id[:8]}.json"
        media_type = "application/json"
    elif fmt == "sarif":
        content = to_sarif(raw, repo_root)
        filename = f"secretscanner-{scan_id[:8]}.sarif"
        media_type = "application/json"
    else:
        raise HTTPException(status_code=400, detail="Format must be 'json' or 'sarif'")

    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(iter([content]), media_type=media_type, headers=headers)


@app.post("/api/scan/{scan_id}/baseline")
async def save_scan_baseline(scan_id: str):
    """Save current scan findings to baseline to suppress them in future scans."""
    if scan_id not in SCANS:
        raise HTTPException(status_code=404, detail="Scan not found")
    job = SCANS[scan_id]
    if job["status"] != "done":
        raise HTTPException(status_code=202, detail="Scan still in progress")

    repo_root = job.get("repo_root", ".")
    findings = job.get("findings", [])
    baseline_path = os.path.join(repo_root, ".secretscanner-baseline.json")
    save_baseline(baseline_path, findings, repo_root)
    return {"message": f"Baseline saved to {baseline_path}", "count": len(findings)}
