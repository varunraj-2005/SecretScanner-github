import re
from dataclasses import dataclass

@dataclass
class Detector:
    id: str
    name: str
    severity: str
    pattern: re.Pattern
    description: str

# Defined structural detectors
DETECTORS = [
    Detector(
        id="aws-access-key",
        name="AWS Access Key ID",
        severity="critical",
        pattern=re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
        description="Identifies AWS Access Key IDs, used to authenticate requests to AWS services."
    ),
    Detector(
        id="aws-secret-key",
        name="AWS Secret Access Key",
        severity="critical",
        # Matches assignments like aws_secret = "..." or secret_key = "..." containing a 40-char base64 key
        pattern=re.compile(r"(?i)\b(?:aws_secret|aws_secret_access_key|secret_key)\b\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
        description="Identifies AWS Secret Access Keys by looking for variable assignments containing 40-character base64 values."
    ),
    Detector(
        id="github-pat",
        name="GitHub Personal Access Token",
        severity="critical",
        pattern=re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"),
        description="Identifies GitHub Personal Access Tokens (classic or fine-grained) or OAuth tokens."
    ),
    Detector(
        id="slack-token",
        name="Slack Token",
        severity="high",
        pattern=re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
        description="Identifies Slack API or bot tokens."
    ),
    Detector(
        id="slack-webhook",
        name="Slack Webhook URL",
        severity="high",
        pattern=re.compile(r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+\b"),
        description="Identifies Slack incoming webhook URLs."
    ),
    Detector(
        id="stripe-key",
        name="Stripe API Key",
        severity="critical",
        pattern=re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
        description="Identifies Stripe secret or restricted API keys."
    ),
    Detector(
        id="google-api-key",
        name="Google API Key",
        severity="high",
        pattern=re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        description="Identifies Google Cloud API keys."
    ),
    Detector(
        id="gcp-service-account",
        name="GCP Service Account JSON",
        severity="high",
        pattern=re.compile(r"(?i)\"type\"\s*:\s*\"service_account\""),
        description="Identifies keywords indicative of Google Cloud service account key JSON files."
    ),
    Detector(
        id="pem-private-key",
        name="PEM Private Key Block",
        severity="critical",
        pattern=re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----"),
        description="Identifies the header block of a PEM-encoded private key."
    ),
    Detector(
        id="jwt-token",
        name="JSON Web Token (JWT)",
        severity="medium",
        # Matches three base64url-encoded parts separated by periods
        pattern=re.compile(r"\b[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_+/=]*\b"),
        description="Identifies potential JSON Web Tokens."
    ),
    Detector(
        id="npm-token",
        name="npm Authentication Token",
        severity="high",
        pattern=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        description="Identifies npm registry authentication tokens."
    ),
    Detector(
        id="twilio-key",
        name="Twilio Key",
        severity="high",
        # Matches Twilio Account SID (AC...) or Twilio API Key (SK...)
        pattern=re.compile(r"\b(?:AC|SK)[0-9a-fA-F]{32}\b"),
        description="Identifies Twilio Account SIDs or API Keys."
    ),
    Detector(
        id="sendgrid-key",
        name="SendGrid API Key",
        severity="high",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9\-_]{22,23}\.[A-Za-z0-9\-_]{43}\b"),
        description="Identifies SendGrid API keys."
    ),
    Detector(
        id="db-connection-string",
        name="Database Connection String",
        severity="high",
        pattern=re.compile(r"\b(?:postgres|postgresql|mongodb|mysql|mssql|redis|sqlite|oracle|db2)://[^:]+:[^@]+@[^/:]+(?::\d+)?(?:/[^\s?#]*)?\b"),
        description="Identifies database connection strings with embedded username and password."
    ),
    Detector(
        id="generic-assignment",
        name="Generic Credential Assignment",
        severity="low",
        # Matches api_key = "..." style assignments, capturing the value in group 1
        pattern=re.compile(r"(?i)\b(?:api_key|apikey|secret|password|passwd|token|credential|private_key|auth_token)\s*[:=]\s*['\"]([^'\"]+)['\"]"),
        description="Identifies generic key or secret variable assignments, subject to context validation."
    )
]
