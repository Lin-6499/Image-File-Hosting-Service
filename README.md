# Image & Text Hosting Service

Self-hosted file and image hosting for automated callers (e.g. Codex). Upload a
file or image, receive a **time-limited signed download link** and, for images, a
**permanent public display link** suitable for embedding in Markdown or HTML.

## Design in one paragraph

Download links are signed with HMAC-SHA256 and carry their own expiry, so
verification needs no database lookup and the service scales horizontally
without shared session state. Image links are permanent but unguessable, and
include a content hash so `Cache-Control: immutable` is safe. Blobs are stored
content-addressed on local disk (deduplicated, sharded two levels deep);
metadata lives in SQLite in WAL mode. In production nginx serves file bytes via
`X-Accel-Redirect`, keeping large transfers out of the Python process.

---

## Directory layout

```
D:\ImageAndTextHosting\
├── .venv/                     # virtualenv (self-contained, not global)
├── .env                       # active config -- git-ignored
├── .env.example               # config template, committed
├── requirements.txt           # runtime deps
├── requirements-dev.txt       # + pytest / httpx
│
├── app/
│   ├── __init__.py
│   ├── main.py                # app factory, error handlers, health probes
│   ├── config.py              # settings from env/.env; dir layout helpers
│   ├── db.py                  # SQLite schema, migrations, repository
│   ├── storage.py             # content-addressed blob store, streaming writes
│   ├── signing.py             # HMAC sign/verify, TTL clamping  <- core
│   ├── auth.py                # API keys, quota, token-bucket rate limit
│   ├── scanner.py             # antivirus backends: clamd / clamscan / stub
│   ├── scanservice.py         # scan orchestration: queue, resolve, unstick
│   ├── images.py              # magic-byte sniffing, thumbnails, EXIF strip
│   ├── urls.py                # URL builders, safe Content-Disposition
│   ├── schemas.py             # pydantic request/response models
│   ├── cleanup.py             # expiry, reclamation, scan pickup, stale release
│   └── routers/
│       ├── __init__.py
│       ├── files.py           # /api/v1/*  (authenticated)
│       └── access.py          # /d/*, /i/* (public, signature-verified)
│
├── scripts/
│   ├── dev.py                 # start dev server with autoreload
│   ├── mintkey.py             # create an API key
│   ├── keys.py                # list / revoke API keys
│   ├── demo.py                # upload an image and exercise every link type
│   ├── _isolate.py            # temp-dir redirect for in-process scripts
│   ├── smoke_test.py          # full lifecycle over ASGI (isolated)
│   ├── scan_demo.py           # malware gating rules over ASGI (isolated)
│   ├── e2e_local.py           # full lifecycle over real HTTP/TCP
│   ├── av_e2e.py              # malware gate over real HTTP/TCP
│   ├── verify_blobs.py        # audit blobs: hashes, row consistency, orphans
│   └── cleanup.py             # cron entry point for the sweep
│
├── tests/                     # pytest suite (204 tests, fully isolated)
│   ├── conftest.py            # redirects DATA_DIR to a temp dir before import
│   ├── test_signing.py        # HMAC, purpose binding, expiry, TTL clamping
│   ├── test_storage.py        # streaming limits, dedup, sharding, atomicity
│   ├── test_db.py             # CRUD, reclamation safety, API keys
│   ├── test_images.py         # sniffing, thumbnails, EXIF stripping
│   ├── test_scanner.py        # scanners, gating rules, schema migration
│   └── test_api.py            # all endpoints, content-address integrity
│
├── MANUAL_TESTING.md          # hand-driven verification runbook
├── deploy/
│   ├── nginx.conf.example     # TLS, rate limits, internal _blobs mount
│   └── host-service.service   # systemd unit with hardening
│
└── data/                      # runtime payload -- git-ignored
    ├── blobs/<xx>/<sha256>    # content-addressed originals
    ├── thumbs/<xx>/<sha256>_512.webp
    ├── tmp/                   # upload staging (same FS as blobs -> atomic)
    └── host.db                # SQLite
```

`data/tmp/` deliberately sits under `data/` rather than the system temp
directory: `os.replace()` is only atomic within one filesystem, and the OS temp
dir is usually a separate mount.

---

## Setup

```bash
cd D:\ImageAndTextHosting

# 1. virtualenv (already created; recreate only if needed)
python -m venv .venv

# 2. dependencies
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

# 3. config
copy .env.example .env

# 4. create an API key (prints the plaintext exactly once)
.venv\Scripts\python.exe -m scripts.mintkey dev --quota-gb 10
```

If `python` is not on `PATH`, use the interpreter that created the venv:
`C:\Users\Administrator\.workbuddy-ai\binaries\python\versions\3.13.12\python.exe`

### Windows note: `python-magic`

Magic-byte detection is implemented directly in `app/images.py` rather than
depending on `python-magic`, whose Windows build requires the native
`libmagic` DLL. This keeps setup to plain `pip install` with no external
binaries. To switch to `python-magic` on Linux, replace `sniff_mime()`.

### Windows note: SQLite journal mode (important)

`DB_JOURNAL_MODE` defaults to **`TRUNCATE`**, not `WAL`.

WAL mode relies on a shared-memory mapping (the `-shm` file). Some Windows
volumes cannot host it. On such a volume the failure is silent and misleading:
`sqlite3.connect()` succeeds, DDL executes, and then `conn.close()` **blocks
forever** — the process hangs at startup printing nothing but
`Waiting for application startup.`

This was observed during setup of this project. The same code works on `C:`
but hangs under `D:\ImageAndTextHosting`, despite both being NTFS. If you hit a
silent startup hang, this is the cause: set `DB_JOURNAL_MODE=TRUNCATE` (or move
`DATA_DIR` to a volume where WAL works).

**On a Linux production server, switch to WAL** — it lets readers proceed
without blocking the writer, which is exactly this service's access pattern:

```
DB_JOURNAL_MODE=WAL
```

---

## Running

### Development server

```bash
.venv\Scripts\python.exe -m scripts.dev
```

Serves on `http://127.0.0.1:8000`, with autoreload and interactive docs:

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8000/docs` | Swagger UI |
| `http://127.0.0.1:8000/redoc` | ReDoc |
| `http://127.0.0.1:8000/healthz` | liveness |
| `http://127.0.0.1:8000/readyz` | readiness (checks storage writable) |

Configuration is read from `.env` on startup; edit `.env` and restart to apply.

### VS Code (run & debug)

The repository ships a committed `.vscode/` set, so a fresh clone needs no
manual wiring -- just the Python extension (see below). Open the folder
(`File > Open Folder...`), then:

| File | What it gives you |
|---|---|
| `settings.json` | interpreter, pytest discovery, watcher exclusions, UTF-8 terminal |
| `launch.json` | 15 debug configurations (F5) |
| `tasks.json` | 12 tasks + the composite `verify: everything` |
| `extensions.json` | recommended extensions (Python, debugpy, Pylance, Ruff, REST Client) |
| `api.http` | a clickable API console against a running server |

`.gitignore` deliberately ignores `.vscode/*` but re-includes these five files,
so shared config is versioned while personal overrides (e.g. your own
`launch.json` additions) can be kept in a separate untracked file.

#### Prerequisite: the Python extension

**F5 does nothing useful without it.** `launch.json` uses
`"type": "debugpy"`, which is contributed by `ms-python.debugpy` -- and that
arrives as a dependency of `ms-python.python`. With no Python extension
installed, VS Code has no debugger registered for these configurations, so the
Run and Debug dropdown comes up empty and pressing F5 prompts you to "create a
launch.json file" even though one is sitting right there.

```bash
code --install-extension ms-python.python
```

That pulls in the whole set: `ms-python.python`, `ms-python.debugpy`,
`ms-python.vscode-pylance`, `ms-python.vscode-python-envs`. Confirm with
`code --list-extensions`. Reload the window afterwards.

The **tasks** in `tasks.json` do *not* need it -- they spell out
`.venv/Scripts/python.exe` directly, so `F1` → `Tasks: Run Task` works
on a bare VS Code install. Only the debugger and the Test Explorer need the
extension.

> This guide writes **`F1`** wherever the command palette is needed. `Ctrl+Shift+P`
> does the same thing, but on Chinese Windows it is frequently intercepted by the
> input-method hotkey -- see [`Ctrl+Shift+P` does nothing](#ctrlshiftp-does-nothing-chinese-windows)
> at the end of this section. `F1` always works.

#### First run

Check the interpreter in the status bar -- it must read
`.venv\Scripts\python.exe` (Python 3.13). If it does not,
`F1` → `Python: Select Interpreter` → `./.venv/Scripts/python.exe`.

If VS Code shows a restricted-mode banner, click **Trust** -- untrusted
workspaces refuse to run debug configurations and tasks.

#### The everyday loop

Press `F5` and pick **Dev server (autoreload)**. Edit a `.py` file under `app/`
and the reloader restarts the worker; set a breakpoint anywhere in a request
handler and it fires on the next request. The terminal shows:

```
INFO:     Started reloader process [...] using WatchFiles
INFO:     Started server process [...]
INFO:     Application startup complete.
```

Then open <http://127.0.0.1:8000/docs>.

#### If something does not work

| Symptom | Cause | Fix |
|---|---|---|
| Run and Debug dropdown is empty | Python extension not installed | `code --install-extension ms-python.python`, reload window |
| `The debug type is not recognized` | Python extension older than 2024.x | Update it; or change `"type": "debugpy"` to `"type": "python"` |
| F5 prompts "create a launch.json file" | Folder opened is not the project root, or `.vscode/` is missing | `File > Open Folder...` on `D:\ImageAndTextHosting` |
| Breakpoints in handlers never hit | `"subProcess"` removed from the autoreload config | Restore `"subProcess": true` |
| Task fails with "command not found" | A task was edited back to `${command:python.interpreterPath}` | Use the explicit `.venv` path instead |
| Tests missing from the Testing sidebar | pytest not discovered | `F1` → `Python: Configure Tests` → pytest → `tests` |
| Nothing runs at all | Workspace not trusted | Click **Trust** in the banner |
| `Ctrl+Shift+P` does nothing at all | Windows binds `Ctrl+Shift` to input-method switching | Press **`F1`** -- same command palette, no modifiers |
| Every `Ctrl+Shift+...` shortcut is dead | same as above | same; or unbind the Windows hotkey (below) |

#### `Ctrl+Shift+P` does nothing (Chinese Windows)

If the command palette never opens, check the Windows input-method hotkey
before suspecting VS Code:

```powershell
Get-ItemProperty 'HKCU:\Keyboard Layout\Toggle'
```

```
Layout Hotkey   : 2      # 2 = Ctrl+Shift, 1 = Left Alt+Shift, 3 = unassigned
Language Hotkey : 1
```

With `Layout Hotkey = 2`, Windows consumes `Ctrl+Shift` to cycle input methods
**before VS Code ever sees the keystroke**, so the palette never opens. This
bites every `Ctrl+Shift+...` binding, not just this one.

Two ways out:

1. **Press `F1`.** It opens the same command palette and involves no modifier
   keys, so nothing can intercept it. The menu works too: **查看(V) → 命令面板**.
2. **Unbind the Windows hotkey** (system-wide, affects every application):
   `设置` → `时间和语言` → `输入` → `高级键盘设置` → `输入语言热键` →
   `更改按键顺序` → set 切换键盘布局 to **未分配**.

The equivalent registry value is `Layout Hotkey = 3` under
`HKCU\Keyboard Layout\Toggle`, but change it through the Settings UI -- the
change is not always picked up from the registry alone.

**Zero-config fallback.** If VS Code misbehaves entirely, the project runs from
any terminal with no editor involvement:

```bash
.venv\Scripts\python.exe -m scripts.dev
```

**Launch configurations**, grouped by intent:

*Server* — `Dev server (autoreload)` (the default choice), `Dev server (debug,
no reload)` (stable PIDs and no restart noise, better for stepping through
startup), `Dev server (AV_BACKEND=stub)` (the scanner test double).

*Tests, no server needed* — `pytest: all tests`, `pytest: current file`,
`pytest: current test method` (select a test name in the editor first; it is
passed through `-k`), `Smoke test (ASGI, isolated)`, `Scan demo (ASGI,
isolated)`.

*Against a running server* — `Demo`, `E2E over real HTTP`, `AV gate over real
HTTP`. Start one of the server configs first; these three talk TCP and will
fail fast if nothing is listening.

*Maintenance* — `Audit blob store`, `Cleanup sweep`, `Mint API key` (prompts
for a key label). *Generic* — `Current file`.

**Tasks** (`F1` → `Tasks: Run Task`). Every task invokes
`${workspaceFolder}/.venv/Scripts/python.exe` by explicit path, so it needs no
extension and cannot pick up a stray interpreter from `PATH`. (On Linux/macOS
change those paths to `.venv/bin/python`.) `test: pytest (all)` is wired as the
default test task and attaches a problem matcher, so failures land in the
Problems panel. `verify: everything (no server needed)` runs pytest → smoke →
scan demo → audit
in sequence, which is the one to run before committing.

**Test Explorer.** The Testing sidebar discovers all 204 tests; the gutter
icons in `tests/*.py` debug a single test under the debugger. This is the
fastest path to a breakpoint inside `stream_to_blob` or the signing helpers.

**Interactive API.** With the dev server running, open `.vscode/api.http` and
click `Send Request` above any block. Set `@apiKey` at the top from
`Mint API key` first. Responses are captured by name (`# @name upload`), so
later requests reference `{{upload.response.body.$.download_url}}` without
copy-paste.

**Two settings that are not optional.** Both are commented inline in
`launch.json`:

- `"subProcess": true` on the autoreload config. uvicorn's reloader runs the
  app in a child process; without this the debugger attaches only to the
  parent watcher and breakpoints in request handlers silently never fire.
- `"justMyCode": false` everywhere. The default steps over `site-packages`,
  which hides Starlette/FastAPI frames -- precisely the frames you need when
  working out why a request returned 500.

**One code-side companion.** `scripts/dev.py` passes `reload_excludes` to
uvicorn so the watcher ignores `.venv`, `data` and `scratch`. uvicorn only
reacts to `*.py`, and `data/` holds no Python files, so uploads never triggered
restarts anyway -- this keeps the watcher off the thousands of `.py` files in
`site-packages` when packages are installed while the server runs.

Getting that list right is fussier than it looks, and `scripts/dev.py`
documents both traps in full:

- **Bare directory names do nothing.** uvicorn's `FileFilter` keeps directory
  entries as given and tests them with `exclude_dir in path.parents`. A
  relative `Path("data")` never equals the absolute parents of a watched file,
  so the exclusion is silently inert. Only absolute paths match.
- **An absolute path to a directory that does not exist crashes startup.**
  uvicorn falls through to `Path.cwd().glob(<absolute pattern>)`, which raises
  `NotImplementedError: Non-relative patterns are unsupported`. So each entry
  is filtered through `is_dir()` first -- `.pytest_cache` does not exist until
  something has run.

### Verify the installation

Four layers, each catching a class of problem the others cannot see.

```bash
# 1. pytest -- fast, isolated, writes only to a temp directory
.venv\Scripts\python.exe -m pytest -q

# 2. script-style assertions over the in-process ASGI transport
.venv\Scripts\python.exe scripts/smoke_test.py    # full lifecycle, 38 checks
.venv\Scripts\python.exe scripts/scan_demo.py     # malware gating, 5 rules

# 3. real HTTP/TCP against a running server
.venv\Scripts\python.exe -m scripts.dev
.venv\Scripts\python.exe scripts/e2e_local.py http://127.0.0.1:8000   # 47 checks
AV_BACKEND=stub .venv\Scripts\python.exe scripts/av_e2e.py http://127.0.0.1:8000  # 20 checks

# 4. storage invariant audit
.venv\Scripts\python.exe scripts/verify_blobs.py
```

Expected: `206 passed`, `all checks passed`, `all 47 checks passed`,
`all 20 checks passed`, `store and rows are consistent`.

**Why layer 3 matters.** The in-process transport cannot see real TCP
behaviour, host-level monkeypatching of the standard library, or process-wide
side effects. Two genuine defects -- cleanup exceptions tearing down otherwise
healthy requests, and `AV_BACKEND=stub` silently flagging nothing -- were both
invisible to 166 green in-process tests and surfaced immediately over real
HTTP.

**Where each layer writes.** pytest and the in-process scripts
(`smoke_test.py`, `scan_demo.py`) redirect `DATA_DIR` to a temp directory
*before* importing the app, because `app.config.settings` builds its paths at
import time. `demo.py`, `e2e_local.py` and `av_e2e.py` talk to a running server
over HTTP and therefore legitimately use the real `data/`. Set
`HOST_SCRIPT_NO_ISOLATE=1` to opt the in-process scripts back out.

Coverage by module:

| File | Focus |
|---|---|
| `test_signing.py` | HMAC correctness, purpose binding, expiry, clock skew, TTL clamping |
| `test_storage.py` | Streaming size enforcement, dedup, sharding, atomic commit, tmp sweep, pre-commit sanitising |
| `test_db.py` | CRUD, soft delete, reference-counted reclamation, API keys, stats |
| `test_images.py` | Magic-byte sniffing, thumbnails, animated-GIF handling, EXIF stripping |
| `test_scanner.py` | Scanner backends, the five-state gate, schema migration, stub wiring, queued-file pickup, cleanup fault isolation |
| `test_api.py` | Every endpoint: auth, upload, signed download, image links, deletion, content-address integrity |

### Auditing the blob store

```bash
.venv\Scripts\python.exe scripts/verify_blobs.py
```

Content addressing only pays off if it actually holds, so this re-hashes every
blob and checks it against its filename, then cross-checks each live row
against the file it references, then looks for blobs that no row references at
all. Three independent failure modes, checked separately: a blob can be
internally consistent while the row describing it is stale, and vice versa --
and an orphan is invisible to both of those checks *and* to the cleanup sweep,
which works from `files` and so has no row to find. Exit code is 1 on any
problem.

Run it after upgrading an instance that predates the pre-commit sanitising fix
(see "Content addressing is load-bearing" below).

### Live demo against a running server

```bash
# in one terminal
.venv\Scripts\python.exe -m scripts.dev

# in another
.venv\Scripts\python.exe -m scripts.demo
```

The demo uploads a generated PNG, prints every link type, confirms that a
tampered `purpose` returns 403 and a forced expiry returns 410, then prints the
`image_url` to open in a browser.

For a step-by-step hand-driven walkthrough, see `MANUAL_TESTING.md`.

### Cleanup sweep

```bash
.venv\Scripts\python.exe -m scripts.cleanup
```

Schedule this hourly. It performs these jobs in order:

1. **Scan whatever is queued.** A file is left `pending` when its upload died
   between inserting the row and scanning it — an interrupted request, a
   crashed worker. Nothing used to scan those: the sweep would mark them
   `error`, and `error` is not servable, so a perfectly clean file stayed
   permanently undownloadable while a working scanner sat idle. Rows younger
   than `SCAN_PICKUP_GRACE` (60s) are skipped, because an in-flight upload
   scans its own row and the two would otherwise race. Capped at
   `SCAN_PICKUP_BATCH` (100) per sweep.
2. **Release stale `pending` files** that job 1 could not resolve — a file
   stuck waiting on an unresponsive scanner is unservable forever with no error
   surfaced anywhere. This job is *skipped* when job 1 hit its batch cap:
   "did not get to it" is not "failed", and marking an unscanned row `error`
   would brick it. The next sweep continues where this one stopped.
3. Mark records past their retention window as deleted.
4. Reclaim blobs with no remaining live reference (after the grace period, with
   a re-check immediately before unlinking). A hash only loses its metadata row
   once its bytes are confirmed gone from disk. `delete_blob` reports whether
   the file *existed*, not whether the unlink *succeeded* — `_discard` swallows
   `OSError`, which is what a file held open by antivirus or a backup agent
   looks like. Purging the row anyway would discard the only record that the
   orphan exists, and since `find_orphan_blobs` works from `files`, nothing
   would ever retry: the disk stays consumed forever with no trace of why.
5. Remove orphaned upload fragments from the staging directory.

> **Orphaned bytes are invisible to the sweep.** Steps 4 and 5 both work from
> metadata. If a blob's row disappears by any route other than this sweep — a
> database restored from a snapshot, a manual `DELETE` — the bytes on disk are
> no longer discoverable and no sweep will ever reclaim them. To check, compare
> the blob directory against `SELECT DISTINCT sha256 FROM files` (see
> `scripts/verify_blobs.py`).

Job 1 is wrapped in a catch-all so a scanner failure cannot abort the sweep:
jobs 3–5 reclaim disk and must run even when `clamd` is unreachable. Job 2 is
then the fallback for exactly that case.

The one-line summary names each counter, so a sweep that is silently doing
nothing is visible rather than merely quiet:

```
cleanup: scan_resolved=0 scan_released=0 marked=2 blobs_removed=0 hashes_purged=0 tmp_removed=0
```

On Windows:

```
schtasks /create /tn "host-cleanup" /tr "D:\ImageAndTextHosting\.venv\Scripts\python.exe -m scripts.cleanup" /sc hourly
```

---

## Antivirus scanning (optional)

Off by default. When disabled, uploads are recorded as `skipped` and the
service behaves exactly as it did before the feature existed.

```bash
# .env
AV_BACKEND=clamd        # none | clamd | clamscan | stub
CLAMD_HOST=127.0.0.1
CLAMD_PORT=3310
# CLAMD_SOCKET=/var/run/clamav/clamd.ctl   # overrides host/port
AV_TIMEOUT=30.0
AV_PENDING_GRACE=900
# Only meaningful with AV_BACKEND=stub:
AV_STUB_MARKERS=MALWARE_MARKER
```

| Backend | Use |
|---|---|
| `none` | Scanning off (default). No dependency. |
| `clamd` | **Production.** Talks INSTREAM to a running daemon; signatures load once. |
| `clamscan` | Low-volume only. Loads signatures per invocation (seconds, hundreds of MB). |
| `stub` | Tests and dry runs. Matches on content markers. **No real protection.** |

`AV_STUB_MARKERS` is a comma-separated list of content substrings the stub
reports as infected. It exists so the complete upload → scan → gate path can be
exercised locally without ClamAV. Matching is on **file content**, not filename:
blobs are content-addressed, so the path handed to the scanner is the SHA-256
hash and never carries the original name.

### Scan states

| State | Served? | Meaning |
|---|---|---|
| `pending` | No → `409` | Queued; not yet scanned |
| `clean` | Yes | Cleared |
| `infected` | No → `403` | Malware found; verdict is final |
| `error` | No → `409` | Scanner failed to produce a verdict |
| `skipped` | Yes | Scanning disabled |

Two deliberate choices in those status codes:

- **`pending`/`error` return 409, not 403.** They are transient, so an
  automated caller should retry the same link rather than treat it as broken.
  Only `infected` is a permanent refusal.
- **Scanner failure never yields `clean`.** A `ScanError` is recorded as
  `error`. Silently treating "could not scan" as "safe" is precisely the
  failure that makes antivirus integration worthless.

### Verification

Three layers, each catching a different class of problem:

```bash
# 1. Unit + integration (in-process ASGI transport, no network)
.venv\Scripts\python.exe -m pytest -q

# 2. Smoke test -- full lifecycle over ASGI
.venv\Scripts\python.exe scripts/smoke_test.py

# 3. End-to-end over REAL HTTP against a running server
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8021
.venv\Scripts\python.exe scripts/e2e_local.py http://127.0.0.1:8021

# 4. Antivirus gate over real HTTP
AV_BACKEND=stub .venv\Scripts\python.exe -m uvicorn app.main:app --port 8022
AV_BACKEND=stub .venv\Scripts\python.exe scripts/av_e2e.py http://127.0.0.1:8022
```

`e2e_local.py` and `av_e2e.py` talk over TCP rather than ASGI, which is what
surfaces transport-level and host-environment problems that in-process tests
structurally cannot see. Both mint their own API key through the DB API, so no
manual setup is needed.

> **Note on returned URLs.** The links in an upload response are absolute and
> built from `BASE_URL`. If you run the server on a port other than the one in
> `.env`, the returned URLs point at the wrong port — that is configuration
> drift, not a defect. Both scripts retarget the host before fetching. Under
> nginx this does not arise: `BASE_URL` is the public origin.

`scan_demo.py` covers the same five gating rules as `av_e2e.py` but through the
in-process transport, so it runs without starting a server.

### Host-environment hazards

**Cleanup must never fail the request.** `storage._discard()` wraps every
temporary-file removal and swallows `BaseException`, not just `OSError`. This is
not defensive overkill: runtimes that intercept `pathlib.Path.unlink` to route
deletions through a trash/recycle-bin shim can raise `SystemExit` or
`KeyboardInterrupt`, which plain `except OSError` does not catch. Escaping that
exception replaced useful errors (`FileTooLarge`, `StorageFull`) and even
otherwise-successful duplicate uploads with an opaque 500. An undeletable
fragment is harmless — `sweep_tmp()` reclaims it later.

**A disabled scanner must not look like a working one.** `AV_BACKEND=stub`
without markers reports every file as `clean` while advertising itself as
active. `build_scanner()` now seeds the stub from `AV_STUB_MARKERS` and logs a
warning that the stub is a test double, not protection. The startup log always
states the antivirus posture; treat "scanning off" in production as a
deployment failure.

**In-process tests cannot see the host.** The ASGI transport bypasses real TCP
and, more importantly, is unaffected by process-wide monkeypatching of the
standard library. Two defects -- cleanup exceptions tearing down healthy
requests, and the silently inert scanner stub -- passed 166 in-process tests and
surfaced within seconds over real HTTP. Keep a real-HTTP layer in the suite;
it earns its keep more than additional unit tests do.

**An ambient proxy silently breaks the real-HTTP scripts.** `httpx` defaults to
`trust_env=True`, so it honours `HTTP_PROXY` / `HTTPS_PROXY`. On a machine that
sets a proxy without also setting `NO_PROXY` -- sandboxes and CI images
routinely do -- every `127.0.0.1` request in `demo.py`, `e2e_local.py` and
`av_e2e.py` is routed through that proxy instead of hitting the server. The
symptom is nasty because it is intermittent and misleading: the proxy forwards
fine most of the time, and when it hiccups the script dies with

```
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

on its very first call, which reads like a bug in the script or the server. It
was twice written off as "environmental noise" before the transport was
actually inspected -- `client._transport_for_url(...)._pool._proxy_url` showed
the connection was going to the proxy port, not to the server.

All three scripts now build their client with `trust_env=False`. Loopback
traffic should never be proxied. If you add another real-HTTP script, do the
same. `curl` is not a reliable control here: it also honours the proxy, so a
green `curl` does not prove the proxy is not in the path.

### Deployment notes

- **Resolve the scanner lazily.** Importing the app must never require ClamAV
  to be present — otherwise a scanned deployment cannot start before the daemon
  does.
- **An unreachable backend disables scanning rather than blocking startup**,
  and logs an error. Check the startup log: it reports the antivirus posture
  explicitly, so "scanning silently off" cannot go unnoticed.
- With `clamd`, put the socket on a local path and set `AV_TIMEOUT`
  conservatively; a wedged daemon must not hang the upload path.
- Scanning runs **synchronously within the upload request**. Uploads are
  infrequent relative to downloads, and the caller should never receive a link
  to a file whose safety is still unknown. For high upload volume, switch to
  `process_pending()` driven by a dedicated worker — the queue plumbing already
  exists, and the cleanup sweep already drains the queue hourly for the
  interrupted-upload case.

---

## API

All `/api/v1/*` routes require `Authorization: Bearer <api_key>`.

### Trying it in the browser (`/docs`)

Swagger UI at <http://127.0.0.1:8000/docs> is the fastest way to exercise the
API by hand. Ten minutes, end to end.

**1. Mint an API key.** Every `/api/v1/*` route needs one, and the plaintext is
shown exactly once:

`F1` → `Tasks: Run Task` → `maintenance: mint API key` → type a label.

The argument is a **label** -- any name you like, for your own bookkeeping. It
is not a key:

```
.venv\Scripts\python.exe -m scripts.mintkey dev
```

```
  key_id : key_xxxxxxxxxxxx
  api key: sk_<43 random characters, shown only here>
```

Copy the `sk_...` value. Each key is a separate identity with its own quota and
rate limit, and **every run mints a brand-new key** -- re-running with the same
label does not hand back the old one.

> **Passing a `sk_...` value as the label does nothing useful.** It creates yet
> another new key, merely *labelled* with that string. It does not import,
> recover or re-activate anything. If you have done this, the keys are harmless
> but unused; the plaintext is gone, so delete them (see *Rotating a leaked
> key*) and mint a fresh one properly.

> **Never paste a real key into a file others can read.** This README once
> carried a working key as "sample output" -- and it authenticated, so anyone
> who read the file got a usable credential. (This project is not a git
> repository yet, so nothing was ever committed; the exposure was the file
> itself and any copy of the folder -- backups, sync clients, archives.) Keys
> belong in `.env` (gitignored) or a password manager -- placeholders only in
> docs.

**2. Authorise the page.** Click **Authorize** at the top right of `/docs`,
paste **only the key** -- Swagger UI prepends `Bearer ` itself -- then
Authorize → Close. Every request from the page now carries the header.

> No **Authorize** button? The running server predates the change that declared
> the scheme as an `HTTPBearer` dependency. Restart it.

**3. Upload.** `POST /api/v1/files` → **Try it out** → set `file` to
`scratch/photo.png` → **Execute**. Expect `201`.

The response is the whole story:

| Field | What to do with it |
|---|---|
| `file_id` | the handle for every other call |
| `download_url` | signed; expires after `download_expires_in` seconds |
| `image_url` | permanent, unsigned, meant for embedding |
| `sha256`, `size_bytes` | verify the downloaded bytes against these |
| `deduplicated` | `true` when identical content was already stored |
| `scan_status` | `skipped` while `AV_BACKEND=none` |

> **A `201` is not proof that the file is still there.** The response is
> assembled from the record the server just wrote, so it looks perfectly
> healthy even if that record is about to disappear -- for example when
> `retain` was set so short that the cleanup sweep reclaims it moments later.
> Confirm with `GET /api/v1/files/{file_id}`: `200` means it persisted, `404`
> means it is already gone (deleted, or expired and swept). Do this before
> quoting a `file_id` from a response you did not just receive: a `201` left
> open in a browser tab stays on screen indefinitely and keeps looking valid
> long after the record it describes has stopped existing.

> **Leave `ttl` and `retain` empty on a first run.** They are optional, and
> both are easy to fill in with something that ruins the walkthrough:
>
> - `ttl` is the *download link* lifetime in seconds. Typing a small number --
>   `12`, say -- makes the link look broken: it still works for `ttl` plus
>   `CLOCK_SKEW` seconds (measured: `ttl=12` with `CLOCK_SKEW=5` returns `200`
>   until `exp+4s`, then `410 link expired`), so it expires while you are still
>   copying the URL out of the response. Omit it for the default hour.
> - `retain` is how long the *file* is kept. Omitting it keeps the file
>   indefinitely; setting it to `600` marks the record deleted ten minutes
>   later, so the file is gone when you come back to it.
>
> Each field also has a **Send empty value** checkbox. Ticking it for `ttl` or
> `retain` sends an empty string, which is not a valid integer, so the request
> comes back `422` with `loc: ["body","ttl"]`. That is correct validation, not a
> bug -- but if you see a 422, check those checkboxes first.

**4. Fetch both links.** Paste `download_url` into a new tab -- it downloads.
Paste `image_url` -- it renders inline. `image_url` is the one to put in
Markdown; it never expires.

**5. Get a ready-made embed.** `GET /api/v1/files/{file_id}/image` returns
`embedded_markdown` and `embedded_html` with the URL already substituted, plus
`width`, `height` and `format`.

**6. Re-issue a link.** `POST /api/v1/files/{file_id}/links` with
`{"ttl": 120}`.

> The field is `ttl`, **not** `ttl_seconds`. Unknown fields are ignored
> silently, so a typo here hands you the default hour instead of two minutes
> with no error at all.

**7. Break it on purpose.** The failure modes are the point:

| Try this | Expect | Why |
|---|---|---|
| `GET /api/v1/files` without Authorize | `401 missing Authorization header` | |
| Authorize with `sk_wrong` | `401 invalid api key` | |
| Change one character of `sig=` | `403 invalid signature` | |
| Change `p=dl` to `p=img` | `403` | `purpose` is inside the MAC |
| Rewrite `exp` to a past timestamp | `410 Gone` | expiry is checked first |
| Move a valid `sig` to another `file_id` | `403` | `file_id` is inside the MAC |

`410` versus `403` is deliberate: automation can tell "expired, request a new
link" apart from "you built this link wrong".

**8. Delete.** `DELETE /api/v1/files/{file_id}` returns
`{"deleted": true, ...}`. Both links return `404` immediately. The blob itself
is reclaimed later by the cleanup sweep, because other rows may share it.

> **An empty `SECRET_KEY` makes links die on every restart.** The autoreloader
> restarts the worker whenever you save a `.py` file, and with `SECRET_KEY=`
> empty a new signing key is generated each boot -- so a link you just
> generated returns `403 invalid signature` moments later, looking exactly like
> a signing bug. `.env` sets it for this reason; clear it and expect the churn.

### Rotating a leaked key

```bash
.venv\Scripts\python.exe -m scripts.keys                          # list
.venv\Scripts\python.exe -m scripts.keys disable key_abc123        # revoke
.venv\Scripts\python.exe -m scripts.keys disable --label "old laptop"
.venv\Scripts\python.exe -m scripts.keys enable  key_abc123
.venv\Scripts\python.exe -m scripts.keys purge   key_abc123        # only if unused
```

`disable` and `purge` are different on purpose:

| | Effect | Use for |
|---|---|---|
| `disable` | row kept, `enabled = 0`, requests get `401` | any key that has been used |
| `purge` | row deleted | keys that were **never** used |

`purge` refuses anything an audit entry references, because `audit_log` stores
`key_id` rather than the label -- deleting a used key would leave its own
history unattributable:

```
$ python -m scripts.keys purge key_xxxxxxxxxxxx
  kept:      key_xxxxxxxxxxxx  (12 audit row(s) reference it -- disable it instead)
```

That covers the keys nobody ever used -- a typo, a re-mint, or the
`sk_`-as-label mistake below -- which would otherwise clutter the listing
forever, with their plaintext unrecoverable anyway.

Revocation takes effect on the **next request** -- no restart. `lookup_api_key`
filters on `enabled = 1`, so there is nothing to reload:

```
$ curl -s -o /dev/null -w '%{http_code}\n' .../api/v1/files -H "Authorization: Bearer $K"
200
$ python -m scripts.keys disable key_xxxxxxxxxxxx
  disabled: key_xxxxxxxxxxxx
$ curl -s -o /dev/null -w '%{http_code}\n' .../api/v1/files -H "Authorization: Bearer $K"
401
```

The row survives with `enabled = 0` rather than being deleted, so the audit log
keeps resolving `key_id` to a label. Mint a replacement and re-Authorize
`/docs`.

A key that has leaked into a tracked file, a screenshot, or a chat log is
compromised even if it was "only" a development key -- it is a valid credential
for whatever instance is running.

> `mintkey` refuses a label starting with `sk_` for this reason: the argument
> is a name, not a key, and accepting one there silently mints a useless extra
> key. Override with `--force` if you really mean it.

### Upload

```http
POST /api/v1/files
Content-Type: multipart/form-data

file    (required)  the content
ttl     (optional)  download-link lifetime in seconds, default 3600
retain  (optional)  how long to keep the file; omit to keep indefinitely
name    (optional)  override the original filename
```

```json
{
  "file_id": "Vn8Kq2xR7mZp4LwT9bYc3A",
  "mime_type": "image/png",
  "size_bytes": 24819,
  "sha256": "a3f8c1e9...",
  "is_image": true,
  "download_url": "http://127.0.0.1:8000/d/Vn8Kq...?exp=1790003600&p=dl&sig=...",
  "download_expires_at": 1790003600,
  "download_expires_in": 3600,
  "image_url": "http://127.0.0.1:8000/i/Vn8Kq.../a3f8c1e9.webp",
  "deduplicated": false,
  "created_at": 1790000000
}
```

### Re-issue a download link

```http
POST /api/v1/files/{file_id}/links
{ "ttl": 3600 }
```

> This endpoint is authenticated **and** rate-limited on purpose. A caller
> holding an API key already has full access, so the signature does not restrict
> *the caller* -- it restricts *whoever the link is forwarded to*. An
> unauthenticated re-issue endpoint would let any holder of one expired link
> mint fresh ones forever, defeating expiry entirely.

### Get image display link

```http
GET /api/v1/files/{file_id}/image
```
Returns `image_url`, `embedded_markdown`, `embedded_html`, dimensions.
`415` if the file is not an image.

### Other

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/files/{id}` | metadata |
| `GET` | `/api/v1/files` | list; `uploader`, `limit`, `offset` |
| `DELETE` | `/api/v1/files/{id}` | soft delete |
| `GET` | `/api/v1/stats` | record and disk usage |

### Public access routes

```
GET /d/{file_id}?exp={unix}&p=dl&sig={sig}     time-limited download
GET /i/{file_id}/{sha8}.webp                   permanent image (thumbnail)
```

Status codes on `/d/` are chosen to be actionable by an automated caller:

| Code | Meaning | Caller action |
|---|---|---|
| `200` | ok | -- |
| `403` | signature invalid | do not retry; the URL is wrong or forged |
| `410` | link expired | request a fresh link via `POST /links` |
| `404` | file not found or deleted | surface an error |

---

## How expiry works

```
sign:   payload = file_id + "\n" + exp + "\n" + purpose
        sig     = HMAC-SHA256(secret, payload)

verify: 1. exp >= now - clock_skew ?   else 410
        2. compare_digest(sig, expected) else 403
        3. purpose and file_id bound into the signature
```

Three details carry most of the security weight:

1. **`purpose` is inside the signature.** Without it, an attacker takes an
   image URL (`p=img`), changes it to `p=dl`, and the signature still validates
   -- a free privilege escalation from "view" to "download original". Binding
   the parameter into the MAC closes that path.
2. **Newline separators, not bare concatenation.** `("a1","2")` and
   `("a12","")` concatenate identically; a delimiter removes the ambiguity.
3. **`hmac.compare_digest`, never `==`.** Python's `==` short-circuits, so
   comparison time leaks how many leading signature bytes were correct.

`SECRET_KEY` must be set to a stable value in production. Left empty, a random
key is generated per boot: safe by default (nothing can be forged), but every
restart invalidates live links. That failure mode is loud during development and
unacceptable in production.

---

## Deployment checklist

Ordered by how likely each item is to cause a real incident.

- [ ] **`SECRET_KEY` set to a fixed random value.** `python -c "import secrets;print(secrets.token_urlsafe(48))"`
- [ ] **Antivirus decision made explicitly.** Either set `AV_BACKEND=clamd` and
      confirm ClamAV is running, or accept that uploads are unscanned. Check the
      startup log — it states the posture either way. `stub` must never be used
      in production.
- [ ] **`DB_JOURNAL_MODE=WAL`** on Linux. Leave it at `TRUNCATE` on Windows
      volumes that cannot host WAL (see the journal-mode note above).
- [ ] **`location /_blobs/` contains `internal;`.** Without it the blob mount is
      internet-reachable and signature verification is bypassed entirely. This
      is the easiest critical mistake to make.
- [ ] **`SERVE_FILES_DIRECTLY=false`** so nginx serves bytes via `X-Accel-Redirect`.
- [ ] **App binds `127.0.0.1` only.** Binding `0.0.0.0` exposes the port directly,
      bypassing TLS, rate limits and the `internal` mount.
- [ ] **`client_max_body_size`** in nginx matches `MAX_FILE_SIZE`.
- [ ] **`systemd-timesyncd` healthy.** Signature checks depend on the clock; drift
      rejects every link.
- [ ] **Back up `blobs/` and `host.db` as a set.** A mismatch between them
      orphans blobs. Use `sqlite3 host.db ".backup ..."`, never `cp` -- copying a
      live SQLite file can yield a torn snapshot.
- [ ] **`data/` on a dedicated volume** so a full system disk cannot break the
      service. Uploads are refused above `DISK_HIGH_WATERMARK` (90%), because a
      full disk prevents SQLite commits and takes the whole service down.
- [ ] **Schedule `scripts/cleanup.py` hourly.**
- [ ] **Never log full signed URLs or API keys.** They are bearer credentials.

### Schema migrations

`db.init()` runs on startup and adds any missing columns before the schema
script executes. The order matters: the schema contains
`CREATE INDEX ... ON files(scan_status)`, and on a database predating that
column the index creation fails before an `ALTER TABLE` placed afterwards could
have added it. Migration therefore runs first.

Verified behaviour:

| Starting state | Result |
|---|---|
| Fresh database | No migration; schema created correct |
| Pre-`scan_status` database | Columns added, existing rows read as `clean`, no data loss |
| Already migrated | Idempotent, no-op |

Existing rows default to `clean` rather than `pending`, so upgrading does not
retroactively make previously served files unavailable.

### Why uploads are size-checked while streaming

`stream_to_blob()` enforces the limit inside the read loop rather than after
buffering. Reading first and checking afterwards lets one 10 GB request fill the
disk before being rejected. `Content-Length` is never trusted -- it is
attacker-controlled and absent under chunked encoding.

### Content addressing is load-bearing

A blob's filename *is* the SHA-256 of its content, and three properties depend
on that holding without exception:

- **Deduplication** -- an upload is a duplicate iff its digest already exists.
- **Integrity** -- re-hashing detects corruption or a partial write.
- **Unguessable paths** -- the digest is the random string; no separate
  capability token is needed.

Any content transform must therefore run **before** the blob is hashed and
committed. `stream_to_blob()` takes an optional `sanitize` hook for exactly
this: `strip_exif` is passed as that hook, so the stored bytes are the ones the
filename describes.

This was a real defect. An earlier revision stripped EXIF *after* the commit,
which rewrote a file that had already been named for the pre-strip digest. The
consequences were client-visible:

| | Reported | Actually served |
|---|---|---|
| `size_bytes` | 910 | 822 |
| `sha256` | `c0ac2ab0…` | `c2089a25…` |

A client verifying its download against the returned `sha256` saw a false
corruption report on every JPEG or TIFF carrying EXIF. The bug survived 166
green tests because the existing EXIF test resolved the blob via
`blob_path(response["sha256"])` -- a path that exists either way -- and only
asserted GPS was gone. It never compared content against its digest.

`scripts/verify_blobs.py` detects the signature in existing data (rows whose
`size_bytes` exceeds the file on disk). Re-uploading those files fixes them;
`scripts/cleanup.py` reclaims the orphaned blobs.

A sanitizer that raises is logged and ignored, leaving the original bytes in
place: losing an upload is worse than storing unsanitised content, and the
router decides the policy for its own domain.

### Why deletion is not immediate

Content addressing means several uploads can share one blob, so `DELETE` only
sets `deleted_at`. Reclamation runs through `db.find_orphan_blobs()`, then
**re-checks `is_hash_referenced()` immediately before unlinking** -- a concurrent
upload may have re-referenced the same content in between. Deleting a blob that
is still live destroys data that no backup can distinguish from a missing file.

---

## Known limits

Appropriate for a single-instance deployment at roughly 10k uploads/day and a
few hundred GB. Not suitable as-is for multi-node, CDN distribution, files over
1 GB, or more than ~1M requests/day -- SQLite's single-writer model and local
disk become the constraint.

Not yet implemented, listed in the order they should be added:

1. **Resumable uploads** -- needs the S3 multipart protocol.
2. **Multi-instance** -- move metadata to PostgreSQL and blobs to S3/MinIO.
   Note that `find_orphan_blobs()` relies on a single writer; a multi-node
   setup needs a distributed lock or a coordinated sweeper.
3. **CDN** -- serve `/i/` from an edge cache; the `sha8` path segment already
   makes URLs content-versioned and safe to cache permanently.
4. **Async scan queue** -- `scanservice.process_pending()` is wired into the
   cleanup sweep, which drains the queue once an hour. That is enough for the
   current volume; a dedicated worker (or a shorter interval) is the next step
   when uploads become frequent enough that an hour of `pending` is too long.

`python-magic` was also skipped in favour of built-in magic-byte checks to avoid
requiring the native `libmagic` DLL on Windows.

### Antivirus caveat

Scanning is implemented but **off by default**. With `AV_BACKEND=none`, uploads
are not inspected for malware at all. Enable a real backend before exposing the
service to untrusted callers. The `stub` backend provides no protection and must
never be used in production.
