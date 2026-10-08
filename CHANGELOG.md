# Changelog

## 1.1.0 — 2026-10-07 — design 1b "Cards"

Visual redesign of the panel to the Unknown Cyber brand handoff (dark "ink" surfaces, rounded cards).
Behaviour, signals, API calls and threading are unchanged.

- `ui/brand.py`: tokens, scoped `#ucPanel` stylesheet, `FlowLayout`, `RowDelegate` / `BarDelegate`,
  `Meter`, shield assets under `res/`. On by default; *Settings ▸ Appearance* offers `brand` /
  `auto` (dark host themes only) / `plain`, and `UNKNOWNCYBER_BRAND=0/1` overrides it.
- Header card: shield logo, file name + `md5 · x86 · PE` subline, status pill, **version chips**
  (newest 3 + `+N ▾` menu) replacing the combobox, `✓ Matches … exactly` hint, gradient
  **Upload…** button with `⟳ / Dashboard ↗ / ⚙` secondaries, upload strip with gradient progress.
- Stats strip (procedures · with matches · annotated), filter row with the `◉ Following cursor`
  toggle, procedure list with Address · Name · occurrence bar · Occurrences (thousands separator),
  hidden header, 25 px rows, cyan selection edge, `Sort by ▸` context menu; other columns moved to
  the row tooltip.
- Inspector card: title row (`name` + monospace address, Jump / Rename links), **tag chip row** with
  `+ tag` and right-click *Remove tag* (replaces the Tags tab), tabs `Overview · Notes N · Similar N ·
  Group`, similarity bars, note cards.
- Dialogs: upload option cards, settings sections (CONNECTION / BEHAVIOUR) with outlined
  *Test connection*, compare dialog overlap meter, branded banners and editors.
- Not-configured state: centred shield + *Connect to Unknown Cyber* + primary *Open settings*.

## 1.0.1 — 2026-10-07

- The panel opens automatically whenever a database is opened, docked to the right of the
  disassembly view and focused. Setting *Panel ▸ Open the panel automatically* / `UNKNOWNCYBER_AUTO_OPEN=0` turns it off;
  Ctrl-Shift-A still opens or focuses it.
- CA bundle resolution: setting → `UNKNOWNCYBER_CA_BUNDLE` → `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE` →
  OS trust store → `certifi`. A `UNKNOWNCYBER_CA_BUNDLE` that points at a missing file is ignored
  with a warning instead of breaking every request.
- Docker: secret-safe `docker/Dockerfile` (installer password via BuildKit secret, deps in IDA's
  interpreter, plugin in `/opt/ida/plugins`, `UNKNOWNCYBER_CA_BUNDLE` defaulted to
  `/etc/unknowncyber/ssl/unknowncyber-ca.crt`), `docker/compose.yml`, `just docker-build`.

## 1.0.0 — 2026-10-07

Complete rewrite for IDA 8.3 and 9.x (PyQt5 and PySide6). Not backwards compatible with the `idamagic` package.

### Security
- API key is sent only in the `X-API-KEY` header (previously a `?key=` query parameter).
- TLS certificate verification is on by default; optional CA bundle for self-hosted systems.
- Credentials come from `UNKNOWNCYBER_API_KEY`, the OS credential store (`keyring`) or an
  owner-only file in the IDA user directory. No `.env` inside the plugin directory.
- One API client with a validated host; identifiers are validated before any request.
- Disassembly export and IDB upload use private temporary directories that are removed afterwards.

### Behaviour
- Disassembly export runs inside an IDA undo point and leaves the database unchanged.
- All network calls run off the UI thread with timeouts; uploads show progress and status is polled
  automatically.
- New UI: header with analysis-version selector, filterable procedure table synchronised with the
  cursor, inspector with notes/tags/similar/group views, diff-highlighted procedure comparison,
  settings dialog with connection test.

### Packaging
- `requirements.txt` / `requirements-dev.txt`, `pyproject.toml` (ruff), headless smoke tests,
  CI that lints and tests on every push.
- Dropped dependencies: networkx (direct), python-dotenv. Qt binding chosen at import time (PySide6 or PyQt5); both covered by the test suite.
