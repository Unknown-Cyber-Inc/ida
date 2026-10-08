# Unknown Cyber IDA plugin

Integrates IDA Pro with the Unknown Cyber MAGIC platform:

- Upload the original binary, a copy of the IDB, or a disassembly export of the open database.
- Browse the procedures MAGIC extracted for any analysis version of the file, synchronised with
  IDA's cursor (click a row to jump; move in IDA to select).
- Add notes and tags to files, procedures and procedure groups.
- Explore similar files and similar procedures across your corpus and compare procedure code side
  by side with diff highlighting.

## Requirements

| Component | Version |
| --- | --- |
| IDA Pro | **8.3** (PyQt5) and **9.x** (9.0/9.1 PyQt5, 9.2+ PySide6). The same package runs on both; `unknowncyber/qt.py` picks the Qt binding at import time and the test suite runs under both. |
| Python | the interpreter IDA uses, 3.8+ |
| Unknown Cyber | an API key for `https://api.magic.unknowncyber.com` or a self-hosted MAGIC system |

## Install

1. Download `unknowncyberidaplugin-<version>.zip` (or `.tgz`) from a release and verify it against
   `checksum`.
2. Install the Python dependencies **with the interpreter IDA uses**:

   ```sh
   python3 -m pip install -r requirements.txt
   ```

   `sark` is only needed for disassembly export — use `sark==8.2.1` on IDA 8.3 and `sark>=9.0` on
   IDA 9.x (see the comment in `requirements.txt`). `keyring` is optional and lets the plugin keep
   the API key in your OS credential store.
3. Copy the *contents* of `plugins/` into your IDA plugins directory:
   - Linux/macOS: `~/.idapro/plugins/`
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`

   You should end up with `plugins/unknowncyber_plugin.py` and `plugins/unknowncyber/`.
4. Start IDA and open a database: the panel opens automatically, docked to the right of the
   disassembly view and focused (turn this off in the settings dialog or with
   `UNKNOWNCYBER_AUTO_OPEN=0`). Drag the tab to re-arrange; IDA remembers the layout in the IDB. **Ctrl-Shift-A** or
   **Edit ▸ Plugins ▸ Unknown Cyber** opens or focuses it at any time.
5. Click the gear icon, enter the API host and your API key and press **Test connection**.

### Where the key is stored

- Preferred: the `UNKNOWNCYBER_API_KEY` environment variable.
- Otherwise the OS credential store through `keyring` (macOS Keychain, Windows Credential Manager,
  Secret Service on Linux).
- Fallback: `<IDA user dir>/unknowncyber.key` with owner-only permissions; the settings dialog says
  which backend is active.
- Non-secret settings live in `<IDA user dir>/unknowncyber.json`.

Other environment overrides: `UNKNOWNCYBER_API_HOST`, `UNKNOWNCYBER_CA_BUNDLE` (PEM bundle for a
self-hosted CA), `UNKNOWNCYBER_INSECURE_TLS=1` (disables certificate verification; not recommended),
`UNKNOWNCYBER_LOGLEVEL`.

### Self-hosted systems with a private CA

Certificate verification uses, in order: the *CA bundle* setting, `UNKNOWNCYBER_CA_BUNDLE`,
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE`, the operating system's trust store
(`/etc/ssl/certs/ca-certificates.crt` on Debian/Ubuntu, i.e. whatever `update-ca-certificates`
maintains), and only then the public roots bundled with `certifi`. So either point the setting at
your CA's PEM, or install the CA system-wide — both keep "Verify TLS certificates" on.

## Look and feel (design 1b "Cards")

The panel uses the Unknown Cyber brand surfaces by default: ink background, rounded cards,
version chips, stats tiles, occurrence/similarity bars and tag chips (`plugins/unknowncyber/ui/brand.py`,
assets in `plugins/unknowncyber/res/`). Every rule is scoped to the panel (`#ucPanel`), so IDA's own
widgets are untouched. *Settings ▸ Appearance* switches between **Unknown Cyber brand** (default, regardless of the host theme),
**Match the host theme** (ink look on dark themes only) and **Plain host widgets**; it takes effect the
next time the panel is opened. `UNKNOWNCYBER_BRAND=0/1` overrides the setting for troubleshooting.

## Disassembly export

"Upload ▸ Disassembly export" needs the original binary next to the IDB (its sha1/sha512 are part of
the upload) and the `sark` package. The export temporarily rebases the database to 0, normalises
operand display and optionally creates functions for unclaimed `push ebp / mov ebp, esp` prologues;
all of that happens inside an IDA undo point that is reverted automatically when the export finishes,
so the database is left exactly as it was. The archive is built in a private temporary directory
and deleted after the upload.

## Development

```sh
pip install -r requirements-dev.txt
just lint      # ruff
just test      # headless Qt smoke test with stubbed IDA modules (tests/stubs)
just dist      # release archives + checksum
```

`tests/test_ui_smoke.py` builds the whole panel against a fake API client, so UI changes can be
checked without IDA. Run it under both bindings before a release:

```sh
QT_QPA_PLATFORM=offscreen python -m pytest -q tests                              # PySide6 (IDA 9.2+)
UNKNOWNCYBER_QT_BINDING=PyQt5 QT_QPA_PLATFORM=offscreen python -m pytest -q tests  # PyQt5 (IDA 8.3 / 9.0 / 9.1)
```

IDA-API differences between 8.x and 9.x are isolated in `idb.py` and `exporter/prolog.py`
(`inf_*` getters with `get_inf_structure()` fallbacks). Package layout:

```
plugins/
  unknowncyber_plugin.py      IDA entry point (PLUGIN_ENTRY)
  unknowncyber/
    __init__.py               plugin_t, hotkey, desktop restore hook
    qt.py                     PySide6 (IDA 9.2+) / PyQt5 (IDA 8.3-9.1) shim
    config.py                 settings + credential storage
    client.py                 typed, validated API facade (TLS on, timeouts, no key in URLs)
    models.py                 dataclasses shared by client and UI
    workers.py                background execution, main-thread helpers
    idb.py                    read-only database helpers, cursor hook
    exporter/                 disassembly export (undo point, temp dir)
    ui/                       panel, inspector, dialogs
```

## Docker (plugin baked into an IDA image)

`docker/Dockerfile` builds an IDA 8.3 image with the plugin in `/opt/ida/plugins` and its
dependencies in the interpreter `idapyswitch` selects, replacing the old image recipe (which kept
the installer password in image history and shipped a `.env` with an API key).

```sh
mkdir -p idasetup && cp /path/to/ida.run idasetup/ida.run      # git-ignored, bind-mounted at build time
export IDA_PASSWORD='<installer password>'                      # BuildKit secret, not an ARG
just docker-build 1.0.0                                         # -> virusbattleacr.azurecr.io/unknowncyber/ida:1.0.0
# equivalent to:
# docker buildx build --secret id=ida_password,env=IDA_PASSWORD --build-arg IDA_KEYLESS=1 \
#     -t virusbattleacr.azurecr.io/unknowncyber/ida:1.0.0 -f docker/Dockerfile .
```

Build arguments: `BASE_IMAGE` (default `…/unknowncyber/base:3.11.16`), `PYTHON_LIB` (the
`libpython` IDA should link; must match the base image), `IDA_KEYLESS` (non-empty strips
`ida.key` so the license is mounted at runtime), `IDA_PREFIX`.

Run it with your license directory mounted over `~/.idapro` and credentials from the environment
(`docker/compose.yml` is a starting point):

```sh
IDA_DIR=~/.idapro UNKNOWNCYBER_API_KEY=… docker compose -f docker/compose.yml run --rm ida /samples/x.exe
```

**Private CA (self-hosted system):** the image sets
`UNKNOWNCYBER_CA_BUNDLE=/etc/unknowncyber/ssl/unknowncyber-ca.crt`; mount your CA's public
certificate there (`compose.yml` does) and the plugin verifies against it. When the file is not
mounted the variable is ignored and the public roots are used, so the same image works against
the SaaS. Change the default with `-e UNKNOWNCYBER_CA_BUNDLE=…` or in the Dockerfile.

Because the plugin lives in `/opt/ida/plugins`, the `~/.idapro` mount does not hide it; because the
Python packages are in system site-packages, no `~/.local` is needed. Remove any copy of the old
plugin (`magic_plugin_entry.py`, `idamagic/`) from the mounted `~/.idapro/plugins`, otherwise IDA
loads both and the old one fails at import.
