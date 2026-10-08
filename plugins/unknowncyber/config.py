"""Persistent plugin settings and credential storage.

Resolution order (first wins)
-----------------------------
1. Environment variables ``UNKNOWNCYBER_API_HOST``, ``UNKNOWNCYBER_API_KEY``,
   ``UNKNOWNCYBER_CA_BUNDLE``, ``UNKNOWNCYBER_INSECURE_TLS``.
2. The settings file ``<IDA user dir>/unknowncyber.json`` (host, TLS options,
   UI preferences).
3. The API key is stored in the OS credential store through the optional
   ``keyring`` package.  When ``keyring`` is unavailable the key is written to
   ``<IDA user dir>/unknowncyber.key`` with ``0600`` permissions and the UI
   shows a warning.

Nothing in this module imports Qt or IDA GUI code, so it is unit-testable.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import stat
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

_log = logging.getLogger(__name__)

DEFAULT_HOST = "https://api.magic.unknowncyber.com"
KEYRING_SERVICE = "unknowncyber-ida-plugin"
SETTINGS_FILE = "unknowncyber.json"
KEY_FILE = "unknowncyber.key"


@dataclasses.dataclass
class Settings:
    api_host: str = DEFAULT_HOST
    verify_tls: bool = True
    ca_bundle: str = ""
    dashboard_url: str = ""
    auto_poll_seconds: int = 20
    create_missing_functions: bool = True
    auto_open: bool = True  # open the panel whenever a database is opened
    log_level: str = "INFO"
    appearance: str = "brand"  # brand | auto | plain (see ui/brand.py)

    # Not persisted to the JSON file, see ``store_api_key``.
    api_key: str = dataclasses.field(default="", repr=False, compare=False)

    # -- derived -----------------------------------------------------------
    @property
    def api_base_url(self) -> str:
        """Host with a single ``/v2`` suffix, as the SDK expects."""
        return normalize_host(self.api_host)

    @property
    def dashboard_base_url(self) -> str:
        if self.dashboard_url.strip():
            return self.dashboard_url.strip().rstrip("/")
        parsed = urlparse(self.api_base_url)
        host = parsed.netloc
        if host.startswith("api."):
            host = host[4:]
        return f"{parsed.scheme}://{host}"

    @property
    def is_configured(self) -> bool:
        return bool(self.api_host.strip()) and bool(self.api_key)


def normalize_host(host: str) -> str:
    """``https://x`` / ``https://x/`` / ``https://x/v2/`` all become ``https://x/v2``."""
    host = (host or "").strip().rstrip("/")
    if not host:
        return ""
    if "://" not in host:
        host = "https://" + host
    if host.endswith("/v2"):
        return host
    return host + "/v2"


def validate_host(host: str) -> Optional[str]:
    """Return an error message when *host* is not an acceptable base URL."""
    if not host.strip():
        return "API host is required."
    parsed = urlparse(normalize_host(host))
    if parsed.scheme not in ("https", "http"):
        return "API host must start with https://"
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
        return "Plain http:// is only allowed for localhost."
    if not parsed.hostname:
        return "API host is not a valid URL."
    return None


# Debian/Ubuntu (incl. the IDA docker image), RHEL/Fedora, Alpine, macOS/Homebrew.
SYSTEM_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
)


def effective_ca_bundle(settings: "Settings") -> Optional[str]:
    """The CA bundle the HTTP client should verify against.

    Order: the configured bundle, then ``SSL_CERT_FILE`` / ``REQUESTS_CA_BUNDLE``,
    then the operating system's bundle (which is what ``update-ca-certificates``
    maintains, so a private CA installed there is honoured), and finally ``None``,
    which makes the SDK fall back to ``certifi``'s public roots.
    """
    if settings.ca_bundle.strip():
        return settings.ca_bundle.strip()
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        value = os.environ.get(var)
        if value and os.path.isfile(value):
            return value
    for path in SYSTEM_CA_BUNDLES:
        if os.path.isfile(path):
            return path
    return None


# --------------------------------------------------------------------------
# Storage locations
# --------------------------------------------------------------------------


def user_dir() -> Path:
    """IDA's per-user directory, or ``~/.idapro`` when running outside IDA."""
    try:
        import ida_diskio  # type: ignore

        return Path(ida_diskio.get_user_idadir())
    except Exception:  # noqa: BLE001 - not inside IDA
        override = os.environ.get("UNKNOWNCYBER_CONFIG_DIR")
        return Path(override) if override else Path.home() / ".idapro"


def settings_path() -> Path:
    return user_dir() / SETTINGS_FILE


def key_file_path() -> Path:
    return user_dir() / KEY_FILE


# --------------------------------------------------------------------------
# Load / save
# --------------------------------------------------------------------------


def load() -> Settings:
    settings = Settings()
    path = settings_path()
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            for field in dataclasses.fields(Settings):
                if field.name == "api_key" or field.name not in data:
                    continue
                value = data[field.name]
                # Only accept values of the same type as the default (bool/int/str).
                if type(value) is type(field.default):
                    setattr(settings, field.name, value)
    except (OSError, ValueError) as exc:
        _log.warning("could not read %s: %s", path, exc)

    env_host = os.environ.get("UNKNOWNCYBER_API_HOST")
    if env_host:
        settings.api_host = env_host
    env_ca = os.environ.get("UNKNOWNCYBER_CA_BUNDLE")
    if env_ca:
        # A default that may legitimately be absent (e.g. a SaaS user running an image
        # that ships the variable): only apply it when the file is actually there.
        if os.path.isfile(env_ca):
            settings.ca_bundle = env_ca
        else:
            _log.warning("UNKNOWNCYBER_CA_BUNDLE=%s does not exist; ignoring it", env_ca)
    if os.environ.get("UNKNOWNCYBER_INSECURE_TLS", "").lower() in ("1", "true", "yes"):
        settings.verify_tls = False
    env_auto_open = os.environ.get("UNKNOWNCYBER_AUTO_OPEN")
    if env_auto_open:
        settings.auto_open = env_auto_open.lower() in ("1", "true", "yes")

    settings.api_key = os.environ.get("UNKNOWNCYBER_API_KEY") or load_api_key(settings.api_host) or ""
    return settings


def save(settings: Settings) -> None:
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {f.name: getattr(settings, f.name) for f in dataclasses.fields(Settings) if f.name != "api_key"}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# API key storage
# --------------------------------------------------------------------------


def key_storage_backend() -> str:
    """``"keyring"`` when an OS credential store is usable, else ``"file"``."""
    if os.environ.get("UNKNOWNCYBER_API_KEY"):
        return "environment"
    try:
        import keyring  # type: ignore
        from keyring.errors import NoKeyringError  # type: ignore

        try:
            backend = keyring.get_keyring()
            # keyring's "fail" backend raises on every call; detect it early.
            if backend.__class__.__module__.startswith("keyring.backends.fail"):
                return "file"
        except NoKeyringError:
            return "file"
        return "keyring"
    except Exception:  # noqa: BLE001
        return "file"


def _keyring_username(host: str) -> str:
    return normalize_host(host) or "default"


def load_api_key(host: str) -> Optional[str]:
    if key_storage_backend() == "keyring":
        try:
            import keyring  # type: ignore

            value = keyring.get_password(KEYRING_SERVICE, _keyring_username(host))
            if value:
                return value
        except Exception as exc:  # noqa: BLE001
            _log.warning("keyring lookup failed: %s", exc)
    path = key_file_path()
    try:
        if path.is_file():
            return path.read_text(encoding="utf-8").strip() or None
    except OSError as exc:
        _log.warning("could not read %s: %s", path, exc)
    return None


def store_api_key(host: str, api_key: str) -> str:
    """Persist *api_key* and return the backend that was used."""
    api_key = api_key.strip()
    backend = key_storage_backend()
    if backend == "keyring":
        try:
            import keyring  # type: ignore

            if api_key:
                keyring.set_password(KEYRING_SERVICE, _keyring_username(host), api_key)
            else:
                try:
                    keyring.delete_password(KEYRING_SERVICE, _keyring_username(host))
                except Exception:  # noqa: BLE001
                    pass
            _remove_key_file()
            return "keyring"
        except Exception as exc:  # noqa: BLE001
            _log.warning("keyring write failed (%s); falling back to file storage", exc)
    _write_key_file(api_key)
    return "file"


def _write_key_file(api_key: str) -> None:
    path = key_file_path()
    if not api_key:
        _remove_key_file()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(api_key + "\n")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def _remove_key_file() -> None:
    try:
        key_file_path().unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        _log.warning("could not remove key file: %s", exc)
