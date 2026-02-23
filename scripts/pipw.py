import os
import sys
from pathlib import Path


def _is_existing_file(p: str | None) -> bool:
    if not p:
        return False
    try:
        return Path(p).is_file()
    except Exception:
        return False


def _certifi_where() -> str | None:
    try:
        from pip._vendor import certifi as pip_certifi

        return pip_certifi.where()
    except Exception:
        return None


def _ensure_tls_ca_bundle() -> None:
    ca_path = _certifi_where()
    if not ca_path:
        return

    ssl_cert_file = os.environ.get("SSL_CERT_FILE")
    requests_ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    pip_cert = os.environ.get("PIP_CERT")

    if ssl_cert_file and not _is_existing_file(ssl_cert_file):
        os.environ["SSL_CERT_FILE"] = ca_path
    else:
        os.environ.setdefault("SSL_CERT_FILE", ca_path)

    if requests_ca_bundle and not _is_existing_file(requests_ca_bundle):
        os.environ["REQUESTS_CA_BUNDLE"] = ca_path
    else:
        os.environ.setdefault("REQUESTS_CA_BUNDLE", ca_path)

    if pip_cert and not _is_existing_file(pip_cert):
        os.environ["PIP_CERT"] = ca_path
    else:
        os.environ.setdefault("PIP_CERT", ca_path)


def main() -> int:
    _ensure_tls_ca_bundle()
    from pip._internal.cli.main import main as pip_main

    return int(pip_main(args=sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())

