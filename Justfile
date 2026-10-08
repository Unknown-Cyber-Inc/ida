# vim: set ft=just:
set shell := ["bash", "-euo", "pipefail", "-c"]

VERSION := "1.1.0"

@default:
    just --list

# Lint and format-check
lint:
    python3 -m ruff check plugins tests
    python3 -m ruff format --check plugins tests

# Run the headless UI smoke tests (needs requirements-dev.txt)
test:
    QT_QPA_PLATFORM=offscreen python3 -m pytest -q tests
    UNKNOWNCYBER_QT_BINDING=PyQt5 QT_QPA_PLATFORM=offscreen python3 -m pytest -q tests

# Build the IDA docker image with the plugin baked in (needs idasetup/ida.run and $IDA_PASSWORD)
docker-build TAG=VERSION IMAGE="virusbattleacr.azurecr.io/unknowncyber/ida":
    test -f idasetup/ida.run || { echo "put the IDA installer at idasetup/ida.run"; exit 1; }
    test -n "${IDA_PASSWORD:-}" || { echo "export IDA_PASSWORD first (it is passed as a BuildKit secret)"; exit 1; }
    docker buildx build --secret id=ida_password,env=IDA_PASSWORD --build-arg IDA_KEYLESS=${IDA_KEYLESS:-1} \
        -t {{IMAGE}}:{{TAG}} -f docker/Dockerfile .

# Build the release archive: plugins/ + requirements + docs
dist:
    rm -rf dist && mkdir -p dist
    cp -r plugins requirements.txt README.md dist/
    find dist -name "__pycache__" -type d -prune -exec rm -rf {} +
    (cd dist && zip -qr ../unknowncyberidaplugin-{{VERSION}}.zip . && tar czf ../unknowncyberidaplugin-{{VERSION}}.tgz .)
    sha256sum unknowncyberidaplugin-{{VERSION}}.* > checksum
