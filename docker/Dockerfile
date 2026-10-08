# syntax=docker/dockerfile:1.7
#
# IDA Pro 8.3 image with the Unknown Cyber plugin baked in.
#
# Build (the installer password is a BuildKit secret: it is never stored in a
# layer or in `docker history`):
#
#   IDA_PASSWORD='…' docker buildx build \
#       --secret id=ida_password,env=IDA_PASSWORD \
#       --build-arg IDA_KEYLESS=1 \
#       -t <registry>/unknowncyber/ida:1.0.0 -f docker/Dockerfile .
#
# Expects the IDA installer at idasetup/ida.run (bind-mounted at build time,
# not copied into the image).  See README.md § Docker.

ARG BASE_IMAGE=virusbattleacr.azurecr.io/unknowncyber/base:3.11.16
FROM ${BASE_IMAGE} AS ida

ARG IDA_PREFIX=/opt/ida
# libpython IDA links against; must match the base image's interpreter.
ARG PYTHON_LIB=/usr/local/lib/libpython3.11.so
# Set to any non-empty value to strip ida.key from the image (license is
# mounted at runtime via $IDA_DIR -> ~/.idapro instead).
ARG IDA_KEYLESS=""
ARG APP_USER=unknowncyber

USER root

# Runtime libraries IDA links against: Qt/X11 for the GUI and libsecret
# (ida64 itself needs libsecret-1.so.0 for its credential storage).
RUN set -eu \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libsecret-1-0 \
        libdbus-1-3 libgl1 libglu1 libglx-mesa0 libxkbcommon-x11-0 \
        libxcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
        libxcb-render0 libxcb-render-util0 libxcb-shape0 libxcb-shm0 \
        libxcb-xfixes0 libxcb-xinerama0 libxcb-xkb1 \
    && rm -rf /var/lib/apt/lists/*

# IDA itself.  No `set -x` here: it would echo the password into the build log.
RUN --mount=type=bind,source=idasetup/ida.run,target=/tmp/idasetup/ida.run \
    --mount=type=secret,id=ida_password,required=true \
    set -eu \
    && /tmp/idasetup/ida.run --mode unattended --prefix "${IDA_PREFIX}" \
        --installpassword "$(cat /run/secrets/ida_password)" \
    && "${IDA_PREFIX}/idapyswitch" --force-path "${PYTHON_LIB}" \
    && if [ -n "${IDA_KEYLESS}" ]; then rm -f "${IDA_PREFIX}/ida.key"; fi \
    && if ldd "${IDA_PREFIX}/ida64" | grep -q "not found"; then \
           echo "ida64 has unresolved shared libraries:"; ldd "${IDA_PREFIX}/ida64" | grep "not found"; exit 1; fi

# Plugin dependencies, installed into the *same* interpreter idapyswitch
# selected above (system site-packages, so they are visible regardless of
# which directory is bind-mounted over the home directory at runtime).
# PyQt5 is deliberately not installed with pip: IDA ships its own copy under
# $IDA_PREFIX/python/3/PyQt5 and puts it on sys.path at start-up.
COPY requirements.txt /tmp/unknowncyber-requirements.txt
RUN set -eu \
    && python3 -m pip install --no-cache-dir --disable-pip-version-check \
        -r /tmp/unknowncyber-requirements.txt "sark==8.2.1" \
    && rm /tmp/unknowncyber-requirements.txt \
    && python3 -c "import cythereal_magic, sark; print('plugin deps ok')" \
    && test -d "${IDA_PREFIX}/python/3/PyQt5"

# The plugin goes into IDA's own plugins directory, which IDA scans at start-up
# and which is NOT shadowed by the runtime ~/.idapro mount (license + state).
# Only the plugin's own two entries are copied, so leftovers from the previous
# plugin in a checkout (magic_plugin_entry.py, idamagic/) can never ride along.
COPY --chown=${APP_USER}:${APP_USER} plugins/unknowncyber_plugin.py ${IDA_PREFIX}/plugins/
COPY --chown=${APP_USER}:${APP_USER} plugins/unknowncyber/ ${IDA_PREFIX}/plugins/unknowncyber/
RUN find "${IDA_PREFIX}/plugins" -name "__pycache__" -type d -prune -exec rm -rf {} + \
    && test -f "${IDA_PREFIX}/plugins/unknowncyber_plugin.py" \
    && ! test -e "${IDA_PREFIX}/plugins/magic_plugin_entry.py" \
    && ! test -e "${IDA_PREFIX}/plugins/idamagic"

# Default CA bundle for self-hosted systems: mount the CA's public certificate
# at this path and the plugin verifies against it.  If nothing is mounted the
# plugin ignores the variable and uses the public roots, so SaaS users are fine.
ENV UNKNOWNCYBER_CA_BUNDLE=/etc/unknowncyber/ssl/unknowncyber-ca.crt

USER ${APP_USER}
# Runtime configuration (never bake these in):
#   -e UNKNOWNCYBER_API_KEY=…   -e UNKNOWNCYBER_API_HOST=…
#   -v ./certs:/etc/unknowncyber/ssl:ro
ENTRYPOINT ["/opt/ida/ida64"]
