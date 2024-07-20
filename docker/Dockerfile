FROM virusbattleacr.azurecr.io/unknowncyber/base AS ida
ARG IDA_PASSWORD
ARG IDA_KEYLESS
ENV QT_DEBUG_PLUGINS=1

USER root
RUN set -x \
    && apt update \
    && apt install -y --no-install-recommends \
        libsecret-1-0 \
        libsecret-1-dev \
        libxkbcommon-x11-0 \
        libdbus-1-3 \
        libxcb-xinerama0 \
        libxcb-icccm4 \
        libxcb-image0 \
        libxcb-keysyms1 \
        libxcb-render-util0 \
        libxcb-randr0 \
        libxcb-shape0 \
        libglu1 \
        libgl1-mesa-glx \
        libxcb1 \
        libxcb-render0 \
        libxcb-shm0 \
        libxcb-xfixes0 \
        libxcb-xkb1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt -y autoremove

COPY --chown=unknowncyber plugins /home/unknowncyber/.idapro/plugins

COPY --chown=unknowncyber setup.cfg pyproject.toml .
RUN set -x \
    && apt update \
    && apt install -y --no-install-recommends \
        git \
    && mkdir -m 777 plugins \
    && runuser -l unknowncyber -c 'python -m pip install --user --disable-pip-version-check --no-cache-dir .[dev]' \
    && rm -rf plugins setup.cfg pyproject.toml build /var/lib/apt/lists/* \
    && apt -y remove git \
    && apt -y autoremove

RUN --mount=type=bind,source=idasetup/ida.run,target=/tmp/idasetup/ida.run set -x \
    && /tmp/idasetup/ida.run --mode unattended --prefix /opt/ida --installpassword $IDA_PASSWORD \
    && /opt/ida/idapyswitch --force-path /usr/local/lib/libpython3.11.so \
    && if [ ! -z $IDA_KEYLESS ]; then rm /opt/ida/ida.key; fi;

USER unknowncyber
ENTRYPOINT ["/opt/ida/ida64"]
