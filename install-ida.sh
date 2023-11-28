#!/bin/bash
#
#
# This script requires having a valid ida.run file within the same
# directory as it. It also requires passing in the ida install password
# on the command line as an argument

set -x

# Install dependencies
sudo apt update
sudo apt install -y --no-install-recommends \
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
    libglu1

sudo mkdir -p /opt/ida
sudo chown -R `logname` /opt/ida

./ida.run --mode unattended --prefix /opt/ida --installpassword $1
