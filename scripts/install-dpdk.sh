#!/bin/bash

## Usage: ./install-dpdk.sh [<install-dir>]
## Default is /usr/local/

# Check arguments.
if [ $# -gt 1 ]; then
    echo "Usage: $0 [<install-dir>]"
    exit 1
fi

# Set install directory.
if [ $# -eq 1 ]; then
    INSTALL_DIR=$1
else
    INSTALL_DIR=/usr/local/
fi

# Install prerequisites
sudo apt update
sudo apt install -y librdmacm-dev libmnl-dev build-essential clang libnuma-dev pkg-config python3 python3-pip meson clang-format cmake python3-pyelftools

# Fail on error.
set -e

# Switch to working directory.
pushd $PWD
mkdir -p $HOME/tmp/dpdk
cd $HOME/tmp/dpdk

# Download sources.
git clone https://github.com/DPDK/dpdk.git
cd dpdk
git checkout v22.11

# Build and install
meson --buildtype=release --default_library=shared --prefix=$INSTALL_DIR build
cd build
ninja build
sudo ninja install
sudo ldconfig

# Cleanup.
popd
rm -rf $HOME/tmp/dpdk