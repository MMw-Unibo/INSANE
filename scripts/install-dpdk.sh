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
sudo apt install -y librdmacm-dev libmnl-dev build-essential clang libnuma-dev pkg-config python3 python3-pip meson clang-format cmake python3-pyelftools libsystemd-dev libpcap-dev

# Fail on error.
set -e

# Switch to working directory.
home=$(pwd)
pushd $PWD
mkdir -p $HOME/tmp/dpdk
cd $HOME/tmp/dpdk

# Download sources.
git clone https://github.com/DPDK/dpdk.git
cd dpdk
git checkout v22.11
git apply "$home/../dpdk_22_11_mods.diff"

# Build and install
meson setup --buildtype=release --prefix=$INSTALL_DIR build
cd build
ninja
sudo ninja install
sudo ldconfig

# Make it seen by pkg-config
export PKG_CONFIG_PATH=$INSTALL_DIR/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH

# Cleanup.
popd
rm -rf $HOME/tmp/dpdk
