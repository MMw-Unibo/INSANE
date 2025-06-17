#!/bin/bash

## Usage: ./install-tldk.sh [<install-dir>]
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

# Detect DPDK using pkg-config.
if ! pkg-config --exists libdpdk; then
    echo "DPDK not found. Please install DPDK first."
    exit 1
fi

# Fail on error.
set -e

# Switch to working directory.
pushd $PWD
mkdir -p $HOME/tmp
cd $HOME/tmp

# Download sources.
git clone https://github.com/ellerre/tldk.git
cd tldk

# Build and install
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR ..
make -j $(nproc)
make install

# Cleanup.
popd
rm -rf $HOME/tmp/tldk