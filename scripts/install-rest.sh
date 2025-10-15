#!/bin/bash

## Usage: ./install-rest.sh [<install-dir>]
## Default is $INSANE_ROOT/deps, assuming the script is launched from the INSANE root directory.

# The script will download the cJSON library and the civetweb library.
# It will build and install them in the specified directory.

# Check arguments.
if [ $# -gt 1 ]; then
    echo "Usage: $0 [<install-dir>]"
    exit 1
fi

# Set install directory.
if [ $# -eq 1 ]; then
    INSTALL_DIR=$1
else
    INSTALL_DIR=$(pwd)/deps
fi

# Fail on error.
set -e

# Switch to working directory.
pushd $PWD
mkdir -p $HOME/tmp/rest
cd $HOME/tmp/rest

# Download sources for cJSON
git clone https://github.com/DaveGamble/cJSON.git
cd cJSON
git checkout v1.7.19

# Build and install
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR -DENABLE_CJSON_TEST=Off -DBUILD_SHARED_LIBS=Off ..
make -j $(nproc)
make install

cd ../..

# Download sources for civetweb
git clone https://github.com/civetweb/civetweb.git
cd civetweb
git checkout v1.16
mkdir mybuild
cd mybuild
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR ..
make -j $(nproc)
make install

# Cleanup.
popd
rm -rf $HOME/tmp/dpdk
