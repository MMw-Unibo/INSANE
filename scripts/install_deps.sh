#!/bin/env bash

set -x

# Install dependencies
DEPS_DIR=deps
XDP_TOOLS_DIR=xdp-tools
CMD=$1

if [ "$CMD" = "clean" ]; then
    # TODO: Clean up, remove deps directory not only xdp-tools
    rm -rf $DEPS_DIR/$XDP_TOOLS_DIR
    exit 0
fi

if [ ! -d "$DEPS_DIR" ]; then
    mkdir $DEPS_DIR
fi

cd $DEPS_DIR

if [ ! -d "$XDP_TOOLS_DIR" ]; then
    git clone --recursive https://github.com/xdp-project/xdp-tools.git
    cd xdp-tools
    git checkout tags/v1.5.1
    make libxdp
    cd ..
fi

cd ..
