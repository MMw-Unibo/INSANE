CC=gcc
CFLAGS="-std=c11"
CFLAGS="$CFLAGS -Wall -Wextra -Werror"
LDFLAGS="-lm -ldl -lpthread"
DEFINES=""

BUILD_TYPE=0 		# 0: Debug, 1: Release
BUILD_TYPE_STR=debug
PROJECT_NAME=all

if [ $# -eq 1 ]; then
    BUILD_TYPE=$1
elif [ $# -eq 2 ]; then
    BUILD_TYPE=$1
    PROJECT_NAME=$2
fi

if [ $BUILD_TYPE = "debug" ] || [ $BUILD_TYPE = "0" ]; then
    CFLAGS="$CFLAGS -g"
    DEFINES="$DEFINES -DDEBUG -DNSN_ENABLE_LOGGER"
    POSTFIX="-dbg"
elif [ $BUILD_TYPE = "release" ] || [ $BUILD_TYPE = "1" ]; then
    # Maybe remove the NSN_ENABLE_LOGGER define in release builds
    DEFINES="$DEFINES -DNSN_ENABLE_LOGGER"
    CFLAGS="$CFLAGS -O3 -march=native -mavx2"
    BUILD_TYPE_STR=release
    POSTFIX=""
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

echo "Compiling in '${BUILD_TYPE_STR}' mode"
cd build
set -x
$CC $CFLAGS ../src/nsnd/nsnd.c  -I../src -I../include/  $LDFLAGS $DEFINES -o nsnd${POSTFIX}

# Build the libnsn.a and libnsn.so libraries
gcc $CFLAGS -fPIC ../src/libnsn/libnsn.c -I../src -I../include/ $DEFINES -shared -o libnsn.so
gcc $CFLAGS -fPIC ../src/libnsn/libnsn.c -I../src -I../include/ $DEFINES -c -o libnsn.o
ar rcs libnsn.a libnsn.o
cp libnsn.so ../bindings/libnsn.so

# Build the Applications
# $CC $CFLAGS ../apps/nsn_app_tx.c    -I../include $DEFINES $LDFLAGS -L. -l:libnsn.a -o nsn-app-tx
# $CC $CFLAGS ../apps/nsn_app_rx.c    -I../include $LDFLAGS -lnsn $DEFINES -o nsn-app-rx
$CC $CFLAGS ../apps/nsn_app_perf.c  -I../include $DEFINES $LDFLAGS -L. -l:libnsn.a -o nsn-perf

set +x
cd ..
