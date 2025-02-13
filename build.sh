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
elif [ $BUILD_TYPE = "release" ] || [ $BUILD_TYPE = "1" ]; then
    # Maybe remove the NSN_ENABLE_LOGGER define in release builds
    DEFINES="$DEFINES -DNSN_ENABLE_LOGGER"
    CFLAGS="$CFLAGS -O3 -march=native -mavx2"
    BUILD_TYPE_STR=release
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

echo "Compiling in '${BUILD_TYPE_STR}' mode"
cd build
set -x
$CC $CFLAGS ../src/nsnd.c 	  $LDFLAGS $DEFINES -o nsnd
$CC $CFLAGS ../src/nsn_app_tx.c   $LDFLAGS $DEFINES -o nsn-app-tx
$CC $CFLAGS ../src/nsn_app_rx.c   $LDFLAGS $DEFINES -o nsn-app-rx
$CC $CFLAGS ../src/nsn_app_perf.c $LDFLAGS $DEFINES -o nsn-perf
set +x
cd ..
