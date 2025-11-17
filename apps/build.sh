CC=gcc
CFLAGS="-std=c11"
CFLAGS="$CFLAGS -Wall -Wextra -Werror"
LDFLAGS="-lm -ldl -lpthread -lrt"
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

ROOT_DIR=$(pwd)/..
BUILD_DIR=$ROOT_DIR/build
APPS_DIR=$(pwd)

if [ ! -f "$BUILD_DIR/libnsn.a" ]; then
    echo "ERROR: libnsn.a not found in $BUILD_DIR"
    echo "Please run the main build script first to compile libnsn.a"
    exit 1
fi

echo "Compiling Lunar applications in '${BUILD_TYPE_STR}' mode"
cd $BUILD_DIR
set -x

# Build the lunar streaming library
$CC $CFLAGS -fPIC $APPS_DIR/lunar-streaming/lunar_s.c -I$ROOT_DIR/src -I$ROOT_DIR/include/ $DEFINES -c -o lunar_s.o
ar rcs liblunars.a lunar_s.o

# Build the lunar streaming Applications
$CC $CFLAGS $APPS_DIR/lunar-streaming/s_client.c  -I$ROOT_DIR/include $DEFINES -L. -l:liblunars.a -l:libnsn.a -o s-client${POSTFIX} $LDFLAGS
$CC $CFLAGS $APPS_DIR/lunar-streaming/s_server.c  -I$ROOT_DIR/include $DEFINES -L. -l:liblunars.a -l:libnsn.a -o s-server${POSTFIX} $LDFLAGS
$CC $CFLAGS $APPS_DIR/lunar-streaming/sendfile.c  -I$ROOT_DIR/include $DEFINES -L. -l:liblunars.a -l:libnsn.a -o sendfile${POSTFIX} $LDFLAGS
$CC $CFLAGS $APPS_DIR/lunar-streaming/recvfile.c  -I$ROOT_DIR/include $DEFINES -L. -l:liblunars.a -l:libnsn.a -o recvfile${POSTFIX} $LDFLAGS

# Build the lunar MoM library
$CC $CFLAGS -fPIC $APPS_DIR/lunar/lunar.c -I$ROOT_DIR/src -I$ROOT_DIR/include/ $DEFINES -c -o lunar.o
$CC $CFLAGS -fPIC $APPS_DIR/lunar/config.c -I$ROOT_DIR/src -I$ROOT_DIR/include/ $DEFINES -c -o config.o
$CC $CFLAGS -fPIC $APPS_DIR/lunar/pack.c -I$ROOT_DIR/src -I$ROOT_DIR/include/ $DEFINES -c -o pack.o
ar rcs liblunar.a lunar.o

# Build the lunar MoM applications
$CC $CFLAGS $APPS_DIR/lunar/lunar_pub.c      -I$ROOT_DIR/include $DEFINES -L. -l:liblunar.a -l:libnsn.a -o lpub${POSTFIX} $LDFLAGS
$CC $CFLAGS $APPS_DIR/lunar/lunar_sub.c      -I$ROOT_DIR/include $DEFINES -L. -l:liblunar.a -l:libnsn.a -o lsub${POSTFIX} $LDFLAGS
$CC $CFLAGS $APPS_DIR/lunar/lunar_perftest.c -I$ROOT_DIR/include $DEFINES -L. -l:liblunar.a -l:libnsn.a -o lunar-perftest${POSTFIX} $LDFLAGS

# Build the perf Applications
#$CC $CFLAGS $APPS_DIR/perf/nsn_app_perf.c  -I../include $DEFINES -L. -l:libnsn.a -o nsn-perf $LDFLAGS

set +x
cd $APPS_DIR
