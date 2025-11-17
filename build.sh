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

# Check dependencies for the REST server. Defaulting to the local "deps" folder for installation
INSTALL_DIR=$(pwd)/deps
export PKG_CONFIG_PATH=$INSTALL_DIR/lib/pkgconfig:$INSTALL_DIR/share/pkgconfig:$PKG_CONFIG_PATH
CJSON=`pkg-config --cflags --libs libcjson --static`
if [ $? -ne 0 ]; then
    echo "libcjson not found. Please install it using the script in scripts/install-rest.sh."
    exit 1
fi
CIVETWEB=`pkg-config --cflags --libs civetweb --static`
if [ $? -ne 0 ]; then
    echo "civetweb not found. Please install it using the script in scripts/install-rest.sh."
    exit 1
fi
REST_INCLUDES="-DNO_SSL -DMG_EXPERIMENTAL_INTERFACES"

if [ ! -d build ]; then
    mkdir build
fi

echo "Compiling in '${BUILD_TYPE_STR}' mode"
cd build
set -x
$CC $CFLAGS ../src/nsnd/nsnd.c ../src/rest/rest.c -I../src -I../include/ -I../include/nsnd $DEFINES $REST_INCLUDES -o nsnd${POSTFIX} $CJSON $CIVETWEB $LDFLAGS

# Build the libnsn.a and libnsn.so libraries
$CC $CFLAGS -fPIC ../src/libnsn/libnsn.c -I../src -I../include/ $DEFINES -shared -o libnsn.so
$CC $CFLAGS -fPIC ../src/libnsn/libnsn.c -I../src -I../include/ $DEFINES -c -o libnsn.o
ar rcs libnsn.a libnsn.o
cp libnsn.so ../bindings/libnsn.so

# Build the libinterception.so library
$CC $CFLAGS -fPIC ../src/libinterception/libinterception.c -I../src -I../include/ $DEFINES -shared -o libinterception.so -L. -l:libnsn.a $LDFLAGS

# Build the Applications
$CC $CFLAGS ../apps/nsn_app_tx.c    -I../include $DEFINES -L. -l:libnsn.a -o nsn-app-tx $LDFLAGS
# $CC $CFLAGS ../apps/nsn_app_rx.c    -I../include -lnsn $DEFINES -o nsn-app-rx $LDFLAGS
$CC $CFLAGS ../apps/perf/nsn_app_perf.c  -I../include $DEFINES -L. -l:libnsn.a -o nsn-perf $LDFLAGS

set +x
cd ..
