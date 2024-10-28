CC=gcc
CFLAGS="-Wall -Wextra -Werror -std=c11"
LDFLAGS="-lm -ldl -lpthread"
DEFINES=""

BUILD_TYPE=debug
PROJECT_NAME=all

if [ $# -eq 1 ]; then
    BUILD_TYPE=$1
elif [ $# -eq 2 ]; then
    BUILD_TYPE=$1
    PROJECT_NAME=$2
fi

if [ $BUILD_TYPE = "debug" ]; then
    CFLAGS="$CFLAGS -g"
    DEFINES="$DEFINES -DDEBUG -DNSN_ENABLE_LOGGER"
elif [ $BUILD_TYPE = "release" ]; then
    # Maybe remove the NSN_ENABLE_LOGGER define in release builds
    DEFINES="$DEFINES -DDEBUG -DNSN_ENABLE_LOGGER"
    CFLAGS="$CFLAGS -O3"
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

cd build
$CC $CFLAGS $LDFLAGS ../src/nsnd.c $DEFINES -o nsnd 
$CC $CFLAGS $LDFLAGS ../src/nsn_app_tx.c $DEFINES -o nsn-app-tx
$CC $CFLAGS $LDFLAGS ../src/nsn_app_rx.c $DEFINES -o nsn-app-rx
$CC $CFLAGS $LDFLAGS ../src/nsn_app_perf.c $DEFINES -o nsn-perf
cd ..