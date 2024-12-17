CC=gcc
CFLAGS="-Wall -Wextra -Werror -Wno-address-of-packed-member -std=c11"
LDFLAGS="-lm -ldl -lpthread"
DEFINES=""

BUILD_TYPE=debug
PROJECT_NAME=all

DPDK=`pkg-config --cflags --libs libdpdk --static`

if [ $# -eq 1 ]; then
    BUILD_TYPE=$1
elif [ $# -eq 2 ]; then
    BUILD_TYPE=$1
    PROJECT_NAME=$2
fi

if [ $BUILD_TYPE = "debug" ]; then
    CFLAGS="$CFLAGS -g"
    DEFINES="$DEFINES -DDEBUG"
elif [ $BUILD_TYPE = "release" ]; then
    CFLAGS="$CFLAGS -O3"
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

cd build
$CC $CFLAGS $LDFLAGS ../udpsock_perf.c $DEFINES -o udpsock-perf
$CC $CFLAGS $LDFLAGS ../udpdpdk_perf.c $DEFINES -o udpdpdk-perf $DPDK
$CC $CFLAGS $LDFLAGS ../tcpsock_perf.c $DEFINES -o tcpsock-perf
cd ..