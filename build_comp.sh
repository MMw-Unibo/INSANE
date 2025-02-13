CC=gcc
CFLAGS="-Wall -Wextra -Werror -Wno-address-of-packed-member -std=c11"
LDFLAGS="-lm -ldl -lpthread"
DEFINES=""

COMPARISON_DIR=comparisons
BUILD_TYPE=debug
PROJECT_NAME=all

DPDK=$(pkg-config --cflags --libs libdpdk --static)

if [ $# -eq 1 ]; then
    BUILD_TYPE=$1
elif [ $# -eq 2 ]; then
    BUILD_TYPE=$1
    PROJECT_NAME=$2
fi

if [ $BUILD_TYPE = "debug" ] || [ $BUILD_TYPE = "0" ]; then
    CFLAGS="$CFLAGS -g"
    DEFINES="$DEFINES -DDEBUG"
elif [ $BUILD_TYPE = "release" ] || [ $BUILD_TYPE = "1" ]; then
    CFLAGS="$CFLAGS -O3 -mavx2 -march=native"
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

echo "Compiling in '${BUILD_TYPE}' mode"
cd build
set -x
$CC $CFLAGS ../${COMPARISON_DIR}/udpsock_perf.c $LDFLAGS $DEFINES 	-o udpsock-perf
$CC $CFLAGS ../${COMPARISON_DIR}/udpdpdk_perf.c $LDFLAGS $DEFINES $DPDK -o udpdpdk-perf
$CC $CFLAGS ../${COMPARISON_DIR}/tcpsock_perf.c $LDFLAGS $DEFINES 	-o tcpsock-perf
XDP_INCLUDES="-I../deps/xdp-tools/headers -L../deps/xdp-tools/lib/libxdp -l:libxdp.a -lbpf"
$CC $CFLAGS ../${COMPARISON_DIR}/udpxsk_perf.c 	$LDFLAGS $XDP_INCLUDES $DEFINES  -o udpxsk-perf
set +x
cd ..
