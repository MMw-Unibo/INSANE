# compile a shared library from the C source code
CC=gcc
CFLAGS="-g -Wall -Wextra -Werror -std=c11 -fPIC -Wno-unused-function -Wno-unused-variable -Wno-deprecated-declarations"

DPDK=`pkg-config --cflags --libs libdpdk --static`

BUILD_TYPE=debug

if [ $# -eq 1 ]; then
    BUILD_TYPE=$1
fi

if [ $BUILD_TYPE = "debug" ]; then
    DEFINES="$DEFINES -DDEBUG -DNSN_ENABLE_LOGGER"
elif [ $BUILD_TYPE = "release" ]; then
    CFLAGS="$CFLAGS -O3"
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

$CC $CFLAGS -c udpdpdk.c -o udpdpdk.o -mssse3
$CC $CFLAGS -shared -o libudpdpdk.so udpdpdk.o $DPDK 

# $CC $CFLAGS -c rdma.c -o rdma.o
# $CC $CFLAGS -shared -o librdma.so rdma.o -lrdmacm -libverbs

$CC $CFLAGS -c udpsock.c -o udpsock.o
$CC $CFLAGS -shared -o libudpsock.so udpsock.o

$CC $CFLAGS -c tcpsock.c -o tcpsock.o
$CC $CFLAGS -shared -o libtcpsock.so tcpsock.o