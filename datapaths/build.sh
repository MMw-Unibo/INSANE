# compile a shared library from the C source code
CC=gcc
CFLAGS="-Wall -Wextra -Werror -std=c11 -fPIC -Wno-unused-function -Wno-unused-variable -Wno-deprecated-declarations"

DPDK=`pkg-config --cflags --libs libdpdk --static`
TLDK="-I ../deps/tldk/include -L ../deps/tldk/lib -ltle_dring -ltle_l4p -ltle_memtank -ltle_timer"

BUILD_TYPE=debug

if [ $# -eq 1 ]; then
    BUILD_TYPE=$1
fi

if [ $BUILD_TYPE = "debug" ]; then
    CFLAGS="-g $CFLAGS" 
    DEFINES="$DEFINES -DDEBUG -DNSN_ENABLE_LOGGER"
elif [ $BUILD_TYPE = "release" ]; then
    CFLAGS="-O3 $CFLAGS"
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

$CC $CFLAGS -c udpdpdk.c -I../src -o udpdpdk.o -mssse3
$CC $CFLAGS -shared -o libudpdpdk.so udpdpdk.o $DPDK 

$CC $CFLAGS -c tcpdpdk.c -I../src -o tcpdpdk.o -mssse3 $TLDK 
$CC $CFLAGS -shared -o libtcpdpdk.so tcpdpdk.o $DPDK $TLDK 

# $CC $CFLAGS -c rdma.c -o rdma.o
# $CC $CFLAGS -shared -o librdma.so rdma.o -lrdmacm -libverbs

$CC $CFLAGS -c udpsock.c -I../src -o udpsock.o
$CC $CFLAGS -shared -o libudpsock.so udpsock.o

$CC $CFLAGS -c tcpsock.c -I../src -o tcpsock.o
$CC $CFLAGS -shared -o libtcpsock.so tcpsock.o
