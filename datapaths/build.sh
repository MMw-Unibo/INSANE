# compile a shared library from the C source code
CC=gcc
CFLAGS="-g -Wall -Wextra -Werror -std=c11 -fPIC -Wno-unused-function -Wno-unused-variable"

DPDK=`pkg-config --cflags --libs libdpdk --static`

# $CC $CFLAGS -c dpdk.c -o dpdk.o
# $CC $CFLAGS -shared -o libdpdk.so dpdk.o $DPDK 

# $CC $CFLAGS -c rdma.c -o rdma.o
# $CC $CFLAGS -shared -o librdma.so rdma.o -lrdmacm -libverbs

$CC $CFLAGS -c udpsock.c -o udpsock.o
$CC $CFLAGS -shared -o libudpsock.so udpsock.o