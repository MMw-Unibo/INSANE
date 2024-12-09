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
    DEFINES="$DEFINES -DDEBUG"
elif [ $BUILD_TYPE = "release" ]; then
    CFLAGS="$CFLAGS -O3"
else
    echo "Invalid build type: $BUILD_TYPE"
    exit 1
fi

cd build
$CC $CFLAGS $LDFLAGS ../ring_tx.c $DEFINES -o ringtx
$CC $CFLAGS $LDFLAGS ../ring_rx.c $DEFINES -o ringrx
cd ..