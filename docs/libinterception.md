## libinterception Documentation

## Overview

`libinterception` is a dynamic library designed to intercept standard POSIX socket API calls at runtime in existing applications without requiring source code modifications.
It uses the `LD_PRELOAD` mechanism to override specific functions from the standard C library at runtime, enabling transparent integration with INSANE. It overrides standard socket functions (such as `socket()`, `sendto()`, `listen()`, `recvfrom()`) and redirects them to INSANE API functions.

## Supported Socket Functions

`libinterception` intercepts the following standard socket API functions:

* `socket()` - Socket creation
* `setsockopt()` - Socket options
* `bind()` - Address binding
* `listen()` - Connection listening
* `accept()` - Connection acceptance
* `connect()` - Connection establishment
* `read()`/`recvfrom()` - Data reception
* `write()`/`sendto()` - Data transmission
* `close()` - Socket closure

## How to use libinterception

In order to compile libinterception `cd` into the `insane` directory and run:
* `./build.sh`

Then to execute one of your legacy socket-based application over INSANE with zero code changes you need to run:
* `sudo LD_PRELOAD=build/libinterception.so my-socket-based-app sink -n 5 -s 1024`

This command intercepts all socket calls made by `my-socket-based-app` and routes data communication through INSANE instead of the standard TCP/UDP stack. 
You must run the command with `sudo` in order to use INSANE client applications.
