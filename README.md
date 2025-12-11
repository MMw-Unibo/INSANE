# INSANE

INSANE is a research prototype that provides Network Acceleration as a Service to applications running bare-metal or in cloud platforms. The key component of INSANE is a userspace OS module, the INSANE runtime, that provides applications transparent access to a wide set of low-latency userspace networking, such as Linux XDP, DPDK, RDMA, in addition to standard kernel networking. The OS module runs as a separate process co-located with the applications and applications interact with it via shared-memory channels.

INSANE (<u>I</u>ntegrated a<u>N</u>d <u>S</u>elective <u>A</u>cceleration for the <u>N</u>etwork <u>E</u>dge) consists of two main components:
* A ***client library***, exposing a uniform, data-centric API with a minimal set of communication primitives, yet expressive enough to let developers define high-level and domain-specific abstractions on top of them. Through a set of Quality of Service (QoS) parameters, applications can define differentiated network requirements for their data flows, such as latency-sensitiveness, reliability, and resource consumption. Within the same application, flows with different requirements can be mapped to different technologies.
* A ***userspace OS module***, working as a *network stack as a service* for applications and offering common services for high-performance networking, including memory management for zero-copy transfers, efficient packet processing, and different packet scheduling strategies. A plugin-based architecture allows the specialization of such abstractions for each integrated network acceleration technology. In particular, the high-level QoS requirements specified by applications are used to dynamically map the flows to the most appropriate acceleration technology that is dynamically available at the deployment site.

## Table of Contents
- [Installing INSANE](#installing-insane)
  - [Prerequisites](#prerequisites)
  - [Build the project](#build-the-project)
- [Running INSANE](#running-insane)
  - [Running the daemon](#running-the-daemon)
  - [Running the test application](#running-the-test-application)
  - [Tutorial](#tutorial)
- [Plugins](#plugins)
  - [DPDK plugins](#dpdk-plugins)
- [REST Monitoring and Control API](#rest-monitoring-and-control-api)
- [Interception library](#interception-library)
- [Performance benchmarks](#performance-benchmarks)
  - [Micro-benchmarks](#micro-benchmarks)
  - [Comparison with Demikernel](#comparison-with-demikernel)
  - [Lunar applications](#lunar-applications)
    - [LUNAR MoM](#lunar-mom)
    - [LUNAR Stream](#lunar-stream)
- [Running on CloudLab](#running-on-cloudlab)
- [Running on Azure](#running-on-azure)
- [Credits](#credits)

## Installing INSANE

### Prerequisites
First, it is necessary to prepare the environment and to install the prerequisites:
* Ubuntu 22.04 or newer (we did not test other environments)
* The following packages: `cmake` and `pkg-config` (you can install them via `sudo apt install cmake pkg-config`)
* Setup hugepages (you need root access) ([script](scripts/hugepages.sh))
* Install cJSON and citiweb as required by the REST support ([script](scripts/install-rest.sh))

Depending on which network stack you will use, you might also want to install:
* DPDK 22.11 ([script](scripts/install-dpdk.sh)), patched to fix a few bugs. We suggest to perform a local installation by creating a $INSANE_DIR/deps folder, and passing its path to the above scripts. In the building scripts, we assume that setup.
* TLDK ([script](scripts/install-tldk.sh)), only after DPDK.
We suggest to perform a local installation by creating a $INSANE_DIR/deps folder, and passing its path to the above scripts. In the building scripts, we assume that setup.

Then, it is possible to proceed with the project build.

### Build the project

The building process is articulated in two steps: building the network-agnostic daemon and then building the network plugins.

Step 1. To build the daemon, `cd` into the `insane` directory and run:
* `./build.sh [debug|release]`

Those commands will create the executables in a folder called `build`. You can `cd` into it to see the results: the daemon executable (`nsnd`), the client library (`libnsn`), the interception library (`libinterception`), a benchmarking application (`nsn-perf`), and a few demo applications (`nsn-app_*`) that serve as hello-world examples.

Step 2. Although the daemon is a standalone application, INSANE requires *at least one datapath plugin* to be available for applications to communicate with remote peers. A *datapath plugin* is a library that specializes the INSANE communication abstraction for a specific protocol/hardware combination. These libraries must be compiled and be available at runtime. The code for the available *datapath plugin* is in the [`datapaths`](datapaths) folder.  You can `cd` into that folder and call the `datapath/build.sh` script to compile one or all of them:
* `cd datapaths`
* `./build.sh [debug|release]`
* `cd ..`
  
## Running INSANE

### Running the daemon

Before starting the daemon, you need to provide a few configuration parameters in a configuration file. An [example](configs/nsnd.cfg) is provided. By default, the daemon will look for a `nsnd.cfg` file in its working directory. You can specify a different file location by using the `--config` command line argument. You need to fill out the configuration file with the correct parameters for your machine.

Then, invoke the the daemon executable (`nsnd`).

### Running the test application

Once the daemon is started, it is possible to start applications that connect to the runtime. Currently the repository provides one pre-built application which is used to test performance (`nsn-perf`).

Similarly to the daemon, you must provide a configuration file, where you specify the application ID. An [example](configs/nsn-app.cfg) is provided. Such ID must be a valid UDP/TCP port: only applications with the same ID will be able to communicate. The configuration file must be placed in the current directory from which the application is invoked and be called `nsn-app.cfg`.


Please note that while INSANE is designed to have multiple applications running concurrently, they **must have different application IDs** if they attach to the same daemon. Future versions of INSANE will enable local app-to-app communication, which is currently not supported.

### Tutorial

A tutorial on writing INSANE-based applications is available at [this repository](https://github.com/ellerre/insane-tutorial).

## Plugins

INSANE comes with a few network plugin implemented, thus enabling networking using different stacks. Currently, we provide plugins for UDP and TCP that use either the standard in-kernel stack (`sock` plugins) or the DPDK library (`dpdk` plugins). We also provide a plugin for RDMA. Linux XDP is available, for the moment, using the DPDK plugin and the XDP driver.

Each plugin **must be configured** in the daemon configuration file by specifying at least the IP address to which it must bind. The port is defined by the applications through their application ID. Please refer to the [example](configs/nsnd.cfg).

### DPDK plugins

To fully support a DPDK-based plugin and still guarantee the flexibility of INSANE, we had to modify a few lines of some drivers. Hence, we provide a [diff file](dpdk_22_11_mods.diff) that contains the changes we made to the driver source code. You can apply this patch to the DPDK source code before building it.

Furthermore, if you are using a Mellanox card for the DPDK plugin, you need to explicitly disable the use of vectorial instructions, as it conflicts with the features we use in the DPDK plugin. To do so, add the following parameter to the DPDK configuration (i.e., the `eal_args` string) in the INSANE daemon configuration file: `-a <pcie_addr>,rx_vec_en=0`, where `<pcie_addr>` is the PCI address of the Mellanox card (e.g., `0000:05:00.0`).

We tested the DPDK plugins also with the Intel i40 driver, but not with other drivers. As long as they support RSS specification and multiple NIC queues, they should be supported. One of such plugins is the XDP plugin, which can be used to test XDP performance while a specific XDP plugin is not currently available for INSANE.

Because the DPDK virtio PMD does not support RSS without specific hypervisor support, INSANE DPDK does not work on virtio-based interfaces, which are common in Virtual Machines. A possible solution is to enable interface passthrough to the VM (e.g., using SR-IOV and passing through a VF) and use the native DPDK driver for such interface. We are currently working to remove the RSS constraint when not supported by the NIC.

## REST Monitoring and Control API
The INSANE daemon provides a REST API to monitor and control its operations. The API is documented in the [dedicated](docs/rest.md) file.

## Interception library

In alternative to its native API, INSANE can run unmodified binaries through the interception library.

`libinterception` is a dynamic library designed to intercept standard POSIX socket API calls at runtime in existing applications without requiring source code modifications.
It uses the `LD_PRELOAD` mechanism to override specific functions from the standard C library at runtime, enabling transparent integration with INSANE. It overrides standard socket functions (such as `socket()`, `sendto()`, `listen()`, `recvfrom()`) and redirects them to INSANE API functions.

More information is available [here](docs/libinterception.md).

<!-- ### Creating custom applications -->

## Performance benchmarks

A performance benchmark of INSANE is provided as part of this repository: [`apps/perf/nsn-perf`](apps/perf/nsn_perf.c). This test can be invoked using the following parameters:

```bash
Usage: ./nsn-perf [MODE] [OPTIONS]
MODE: source|sink|ping|pong
OPTIONS:
-h: display this message and exit
-s: message payload size in bytes
-n: max messages to send (0 = no limit)
-q: datapath QoS. Can be fast or slow
-r: reliability QoS. Can be reliable or unreliable
-c: consumption QoS. Can be poll or low
-a: specify app-defined source id
-t: configure sleep time (s) in send
-m: specify send rate (msg/s) in source mode
```

The ``ping`` and ``pong`` couple is used to launch a latency test, whereas the ``source`` and ``sink`` couple is used to launch a throughput test, as better explained in the following. 

For socket and DPDK, the ``-r`` flag switches between UDP (default) of TCP (if specified).
The ``-q slow`` default selects the socket plugins (default, can be omitted). The ``-q fast`` selects either DPDK (default) or RDMA (if also ``-c low`` is passed).

Please note that the *deterministic QoS* will be implemented in a future release.

### Micro-benchmarks

A **latency test** can be performed by launching the ``nsn-perf`` applications on two nodes: one with the ``pong`` role (working as server) and one with ``ping`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.

For instance, to launch the latency test with UDP on DPDK:
```bash
# On the server node
sudo taskset -c 0-2 ./nsn-perf pong -s 64 -n 100000 -q fast
# On the client node
sudo taskset -c 0-2 ./nsn-perf ping -s 64 -n 100000 -q fast
```

The output of the test is, on the client side, a set number that represent the Round-Trip Time, in microseconds, measured for each message sent and received back. 

A **throughput test** can be performed by launching the ``nsn-perf`` applications on two nodes: one with the ``sink`` role (working as server) and one with ``source`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.

For instance:
```bash
# On the server node
sudo taskset -c 0-2 ./nsn-perf sink -s 1024 -n 1000 -q fast
# On the client node
sudo taskset -c 0-2 ./nsn-perf source -s 1024 -n 1000 -q fast
```

The output of the test is, on the server side, first a human-readable summary of the results, and then a csv line that we used to generate the throughput graphs in the microbenchmarking section. For instance:
```bash
    [ TEST RESULT ]
    Received messages:   1000
    Elapsed time:        0.382 ms
    Measured throughput: 2.618 Mmsg/s
    Measured banwdidth:  21442.612 Mbps

    1000,1024,0.382,2.618,21442.612
```

To launch both a throughput test and a latency test (e.g., to measure *loaded latency*), it is possible to launch two instances of the benchmarking applications, but pay attention to specify different *application IDs* for applications running on the same machine.

Finally, INSANE does not currently support packet fragmentation/reconstruction because that would lead to violations to the pure zero-copy semantic. You should enable jumbo frames on the proper interfaces to send payloads up to 9KB. To do that, you can run:
```bash
sudo ip link set <iface_name> mtu 9000
```
and change the ```MAX_PAYLOAD_SIZE``` constant in [```nsn_perf.c```](examples/nsn_perf.c) file to 8972 bytes. After recompiling, the jumbo frame support is enabled.


### Comparison with Demikernel

The folder [```comparisons```](comparisons) contains test cases to run the Demikernel benchmarks for the comparison showed in the paper. These tests should be copied into the Demikernel repository and run from there, using either the UDP or DPDK support. 

In particular:
* [udp-echo.rs](comparisons/udp-echo.rs) should replace the [original udp-echo](https://github.com/microsoft/demikernel/tree/dev/examples/rust/udp-echo.rs).
* [udp-ping-pong.rs](comparisons/udp-ping-pong.rs) should replace the [original udp-ping-pong](https://github.com/microsoft/demikernel/blob/dev/examples/rust/udp-ping-pong.rs)
* [udp-pktgen.rs](comparison/udp-pktgen.rs) should replace the [original udp-pktgen](https://github.com/microsoft/demikernel/blob/dev/examples/rust/udp-pktgen.rs) 


### Lunar applications

The LUNAR applications are example applications built to show the ease of programming guaranteed by INSANE with no performance compromises. The two applications are a decentralized Message-oriented Middleware (MoM) and an image streaming framework.

#### LUNAR MoM

The code of LUNAR MoM is located in [```apps/lunar```](apps/lunar). The MoM gives the possibility to create topics and have other INSANE applications to publish or subscribe on them. By relying on the INSANE API, this MoM is very simple and exposes a very intuitive and easy-to-use interface.

Together with the MoM code, there is also a simple test application that can be used to test the MoM performance:  [```lunar-perftest```](apps/lunar/lunar_perftest.c). This application provides both a latency and a throughput test with the same semantic as the `nsn-perf` application. Both these tests create a topic and publish/subscribe on it. The topic name can be passed as an argument to the application.

A **latency test** can be performed by launching the ``lunar-perftest`` applications on two nodes: one with the ``subpub`` role (working as server) and one with ``pubsub`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.
A **throughput test** can be performed by launching the ``lunar-perftest`` applications on two nodes: one with the ``sub`` role (working as server) and one with ``pub`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.

For instance, you can launch the latency test as:
```bash
# On the server node
sudo taskset -c 0-2 ./lunar-perftest subpub -s 64 -n 100000 -q fast
# On the client node
sudo taskset -c 0-2 ./lunar-perftest pubsub -s 64 -n 100000 -q fast
```

#### LUNAR Stream

The code of LUNAR Stream is located in [```apps/lunar-streaming```](apps/lunar-streaming). Lunar Streaming exposes a simple set of APIs, starting with ```lnr_s_open_server``` to open the server-side application and with ```lnr_s_connect``` that allows clients to connect to it. Thus, the server application must implement a simple interface by exposing two methods: ```get_frame``` and ```wait_next```. The first allows to get a new frame, while the second pauses the server waiting for the next frame. To start streaming, the server application must invoke ```lnr_s_loop``` which performs the following steps: 
1. Requesting a new frame
2. Fragmenting and sending the frame
3. Waiting for the next frame to restart the loop until the end of streaming.

Together with the Stream code, there is also a simple client/server application, written using the LUNAR Stream framweork, that can be used to test the performance of raw image streaming:  [```s-server```](apps/lunar-streaming/s_server.c) and [```s-client```](apps/lunar-streaming/s_client.c). The server application embeds two files from the single-header library [stb](https://github.com/nothings/stb) to handle image loading and writing.

The application measures two metrics:
1. The number of frames per second (FPS) the client application can handle;
2. The average end-to-end latency for frame transmission, i.e., the time between the server application sending a frame (including fragmentation) and the client application receiving the reconstructed frame.

Because the measured latency is *one-way latency*, before the test execution it is necessary that the two physical hosts are synchronized using PTP. At [this link](https://tsn.readthedocs.io/timesync.html) you can find the necessary instructions.
<!-- TODO: provide the commands to synchronize the hosts. Here or in a separate section of the readme/folder of the repo -->

Once the hosts are synchronized, the client must be started first: this simulates the behavior of usual streaming application in which the client asks the server for data, and the server sends it back. The client application takes the following arguments:
```bash
Usage: apps/s-client [-q <quality>]
-q: image quality. Can be hd|fullhd|2k|4k|8k.
```
For instance, to ask the server for a FullHD (1920x1080) image, you can run:
```bash
sudo taskset -c 0-2 ./s-client -q fullhd
```

After starting the client on one host, the server can be started on the other host. The server application takes the following arguments:

```bash
Usage: apps/s-server -i <filename> -f <frames> -r <rate_ms>
-i: input file
-f: number of frames to send
-r: frame rate in ms
```
In the [data](apps/lunar-streaming/data) folder, three examples images are already provided as samples that can be passed with the -i parameter. The -f parameter specifies the number of frames to send, whereas the -r parameter specifies the frame rate in milliseconds. For instance, to send 1000 frames at 500 FPS, you can run:
```bash
sudo taskset -c 0-2 ./s-server -i data/test.jpg -f 1000 -r 2
``` 

To change the QoS parameters passed to INSANE, currenlty the application does not provide a command line interface. You must change the proper options at line 44 of the [```lunar_s.c```](apps/lunar-streaming/lunar_s.c) file and recompile the application.

The results of the tests will be printed to the console of both the client and the server application, one line per frame. On the client side, each line shows two values: *latency* and *time*. The *latency* field represents the end-to-end latency between when the server started to send the frame and when the client received it entirely. Because frame reception is sequential, this value can be averaged and used to compute the FPS latency the client is able to handle.

An example output on the client side, for three frames, would be:
```bash
lat, time
1807895,1804478
1801885,1797829
1802669,1799150
```
These numbers, which are purely indicative, would correspond to an average 1.8ms *end-to-end* latency and 1.8ms of per-frame handling time, corresponding to roughly 555 FPS.

## Running on CloudLab

To run on CloudLab, we suggest to select an hardware type that supports at least two experimental LANs, so that it is possible to test the same application with kernel-based and DPDK networking. Please do not use the management network for the experiment traffic. To use DPDK, so please try to select a node with Mellanox NICs or with high-performance (>10 Gbps) Intel NICs (driver i40e or newer).

We performed our tests using the [d6515](https://docs.cloudlab.us/hardware.html) hardware, but others with similar characteristics should work as well (e.g., c6525-100g, c6525-25g, r7525). To ease the testing, we created a [CloudLab profile](https://www.cloudlab.us/p/INSANEProject/Ubuntu22.04-TwoLANs) for two nodes that use Ubuntu 24.04, with two suitable LANs already configured. If you use that image, we reccommend using the 192.168.0.0/16 network for DPDK or RDMA, and the 10.0.0.0/16 for kernel-based plugin. 

A second important note is that on CloudLab it is possible that DPDK, by default, gets ownership of all the Mellanox cards on the machine. If that includes the management interface (used for ssh), access to the node is lost. Be sure to specify the right interface's PCI address in the INSANE daemon's configuration file.

We have prepared a step-by-step guide to run INSANE on CloudLab, that is available [here](docs/Cloudlab-detailed-guide.pdf).

## Running on Azure

We support the deployment of INSANE on Azure. However, the use of DPDK in Azure requires some different steps from those described in this guide and likely some code modifications. We are going to release soon the associated instructions, but please email us if you are interested in trying it out.


## Credits

If you use INSANE in your research, please cite us:
```bibtex
@inproceedings{insane,
author = {Rosa, Lorenzo and Garbugli, Andrea and Corradi, Antonio and Bellavista, Paolo},
title = {INSANE: A Unified Middleware for QoS-Aware Network Acceleration in Edge Cloud Computing},
year = {2023},
isbn = {9798400701771},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3590140.3629105},
doi = {10.1145/3590140.3629105},
booktitle = {Proceedings of the 24th International Middleware Conference},
pages = {57–70},
numpages = {14},
keywords = {QoS, Edge Cloud, Network Acceleration},
location = {<conf-loc>, <city>Bologna</city>, <country>Italy</country>, </conf-loc>},
series = {Middleware '23}
}
```
