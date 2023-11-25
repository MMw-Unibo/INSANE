# INSANE: A Unified Middleware for QoS-aware Network Acceleration in Edge Cloud Computing

INSANE is a research prototype that provides *Network Acceleration as a Service* to applications running bare-metal or in cloud platforms. The key component of INSANE is a userspace OS module, the INSANE runtime, that provides applications transparent access to a wide set of low-latency userspace networking, such as Linux XDP, DPDK, RDMA, in addition to standard kernel networking. The OS module runs as a separate process co-located with the applications and applications interact with it via shared-memory channels.

INSANE (<u>I</u>ntegrated a<u>N</u>d <u>S</u>elective <u>A</u>cceleration for the <u>N</u>etwork <u>E</u>dge) consists of two main components:
* A ***client library***, exposing a uniform API with a minimal set of communication primitives, yet expressive enough to let developers define high-level and domain-specific abstractions on top of them. Through a set of Quality of Service (QoS) parameters, applications can define differentiated network requirements for their data flows, such as latency-sensitiveness, reliability, and resource consumption. Within the same application, flows with different requirements can be mapped to different technologies.
* A ***userspace OS module***, working as a *network stack as a service* for applications and offering common services for high-performance networking, including memory management for zero-copy transfers, efficient packet processing, and different packet scheduling strategies. A plugin-based architecture allows the specialization of such abstractions for each integrated network acceleration technology. In particular, the high-level QoS requirements specified by applications are used to dynamically map the flows to the most appropriate acceleration technology that is dynamically available at the deployment site.

To get details about the system, read our paper in Middleware '23. If you use INSANE in your research, please cite us:
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

**The current version of INSANE only supports accelerated networking through DPDK and standard networking through kernel UDP. We are currently developing a new version that also supports RDMA and XDP plugins.**

## Installation

First, it is necessary to prepare the environment by installing the prerequisites. Then, it is possible to proceed with the project build.

### Prerequisites

* Ubuntu 22.04 or newer (we did not test other environments)
* CMake 3.0.0 or newer
* DPDK 22.11 (other versions might require small code changes)

In this first version of the prototype, we require DPDK to start even if it is not used by the applications. Newer releases will remove this constraint.

If you are going to use INSANE in CloudLab, please have a look at the [CloudLab section](#running-on-cloudlab) as we provide a ready-to-use profile with all the dependencies pre-installed. Otherwise, please look at the [DPDK installation script](scripts/install-dpdk.sh) to ease the installation of the prerequisites.


The current implementations also assumes that the two supported plugins run on separate networks. Hence, your environment must have **at least two network interfaces**: one for the kernel UDP plugin and one for the DPDK plugin. Ideally, the UDP plugin should run on a dedicated network separate from the one used as the management network, but that is not a mandatory requirement. For example, to run the INSANE runtime you will need:
* a network interface for the management network (e.g., `eno1`)
* a network interface for the kernel UDP plugin (e.g., `enp0s5`)
* a network interface for the DPDK plugin (e.g., `roce0`)

where `eno1` and `enp0s5` can actually be the same interface, if no dedicated network is available.

#### Limitations

* **Currently, INSANE only runs on two physical machines.** We are working on a new version that will support multiple machines.
* We tested the code only with **Mellanox NICs**. NICs from other vendors might work, but it is possible that small code changes are required.

To check whether the device is using the Mellanox driver, please run the command `dpdk-devbind.py` and check that the interface that will be used with DPDK (e.g., `roce0`) is bound to either the `mlx5_core` or the `mlx4_core` driver.

We are working on removing these limitations in the next release.

### Environment setup

Step 1. Please prepare the enviroment for DPDK by enabling the hugepages: 
```bash
echo 2048 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
```

Step 2. This step is not necessary if a Mellanox NIC is used, as we reccommend. Otherwise, the NIC to be used with DPDK must be bound to the ```vfio-pci``` driver. Please follow the instruction from the [DPDK documentation](https://doc.dpdk.org/guides/tools/devbind.html).

### Building the project

To build the code, `cd` into the `insane` directory and run:
* `mkdir build`
* `cd build`
* `cmake -DCMAKE_BUILD_TYPE=Release ..`
* ``make -j $(nproc)``

## Getting started

First, the INSANE runtime (nsnd) must be started. Then, applications can be started and attached to the runtime.

### Starting the INSANE runtime

Launch the INSANE runtime. Because we are using DPDK in PA IOVA mode, the use of **sudo** is required. You should pass four arguments to the runtime, the local and remote IP addresses of the considered nodes on the DPDK and of the UDP (sk) networks.
```bash
sudo taskset -c 0-2 ./nsnd [local_ip_dpdk] [dest_ip_dpdk] [local_ip_sk] [dest_ip_sk]
```

This daemon must be in execution in the same machine (or VM) of the applications that need acceleration.

**Troubleshoot**. If the INSANE runtime does not exit normally (e.g., if killed or crashed) it does not correctly clean the environment. That might prevent further executions to succeed. In that case, please remove the following files and try again:
```bash
sudo rm -rf /dev/shm/insane
sudo rm -rf /tmp/insane_control.socket
```

### Starting applications

Once the daemon is started, it is possible to start applications that connect to the runtime. Currently the repository provides one pre-built application which is used to test performance. See the section [Performance benchmarks](#performance-benchmarks) for more details. This application should also be considered as an example of how to use the INSANE client library from new applications.

<!-- ### Creating custom applications -->

## Performance benchmarks

A performance benchmark of INSANE is provided as part of this repository: [`example/nsn-perf`](examples/nsn_perf.c). This test can be invoked using the following parameters:

```bash
Usage: nsn-perf [MODE] [OPTIONS]
MODE: source|sink|ping|pong
OPTIONS:
-h: display this message and exit
-s: message payload size in bytes
-n: max messages to send (0 = no limit)
-q: quality. Can be fast or slow
-t: specify app-defined source id
-r: configure sleep time (s) in send
```

The ``ping`` and ``pong`` couple is used to launch a latency test, whereas the ``source`` and ``sink`` couple is used to launch a throughput test, as better explained in the following. 

### Micro-benchmarks

A **latency test** can be performed by launching the ``nsn-perf`` applications on two nodes: one with the ``pong`` role (working as server) and one with ``ping`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.

For instance:
```bash
# On the server node
sudo taskset -c 0-2 ./nsn-perf pong -s 64 -n 1000000 -q fast
# On the client node
sudo taskset -c 0-2 ./nsn-perf ping -s 64 -n 1000000 -q fast
```

The output of the test is, on the client side, a set number that represent the Round-Trip Time, in microseconds, measured for each message sent and received back. In the paper, we used this number to generate the latency graphs in the microbenchmarking section.

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

Please note that INSANE, in the current prototype, does not implement any for of reliability. Hence, especially in the thoughput test, UDP packets can be lost if they exceed the NICs or the switch capacity. If you observe that the sink is not receiving all the packets, that might be the reason. One workaround is to make the source send more messages than expected in the sink. We are planning to add reliability support in the next release of INSANE.

To reproduce the experiment with **multiple subscribers**, it is possible to launch multiple instances of the ``nsn-perf`` application on the same node.

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

The LUNAR applications are example applications built to show the ease of programming guaranteed by INSANE with no performance compromises. The two applications are a Message-oriented Middleware (MoM) and an image streaming framework. In the following we explain how to launch them to reproduce the experiments reported in the paper.

Please remind that these applications attach to the INSANE runtime, so the runtime must be started first. Please refer to the [Starting the INSANE runtime](#starting-the-insane-runtime) section for more details.

We plan to document soon how the LUNAR applications are designed internally.

#### LUNAR MoM

The code of LUNAR MoM is located in [```apps/lunar```](apps/lunar). The MoM gives the possibility to create topics and have other INSANE applications to publish or subscribe on them. By relying on the INSANE API, this MoM is very simple and exposes a very intuitive and easy-to-use interface.

Together with the MoM code, there is also a simple test application that can be used to test the MoM performance:  [```lunar-perftest```](apps/lunar/lunar_perftest.c). This application provides both a latency and a throughput test with the same semantic as the [```nsn-perf```](examples/nsn_perf.c) application. Both these tests create a topic and publish/subscribe on it. The topic name can be passed as an argument to the application.

A **latency test** can be performed by launching the ``lunar-perftest`` applications on two nodes: one with the ``subpub`` role (working as server) and one with ``pubsub`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.
A **throughput test** can be performed by launching the ``lunar-perftest`` applications on two nodes: one with the ``sub`` role (working as server) and one with ``pub`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.

For instance, you can launch the latency test as:
```bash
# On the server node
sudo taskset -c 0-2 ./lunar-perftest subpub -s 64 -n 1000000 -q fast
# On the client node
sudo taskset -c 0-2 ./lunar-perftest pubsub -s 64 -n 1000000 -q fast
```

#### LUNAR Stream

The code of LUNAR Stream is located in [```apps/lunar```](apps/lunar). Lunar Streaming exposes a simple set of APIs, starting with ```lnr_s_open_server``` to open the server-side application and with ```lnr_s_connect``` that allows clients to connect to it. Thus, the server application must implement a simple interface by exposing two methods: ```get_frame``` and ```wait_next```. The first allows to get a new frame, while the second pauses the server waiting for the next frame. To start streaming, the server application must invoke ```lnr_s_loop``` which performs the following steps: 
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

To run on CloudLab, we suggest to select an hardware type that supports at least two experimental LANs, so that it is possible to test the same application with UDP/IP and DPDK. Please do not use the management network for the experiment traffic. To use DPDK, we tested our code with Mellanox hardware only, so please try to select a node with Mellanox NICs. 

We performed our tests using the [d6515](https://docs.cloudlab.us/hardware.html) hardware, but others with similar characteristics should work as well (e.g., c6525-100g, c6525-25g, r7525). To ease the testing, we created a [CloudLab profile](https://www.cloudlab.us/p/INSANEProject/Ubuntu22.04-TwoLANs) for two nodes that use Ubuntu 22.04, with two suitable LANs already configured, and DPDK 22.11 already installed. If you use that image, we reccommend using the 192.168.0.0/16 network for DPDK and the 10.0.0.0/16 for kernel UDP. 

Once instantiated, you can proceed with the installation of the prerequisites (see the [Prerequisites](#prerequisites) section) and the build of the project (see the [Building the project](#building-the-project) section).

A second important note is that on CloudLab it is possible that DPDK, by default, gets ownership of all the Mellanox cards on the machine. If that includes the management interface (used for ssh), access to the node is lost. To avoid this behavior, there is a simple workaround:
1. Get the PCI address of the interface used for DPDK interface (e.g., `roce0` in our previous example) by running the command `dpdk-devbind --status`.
2. When launching the INSANE runtime and applications, pass this address as an environment variable `DPDK_PCI`. E.g.:

```bash
sudo DPDK_PCI=<pci_addr> taskset -c 0-2 ./nsnd [local_ip_dpdk] [dest_ip_dpdk] [local_ip_sk] [dest_ip_sk]
```

We have prepared a step-by-step guide to run INSANE on CloudLab, that is available [here](docs/Cloudlab-detailed-guide.pdf).

## Running on Azure

We support the deployment of INSANE on Azure. However, the use of DPDK in Azure requires some different steps from those described in this guide and also some code modifications. We are going to release soon the associated instructions, but please email us if you are interested in trying it out.

