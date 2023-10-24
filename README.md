# INSANE: A Unified Middleware for QoS-aware Network Acceleration in Edge Cloud Computing

INSANE is a research prototype that provides *Network Acceleration as a Service* to applications running bare-metal or in cloud platforms. The key component of INSANE is a userspace OS module, the INSANE runtime, that provides applications transparent access to a wide set of low-latency userspace networking, such as Linux XDP, DPDK, RDMA, in addition to standard kernel networking. The OS module runs as a separate process co-located with the applications and applications interact with it via shared-memory channels.

INSANE (<u>I</u>ntegrated a<u>N</u>d <u>S</u>elective <u>A</u>cceleration for the <u>N</u>etwork <u>E</u>dge) consists of two main components:
* A ***client library***, exposing a uniform API with a minimal set of communication primitives, yet expressive enough to let developers define high-level and domain-specific abstractions on top of them. Through a set of Quality of Service (QoS) parameters, applications can define differentiated network requirements for their data flows, such as latency-sensitiveness, reliability, and resource consumption. Within the same application, flows with different requirements can be mapped to different technologies.
* A ***userspace OS module***, working as a *network stack as a service* for applications and offering common services for high-performance networking, including memory management for zero-copy transfers, efficient packet processing, and different packet scheduling strategies. A plugin-based architecture allows the specialization of such abstractions for each integrated network acceleration technology. In particular, the high-level QoS requirements specified by applications are used to dynamically map the flows to the most appropriate acceleration technology that is dynamically available at the deployment site.

To get details about the system, read our paper in Middleware '23. If you use INSANE in your research, please cite us:
```bibtex
@inproceedings{insane,
author = {Rosa, Lorenzo and Garbugli, Andrea and Corradi, Antonio and Bellavista, Paolo},
title = {INSANE: A Unified Middleware for QoS-aware Network Acceleration in Edge Cloud Computing},
year = {2023},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3590140.3629105},
doi = {10.1145/3590140.3629105},
booktitle = {Proceedings of the 24rd ACM/IFIP International Middleware Conference},
pages = {14},
location = {Bologna, Italy},
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

If you are going to use INSANE in CloudLab, please have a look at the [CloudLab section](#running-on-cloudlab).\
In this first version of the prototype, we require DPDK to start even if it is not used by the applications. Newer releases will remove this constraint.

The current implementations also assumes that the two supported plugins run on separate networks. Hence, your environment must have **at least two network interfaces**: one for the kernel UDP plugin and one for the DPDK plugin. Ideally, the UDP plugin should run on a dedicated network separate from the one used as the management network, but that is not a mandatory requirement. For example, to run the INSANE runtime you will need:
* a network interface for the management network (e.g., `eno1`)
* a network interface for the kernel UDP plugin (e.g., `enp0s5`)
* a network interface for the DPDK plugin (e.g., `roce0`)

where `enp0s3` and `enp0s8` can actually be the same interface, if no dedicated network is available.

**Currently, INSANE only runs on two physical machines.** We are working on a new version that will support multiple machines.

### Environment setup

Please prepare the enviroment for DPDK by enabling the hugepages: 
```bash
echo 2048 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
```

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
sudo ./nsnd [local_ip_dpdk] [dest_ip_dpdk] [local_ip_sk] [dest_ip_sk]
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
sudo taskset -c 0 ./nsn-perf pong -s 64 -n 1000000 -q fast
# On the client node
sudo taskset -c 0 ./nsn-perf ping -s 64 -n 1000000 -q fast
```

The output of the test is, on the client side, a set number that represent the Round-Trip Time, in microseconds, measured for each message sent and received back. In the paper, we used this number to generate the latency graphs in the microbenchmarking section.

A **throughput test** can be performed by launching the ``nsn-perf`` applications on two nodes: one with the ``sink`` role (working as server) and one with ``source`` role, working as client. To improve performance, please launch the test using the ``taskset`` command to pin the application to a specific set of core, that must be on the same NUMA node.

For instance:
```bash
# On the server node
sudo taskset -c 0 ./nsn-perf sink -s 1024 -n 1000 -q fast
# On the client node
sudo taskset -c 0 ./nsn-perf source -s 1024 -n 1000 -q fast
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

The instructions of how to run the two Lunar applications will be available soon.

## Running on CloudLab

Few modifications are required to run on CloudLab: you must apply a specific [patch](cloudlab_eval.diff).

## Running on Azure

We support the deployment of INSANE on Azure. We are going to release soon the associated instructions, but please email us if you are interested in trying it out.

