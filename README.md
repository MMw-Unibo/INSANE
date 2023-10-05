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
url = {XXX},
doi = {XXX},
booktitle = {Proceedings of the 24rd ACM/IFIP International Middleware Conference},
pages = {---},
numpages = {---},
location = {Bologna, Italy},
series = {Middleware '23}
}
```

**The current version of INSANE only supports accelerated networking through DPDK and standard networking through kernel UDP. We are currently developing a new version that also supports RDMA and XDP plugins.**

**We also plan to allow applications to transparently attach to INSANE through the standard POSIX Socket API.**


## Installation

After preparing the environment by installing the prerequisites, you can build the project.

### Prerequisites

* Ubuntu 22.04 or newer (we did not test other environments)
* CMake 3.0.0 or newer
* DPDK 22.11 (other versions might require small code changes)

If you are going to use INSANE in CloudLab, please have a look at the [CloudLab section](#running-on-cloudlab).\
In this first version of the prototype, we require DPDK to start even if it is not used by the applications. Newer releases will remove this constraint.

### Environment setup

Please prepare the enviroment for DPDK. 

### Building the project

to build the code, `cd` into the `insane` directory and run:
* `mkdir build`
* `cd build`
* `cmake -DCMAKE_BUILD_TYPE=Release ..`
* ``make -j $(nproc)``

## Getting started

### Starting the INSANE runtime

### Creating custom applications

### Starting applications

## Performance benchmarks
### Micro-benchmarks
### Comparison with Demikernel
### Lunar applications

## Running on CloudLab

Few modifications are required to run on CloudLab: you must apply a specific [patch](cloudlab_eval.diff).

## Running on Azure

We support the deployment of INSANE on Azure. We are going to release soon the associated instructions.

