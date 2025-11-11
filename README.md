# INSANE

INSANEv2 is the second version of a research prototype that provides *Network Acceleration as a Service* to cloud applications. The key component of INSANE is a userspace OS module, the INSANE runtime, that provides transparent access to a wide set of low-latency userspace networking, such as Linux XDP, DPDK, RDMA, in addition to standard kernel networking. The OS module runs as a separate process co-located with the applications and applications interact with it via shared-memory channels.

INSANE (<u>I</u>ntegrated a<u>N</u>d <u>S</u>elective <u>A</u>cceleration for the <u>N</u>etwork <u>E</u>dge) consists of two main components:
* A ***client library***, exposing a uniform API with a minimal set of communication primitives, yet expressive enough to let developers define high-level and domain-specific abstractions on top of them. Through a set of Quality of Service (QoS) parameters, applications can define differentiated network requirements for their data flows, such as latency-sensitiveness, reliability, and resource consumption. Within the same application, flows with different requirements can be mapped to different technologies.
* A ***userspace OS module***, working as a *network stack as a service* for applications and offering common services for high-performance networking, including memory management for zero-copy transfers, efficient packet processing, and different packet scheduling strategies. A plugin-based architecture allows the specialization of such abstractions for each integrated network acceleration technology. In particular, the high-level QoS requirements specified by applications are used to dynamically map the flows to the most appropriate acceleration technology that is dynamically available at the deployment site.

## Getting started

### Prerequisites
First, it is necessary to prepare the environment and to install the prerequisites:
* Ubuntu 22.04 or newer (we did not test other environments)
* The following packages: `cmake` and `pkg-config` (you can install them via `sudo apt install cmake pkg-config`)
* Setup hugepages (you need root access) ([script](scripts/hugepages.sh))
* Install cJSON and citiweb as required by the REST support ([script](scripts/install-rest.sh))

Depending on which network stack you will use, you might also want to install:
* DPDK 22.11 ([script](scripts/install-dpdk.sh))
* TLDK ([script](scripts/install-tldk.sh)), only after DPDK.
We suggest to perform a local installation by creating a $INSANE_DIR/deps folder, and passing its path to the above scripts. In the building scripts, we assume that setup.

Then, it is possible to proceed with the project build.

### Build the project

To build the code, `cd` into the `insane` directory and run:
* `./build.sh [debug|release]`

Those commands will create the executables in a folder called `build`. You can `cd` into it to see the results: the daemon executable (`nsnd`) and a demo application (`nsn-app`).

Although the binaries created with the above scripts are standalone, INSANE requires *at least one datapath plugin* to be available for applications to communicate with remote peers. A *datapath plugin* is a library that specializes the INSANE communication abstraction for a specific protocol/hardware combination. These libraries must be compiled and be available at runtime.

The code for the available *datapath plugin* is in the [`datapath`](datapaths) folder.  You can `cd` into that folder and call the `datapath/build.sh` script to compile one or all of them.

## Running INSANE

### Running the daemon

Before starting the daemon, you need to provide a few configuration parameters in a configuration file. An [example](configs/nsnd.cfg) is provided. By default, the daemon will look for a `nsnd.cfg` file in its working directory. You can specify a different file location by using the `--config` command line argument. You need to fill out the configuration file with the correct parameters for your machine.

Then, invoke the the daemon executable (`nsnd`).

### Running the demo application

Once the daemon is running on a machine, you can run multiple INSANE-based applications on that machine. To start the demo application, you can invoke `nsn-app`.


## Plugins

### DPDK plugins

To fully support a DPDK-based plugin and still guarantee the flexibility of INSANE, we had to modify a few lines of the driver of the Mellanox card (mlx5). Hence, we provide a [diff file](dpdk_22_11_mods.diff) that contains the changes we made to the driver source code. You can apply this patch to the DPDK source code before building it.

Furthermore, if you are using a Mellanox card for the DPDK plugin, you need to explicitly disable the use of vectorial instructions, as it conflicts with the features we use in the DPDK plugin. To do so, add the following parameter to the DPDK configuration (i.e., the `eal_args` string) in the INSANE daemon configuration file: `-a <pcie_addr>,rx_vec_en=0`, where `<pcie_addr>` is the PCI address of the Mellanox card (e.g., `0000:05:00.0`).

## REST API
The INSANE daemon provides a REST API to monitor and control its operations. The API is documented in the [dedicated](docs/rest.md) file.