# INSANE REST API Documentation

## Overview

The INSANE middleware includes an integrated RESTful HTTP server (based on CivetWeb) to expose internal status and allow runtime reconfiguration. Hence, INSANE depends on the CivetWeb and cJSON libraries, which must be installed prior to building INSANE using the provided script (see [INSANE prerequisites](../README.md#prerequisites)).

## Configuration

The INSANE configuration file (e.g., `nsnd.cfg`) includes a `[rest]` section to configure the REST server:
```
[rest]
port=8080
host="localhost"
```
- `port`: TCP port number where the REST server listens (default: `8080`)
- `host`: IP address or hostname to bind the REST server (default: `localhost`)

## Endpoints

### 1. `GET /plugins/streams`

**Purpose:** Retrieve the list of active plugins and their associated streams.

**Response Format:** JSON

**Details:**  
Returns the current state of the middleware, listing for each plugin all active streams with their respective sources and sinks.

### 2. `POST /change/qos`

**Purpose:** Change the QoS parameters of an active stream.

**Request Body (JSON):**
```json
{
  "app_id": "<application_identifier>",
  "<qos>": "<desired_qos_level>"
}
```

**Behavior:**
- Changes the `<qos>` quality of the `app_id` to the specified level. E.g:
```json
{
  "app_id": "4444",
  "reliability": "reliable"
}
```
- Suspends or resumes dataplane threads as necessary.
- Responds with HTTP status indicating the outcome of the operation.

## Field Reference

### `app_id`

Must be the L4 port number specified in the INSANE configuration file. This port acts as the unique identifier to establish and isolate the overlay network for the corresponding application.

### QoS Parameters

| Field         | Accepted Values      | Description                                                                 |
|---------------|----------------------|-----------------------------------------------------------------------------|
| `reliability` | `reliable`, `unreliable` | Indicates the desired delivery semantics. In practice, it distinguishes between the TCP (reliable) and UDP (unreliable) transport protocols.        |
| `consumption` | `low`, `poll`        | Controls resource usage: `low` minimizes CPU load; `poll` enables busy-polling for low-latency. |
| `determinism` | `timesensitive`, `default` | Enables time-aware scheduling (e.g., TSN) for deterministic flows.         |
| `acceleration`| `fast`, `default`    | Requests backend network acceleration (e.g., DPDK, RDMA) when `fast` is set. |

Each field is optional and independent. Policies are used as soft constraints and applied based on plugin availability and runtime conditions.

The combination of QoS parameters dynamically determines the network backend selected by INSANE for each communication stream. At runtime, the middleware evaluates the QoS fields as soft constraints. If acceleration=fast is specified, the system attempts to use a kernel-bypass backend (e.g., RDMA, DPDK, XDP) based on local availability. Among these, RDMA is prioritized when available. If consumption=low is set, plugins with lower CPU footprint (e.g., XDP over DPDK) are preferred. In the absence of acceleration, standard kernel-based UDP is used. Deterministic flows (determinism=timesensitive) are scheduled with TSN support if the backend and NIC support it. The selection algorithm ensures fallback to default networking stacks when constraints cannot be satisfied, preserving communication while optimizing for performance where possible.

**Example: Switching from kernel-based TCP/UDP (`udpsock`) to accelerated DPDK-based UDP (`udpdpdk`)**

To instruct INSANE to switch a stream from using the standard kernel UDP stack (`udpsock`) to the DPDK plugin (`udpdpdk`), issue a `POST` request to `/change/qos` with the following JSON payload:

```json
{
  "app_id": "4444",
  "acceleration": "fast",
  "consumption": "poll",
  "reliability": "unreliable"
}
```

This request sets `acceleration=fast` to prefer kernel-bypass backends and `consumption=poll` to allow CPU-intensive busy-polling strategies required by DPDK. The `reliability=unreliable` matches UDP semantics. Assuming the runtime has DPDK available, the stream will be transparently migrated from `udpsock` to `udpdpdk`. If `acceleration` were set to `default`, the system would instead revert to the kernel UDP stack.

## Implementation Notes

- The server uses CivetWeb for multithreaded, embedded web serving.
- REST server lifecycle is tied to that of the INSANE daemon.
- The `determinism` QoS parameter is currently not implemented.