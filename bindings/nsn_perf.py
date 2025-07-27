#!/usr/bin/env python3
# filepath: /home/agarbugli/dev/insane-v2/apps/nsn_app_perf.py

import argparse
import ctypes
import signal
import sys
import time
from enum import Enum

import prometheus_client as prom

import nsn

# Constants
MSG = "That's INSANE!"
MAX_PAYLOAD_SIZE = 1472
MIN_PAYLOAD_SIZE = 16

# Global variables
running = True
latency_metrics = None
registry = None
metric_filename = "/var/lib/node_exporter/textfile_collector/nsn_ping_latency_#{id}.prom"

class Role(Enum):
    SINK = 0
    SOURCE = 1
    PING = 2
    PONG = 3

class TestData(ctypes.Structure):
    _fields_ = [
        ("cnt", ctypes.c_uint64),
        ("tx_time", ctypes.c_uint64)
    ]

class TestConfig:
    def __init__(self):
        self.role = Role.SINK
        self.payload_size = len(MSG) + 1
        self.qos_name = "slow"
        self.qos_datapath = nsn.NSN_QOS_DATAPATH_DEFAULT
        self.qos_reliability = nsn.NSN_QOS_RELIABILITY_UNRELIABLE
        self.app_source_id = 0
        self.sleep_time = 0
        self.max_msg = 0
        self.id = 0

def get_clock_realtime_ns():
    """Get current time in nanoseconds."""
    return time.time_ns()

def signal_handler(sig, frame):
    """Handle Ctrl+C signal."""
    print("Received CTRL+C. Exiting!")
    global running
    running = False

def buffer_is_valid(buf):
    """Check if buffer is valid."""
    return buf and buf.contents

def send_metrics(config, latency):
    # Update the metric in the registry
    latency_metrics.labels(role=config.role.name, id=config.id, qos=config.qos_name).set(latency)
    prom.write_to_textfile(metric_filename, registry)
 
def do_source(stream, config):
    """Source role: Send data continuously."""
    counter = 0
    source = nsn.create_source(stream, config.app_source_id)
    
    while running and (config.max_msg == 0 or counter < config.max_msg):
        if config.sleep_time:
            time.sleep(config.sleep_time)
            
        tx_time = get_clock_realtime_ns()
        buf = nsn.get_buffer(config.payload_size, 0)
        
        if buffer_is_valid(buf):
            # Access the buffer data through ctypes
            data_ptr = ctypes.cast(buf.contents.data, ctypes.POINTER(TestData))
            data = data_ptr.contents
            data.tx_time = tx_time
            data.cnt = counter
            counter += 1
            
            buf.contents.len = config.payload_size
            
            ret = nsn.emit_data(source, buf)
    
    print(f"Finished sending {counter} messages. Exiting...")
    nsn.destroy_source(source)

def do_sink(stream, config):
    """Sink role: Receive data continuously and measure throughput."""
    sink = nsn.create_sink(stream, config.app_source_id, None)
    first_time = 0
    last_time = 0
    
    print("Ready to receive packets")
    counter = 0
    
    while running and (config.max_msg == 0 or counter < config.max_msg):
        buf = nsn.consume_data(sink, nsn.NSN_BLOCKING)
        
        if not buffer_is_valid(buf):
            continue
            
        if counter == 0:
            first_time = get_clock_realtime_ns()
        
        counter += 1
        nsn.release_data(buf)
    
    last_time = get_clock_realtime_ns()
    
    # Compute results
    elapsed_time_ns = last_time - first_time
    mbps = ((counter * config.payload_size * 8) * 1e3) / elapsed_time_ns
    throughput = (counter * 1e3) / elapsed_time_ns
    
    # Print results
    print(f"""
[ TEST RESULT ]                 
Received messages:   {counter}        
Elapsed time:        {elapsed_time_ns / 1e6:.3f} ms    
Measured throughput: {throughput:.3f} Mmsg/s
Measured bandwidth:  {mbps:.3f} Mbps  
""")
    
    print(f"{counter},{config.payload_size},{elapsed_time_ns / 1e6:.3f},{throughput:.3f},{mbps:.3f}")
    nsn.destroy_sink(sink)

def do_ping(stream, config):
    """Ping role: Send data and measure round-trip latency."""
    sink = nsn.create_sink(stream, config.app_source_id, None)
    source = nsn.create_source(stream, config.app_source_id)
    
    counter = 0
    
    if config.payload_size < ctypes.sizeof(TestData):
        print("Payload size too small", file=sys.stderr)
        return
    
    global running
    while running and (config.max_msg == 0 or counter < config.max_msg):
        if config.sleep_time:
            time.sleep(config.sleep_time)
        
        buf_send = nsn.get_buffer(config.payload_size, nsn.NSN_BLOCKING)
        send_time = get_clock_realtime_ns()
        
        if not buffer_is_valid(buf_send):
            print("Failed to get buffer", file=sys.stderr)
            continue
        
        # Fill the buffer with test data
        data_ptr = ctypes.cast(buf_send.contents.data, ctypes.POINTER(TestData))
        data = data_ptr.contents
        data.cnt = counter
        data.tx_time = send_time
        buf_send.contents.len = config.payload_size
        
        nsn.emit_data(source, buf_send)
        
        buf_recv = nsn.consume_data(sink, nsn.NSN_BLOCKING)
        response_time = get_clock_realtime_ns()
        
        if buffer_is_valid(buf_recv):
            latency = response_time - send_time
            nsn.release_data(buf_recv)
            
            # Print latency in microseconds (divided by 1000)
            latency_us = latency / 1000.0
            print(f"{latency_us:.3f}")
            send_metrics(config, latency_us)
        
        counter += 1

    # Clean up Prometheus metrics
    print("Cleaning up Prometheus metrics")
    latency_metrics.set(0)
    registry.unregister(latency_metrics)
    del latency_metrics
    del registry
                
    nsn.destroy_sink(sink)
    nsn.destroy_source(source)

def do_pong(stream, config):
    """Pong role: Echo back received data."""
    sink = nsn.create_sink(stream, config.app_source_id, None)
    source = nsn.create_source(stream, config.app_source_id)
    
    counter = 0
    
    while running and (config.max_msg == 0 or counter < config.max_msg):
        buf = nsn.consume_data(sink, nsn.NSN_BLOCKING)
        
        if not buffer_is_valid(buf):
            print("Failing to receive. Continuing...", file=sys.stderr)
            continue
        
        counter += 1
        nsn.emit_data(source, buf)
    
    nsn.destroy_sink(sink)
    nsn.destroy_source(source)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="INSANE middleware test application")
    parser.add_argument("role", choices=["sink", "source", "ping", "pong"], 
                        help="Running mode")
    parser.add_argument("-s", "--size", type=int, default=len(MSG) + 1,
                        help=f"Message payload size in bytes (default: {len(MSG) + 1})")
    parser.add_argument("-n", "--num-msg", type=int, default=0,
                        help="Max messages to send (0 = no limit)")
    parser.add_argument("-q", "--qos-dp", choices=["slow", "fast"], default="slow",
                        help="Datapath QoS")
    parser.add_argument("-r", "--qos-rel", action="store_true",
                        help="Enable reliable QoS")
    parser.add_argument("-a", "--app-source-id", type=int, default=0,
                        help="App-defined source id")
    parser.add_argument("-t", "--sleep-time", type=int, default=0,
                        help="Sleep time (s) in send")
    parser.add_argument("-i", "--id", type=int, default=0, help="App ID to use with Prometheus")
    
    args = parser.parse_args()
    
    # Create config
    config = TestConfig()
    config.role = getattr(Role, args.role.upper())
    config.payload_size = args.size
    config.qos_name = args.qos_dp
    config.qos_datapath = nsn.NSN_QOS_DATAPATH_FAST if args.qos_dp == "fast" else nsn.NSN_QOS_DATAPATH_DEFAULT
    config.qos_reliability = nsn.NSN_QOS_RELIABILITY_RELIABLE if args.qos_rel else nsn.NSN_QOS_RELIABILITY_UNRELIABLE
    config.app_source_id = args.app_source_id
    config.sleep_time = args.sleep_time
    config.max_msg = args.num_msg
    config.id = args.id
    
    # Validate config
    if config.payload_size <= MIN_PAYLOAD_SIZE or config.payload_size > MAX_PAYLOAD_SIZE:
        parser.error(f"Payload size must be between {MIN_PAYLOAD_SIZE} and {MAX_PAYLOAD_SIZE}")
    
    return config

def main():
    config = parse_arguments()
    
    print("Welcome to the test application of the INSANE middleware")
    
    # Print configuration
    print(f"""
Running with the following arguments:
    Role............. : {Role(config.role).name}
    Payload size..... : {config.payload_size}
    Max messages..... : {config.max_msg}
    Datapath QoS..... : {"Fast" if config.qos_datapath == nsn.NSN_QOS_DATAPATH_FAST else "Slow"}
    Reliability QoS.. : {"Reliable" if config.qos_reliability == nsn.NSN_QOS_RELIABILITY_RELIABLE else "Unreliable"}
    Source id........ : {config.app_source_id}
    Sleep time....... : {config.sleep_time}
    """)

    if config.role == Role.PING:
        print("Setting up Prometheus metrics")
        global latency_metrics
        latency_metrics = prom.Gauge("nsn_latency", "Latency in microseconds", ["role", "id", "qos"])
        global registry
        registry = prom.CollectorRegistry(auto_describe=False)
        registry.register(latency_metrics)
    
    # Initialize the NSN library
    if nsn.init() < 0:
        print("Cannot init INSANE library", file=sys.stderr)
        return -1
    
    # Create options and stream
    options = nsn.nsn_options_t(
        datapath=config.qos_datapath,
        consumption=nsn.NSN_QOS_CONSUMPTION_POLL,
        determinism=nsn.NSN_QOS_DETERMINISM_DEFAULT,
        reliability=config.qos_reliability
    )
    stream = nsn.create_stream(options)
    
    # Execute the appropriate function based on role
    if config.role == Role.SINK:
        do_sink(stream, config)
    elif config.role == Role.SOURCE:
        do_source(stream, config)
    elif config.role == Role.PING:
        metric_filename.replace("#{id}", str(config.id))

        do_ping(stream, config)

    elif config.role == Role.PONG:
        do_pong(stream, config)
    else:
        print("Test not supported", file=sys.stderr)
        return -1
    # Clean up
    nsn.destroy_stream(stream)
    nsn.close()
    return 0

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    sys.exit(main())