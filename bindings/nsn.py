import ctypes
from ctypes import c_uint32, c_size_t, c_int, c_void_p, POINTER, Structure

# Define the structs
class nsn_hdr_t(Structure):
    _fields_ = [("channel_id", c_uint32)]


class nsn_buffer_t(Structure):
    _fields_ = [("index", c_size_t),
                ("data", POINTER(c_void_p)),
                ("len", c_size_t)]


class nsn_options_t(Structure):
    _fields_ = [("datapath", c_int),
                ("consumption", c_int),
                ("determinism", c_int),
                ("reliability", c_int)]

# Define constants
NSN_ERROR_ALREADY_INITIALIZED = 1
NSN_ERROR_NOT_INITIALIZED = 2

NSN_QOS_DATAPATH_DEFAULT = 0x0
NSN_QOS_DATAPATH_FAST = 0x1

NSN_QOS_CONSUMPTION_LOW = 0x0
NSN_QOS_CONSUMPTION_POLL = 0x1

NSN_QOS_DETERMINISM_DEFAULT = 0x0
NSN_QOS_DETERMINISM_TIMESENSITIVE = 0x1

NSN_QOS_RELIABILITY_UNRELIABLE = 0x0
NSN_QOS_RELIABILITY_RELIABLE = 0x1

NSN_INVALID_SNK = 0xFFFFFFFF
NSN_INVALID_SRC = 0xFFFFFFFF
NSN_INVALID_STREAM_HANDLE = 0xFFFFFFFF
NSN_INVALID_PLUGIN_HANDLE = 0xFFFFFFFF

NSN_BLOCKING = 0x1
NSN_NONBLOCKING = 0x2

# Load the shared library
# Replace 'your_library_name' with the actual library file name (e.g., 'libnsn.so' or 'nsn.dll')
nsn_lib = ctypes.CDLL('./libnsn.so')

# Define function prototypes
init = nsn_lib.nsn_init
init.restype = c_int

close = nsn_lib.nsn_close
close.restype = c_int

create_stream = nsn_lib.nsn_create_stream
create_stream.argtypes = [nsn_options_t]
create_stream.restype = c_uint32  # nsn_stream_t

destroy_stream = nsn_lib.nsn_destroy_stream
destroy_stream.argtypes = [c_uint32]  # nsn_stream_t
destroy_stream.restype = c_int

create_source = nsn_lib.nsn_create_source
create_source.argtypes = [c_uint32, c_uint32]  # nsn_stream_t*, uint32_t
create_source.restype = c_uint32  # nsn_source_t

destroy_source = nsn_lib.nsn_destroy_source
destroy_source.argtypes = [c_uint32]  # nsn_source_t
destroy_source.restype = c_int

get_buffer = nsn_lib.nsn_get_buffer
get_buffer.argtypes = [c_size_t, c_int]  # size_t, int
get_buffer.restype = POINTER(nsn_buffer_t)

emit_data = nsn_lib.nsn_emit_data
emit_data.argtypes = [c_uint32, POINTER(nsn_buffer_t)]  # nsn_source_t, nsn_buffer_t
emit_data.restype = c_int

check_emit_outcome = nsn_lib.nsn_check_emit_outcome
check_emit_outcome.argtypes = [c_uint32, c_int]  # nsn_source_t, int
check_emit_outcome.restype = c_int

create_sink = nsn_lib.nsn_create_sink
create_sink.argtypes = [c_uint32, c_uint32, c_void_p]  # nsn_stream_t*, uint32_t, handle_data_cb
create_sink.restype = c_uint32  # nsn_sink_t

destroy_sink = nsn_lib.nsn_destroy_sink
destroy_sink.argtypes = [c_uint32]  # nsn_sink_t
destroy_sink.restype = c_int

data_available = nsn_lib.nsn_data_available
data_available.argtypes = [c_uint32, c_int]  # nsn_sink_t, int
data_available.restype = c_int

consume_data = nsn_lib.nsn_consume_data
consume_data.argtypes = [c_uint32, c_int]  # nsn_sink_t, int
consume_data.restype = POINTER(nsn_buffer_t)

release_data = nsn_lib.nsn_release_data
release_data.argtypes = [POINTER(nsn_buffer_t)]
release_data.restype = c_int
