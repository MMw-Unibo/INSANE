import ctypes
import nsn

# Initialize the INSANE session
nsn.init()

# Create QoS options
opts = nsn.nsn_options_t()
opts.datapath = nsn.NSN_QOS_DATAPATH_DEFAULT
opts.consumption = nsn.NSN_QOS_CONSUMPTION_LOW
opts.determinism = nsn.NSN_QOS_DETERMINISM_DEFAULT
opts.reliability = nsn.NSN_QOS_RELIABILITY_UNRELIABLE

# Create a stream
stream = nsn.create_stream(opts)

# Create a source
source_id = 0  # Example source ID
source = nsn.create_source(stream, source_id)

# Get a buffer (allocate a buffer of size 32)
buffer_size = 32
flags = nsn.NSN_BLOCKING  # Use blocking mode
buffer = nsn.get_buffer(buffer_size, flags)

# Check if the buffer is valid
if buffer is not None:
    # Fill the buffer with 32 'a' characters
    # Note: The buffer's data field is a pointer, so we need to access it
    # and fill it with 'a's. We assume the buffer's data is a uint8_t*.
    data_ptr = ctypes.cast(buffer.contents.data, ctypes.POINTER(ctypes.c_char))
    for i in range(buffer_size):
        data_ptr[i] = b'a'  # Fill with 'a'

    # Set the buffer length
    buffer.contents.len = buffer_size

    # Emit the data
    emit_result = nsn.emit_data(source, buffer)

    # Check the result of the emit operation
    if emit_result >= 0:
        print("Data emitted successfully.")
    else:
        print("Failed to emit data.")

    # Release the buffer after use
    nsn.release_data(buffer)
else:
    print("Failed to get a valid buffer.")

# Destroy the source
nsn.destroy_source(source)

# Destroy the stream
nsn.destroy_stream(stream)

# Close the INSANE session
nsn.close()
