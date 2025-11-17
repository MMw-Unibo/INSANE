#ifndef LUNAR_MQTT_PACK_H
#define LUNAR_MQTT_PACK_H

#include <stddef.h>
#include <stdint.h>

/* Reading data on const uint8_t pointer */
// bytes -> uint8_t
uint8_t unpack_u8(const uint8_t **buf);
// bytes -> uint16_t
uint16_t unpack_u16(const uint8_t **buf);
// bytes -> uint32_t
uint32_t unpack_u32(const uint8_t **buf);
// read a defined len of bytes
uint8_t *unpack_bytes(const uint8_t **buf, size_t, uint8_t *);
// Unpack a string prefixed by its length as a uint16 value
uint16_t unpack_string16(uint8_t **buf, uint8_t **dest);

/* Write data on const uint8_t pointer */
// append a uint8_t -> bytes into the bytestring
void pack_u8(uint8_t **buf, uint8_t val);
// append a uint16_t -> bytes into the bytestring
void pack_u16(uint8_t **buf, uint16_t val);
// append a uint32_t -> bytes into the bytestring
void pack_u32(uint8_t **buf, uint32_t val);
// append len bytes into the bytestring
void pack_bytes(uint8_t **buf, uint8_t *str);

#endif // LUNAR_MQTT_PACK_H