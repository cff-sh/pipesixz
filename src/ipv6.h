/*
 * ipv6.h - IPv6 Packet Parsing Utilities
 *
 * Provides lightweight utilities for parsing IPv6 packet headers.
 * Used primarily for logging and diagnostic purposes to extract
 * source and destination addresses, payload protocol, and packet
 * length from raw IPv6 packets read from or written to the TUN
 * device.
 *
 * This module operates purely on packet data and does not perform
 * any OS interaction.
 *
 * IPv6 Header Reference:
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |Version| Traffic Class |           Flow Label                  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Payload Length        |  Next Header  |   Hop Limit   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                         Source Address                        +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                                                               |
 *   +                      Destination Address                      +
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#ifndef PIPESIX_IPV6_H
#define PIPESIX_IPV6_H

#include <stddef.h>
#include <stdint.h>

/* Fixed size of the IPv6 header (40 bytes, no extension headers) */
#define IPV6_HEADER_LEN         40

/* IPv6 version mask and shift in the first 4-bit field */
#define IPV6_VERSION_MASK       0xF0
#define IPV6_VERSION_SHIFT      4

/* IPv6 next header protocol numbers (commonly used) */
#define IPV6_NEXT_HOPOPT        0    /* Hop-by-Hop Options */
#define IPV6_NEXT_TCP           6    /* TCP */
#define IPV6_NEXT_UDP           17   /* UDP */
#define IPV6_NEXT_ICMPV6        58   /* ICMPv6 */

/*
 * pipesix_ipv6_header_t
 *
 * Represents the fixed portion of an IPv6 header. All multi-byte
 * fields are in network byte order. Extension headers are not
 * parsed by this module.
 */
typedef struct __attribute__((packed)) {
    uint32_t    vtc_flow;           /* Version (4), Traffic Class (8), Flow Label (20) */
    uint16_t    payload_length;     /* Length of payload in bytes (network byte order) */
    uint8_t     next_header;        /* Next header protocol number */
    uint8_t     hop_limit;          /* Hop limit */
    uint8_t     source_addr[16];    /* Source IPv6 address */
    uint8_t     dest_addr[16];      /* Destination IPv6 address */
} pipesix_ipv6_header_t;

/*
 * Format an IPv6 address into a human-readable string.
 *
 * Converts a 16-byte IPv6 address to its standard text representation
 * (e.g., "2001:db8::1"). Uses the standard inet_ntop() under the hood.
 *
 * Parameters:
 *   addr - 16-byte IPv6 address in network byte order
 *   buf  - Output buffer (must be at least INET6_ADDRSTRLEN bytes)
 *   size - Size of the output buffer
 *
 * Returns:
 *   Pointer to buf on success, NULL on failure
 */
const char *ipv6_addr_to_str(const uint8_t addr[16], char *buf, size_t size);

/*
 * Parse the IPv6 header from a raw packet buffer.
 *
 * Validates that the buffer is large enough to contain an IPv6 header
 * and that the version field indicates IPv6. Returns a pointer to the
 * parsed header structure.
 *
 * Parameters:
 *   data     - Pointer to the raw packet data
 *   length   - Length of the data in bytes
 *   header   - Output pointer to the parsed header (points within data)
 *
 * Returns:
 *   0 on success, -1 if the packet is too short or not IPv6
 */
int ipv6_parse_header(const uint8_t *data, size_t length,
                      const pipesix_ipv6_header_t **header);

/*
 * Log a summary of the IPv6 packet.
 *
 * Extracts and logs source/destination addresses, payload length,
 * next header protocol, and hop limit at INFO level.
 *
 * Parameters:
 *   data   - Pointer to the raw IPv6 packet
 *   length - Length of the packet in bytes
 *   prefix - String prefix for the log message (e.g., "TX" or "RX")
 */
void ipv6_log_packet(const uint8_t *data, size_t length, const char *prefix);

#endif /* PIPESIX_IPV6_H */
