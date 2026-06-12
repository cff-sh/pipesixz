/*
 * proto.h - pipesix Protocol Definition
 *
 * This file defines the wire protocol used to encapsulate IPv6 packets
 * inside UDP datagrams for transmission between the pipesix client and
 * server. Each UDP payload consists of a fixed-size frame header
 * followed by a raw IPv6 packet.
 *
 * Frame Format (on the wire, all multi-byte fields are big-endian):
 *
 *   +-------+-------+-------+-------+
 *   |          magic (4)             | 0x50495849 = "PIXI"
 *   +-------+-------+-------+-------+
 *   |  version (2)   |   flags (2)   |
 *   +-------+-------+-------+-------+
 *   |         length (4)             | payload length in bytes
 *   +-------+-------+-------+-------+
 *   |                               |
 *   |     IPv6 Packet (variable)    |
 *   |                               |
 *   +-------------------------------+
 *
 * Architecture:
 *
 *   [Client Side]
 *   Applications -> TUN (tun0) -> pipesix client -> UDP -> Internet
 *
 *   [Server Side]
 *   Internet -> UDP -> pipesix server -> TUN (tun0) -> Route64 Gateway
 *
 * The frame header allows the receiver to validate incoming datagrams
 * and extract the encapsulated IPv6 packet for injection into the
 * local TUN device.
 */

#ifndef PIPESIX_PROTO_H
#define PIPESIX_PROTO_H

#include <stdint.h>

/*
 * Magic Number: "PIXI" in ASCII
 * Used to validate that a received UDP datagram is a valid pipesix frame.
 * Stored in network byte order in the header.
 */
#define PIPESIX_MAGIC               0x50495849UL

/*
 * Protocol Version
 * Currently version 1. Incremented when incompatible protocol changes
 * are made to the frame format.
 */
#define PIPESIX_VERSION             1

/*
 * Frame Flags
 * Reserved for future use (e.g., fragmentation, encryption, compression).
 * Currently unused and should be set to PIPESIX_FLAG_NONE.
 */
#define PIPESIX_FLAG_NONE           0x0000

/*
 * MTU and Packet Size Limits
 *
 * PIPESIX_MAX_MTU:     Maximum MTU of the TUN device (standard IPv6 min MTU)
 * PIPESIX_MAX_PACKET:  Maximum IPv6 packet we can handle (MTU + IPv6 header overhead)
 * PIPESIX_MAX_FRAME:   Maximum total frame size (header + payload)
 */
#define PIPESIX_MAX_MTU             1500
#define PIPESIX_MAX_PACKET          (PIPESIX_MAX_MTU + 40)
#define PIPESIX_MAX_FRAME           (PIPESIX_HEADER_SIZE + PIPESIX_MAX_PACKET)

/*
 * pipesix_frame_header_t
 *
 * Fixed-size header prepended to every IPv6 packet before transmission
 * over UDP. All fields except flags are mandatory; flags is reserved.
 *
 * Fields:
 *   magic    - Frame magic number (PIPESIX_MAGIC) for validation
 *   version  - Protocol version (PIPESIX_VERSION)
 *   flags    - Reserved flags field (must be 0)
 *   length   - Length of the encapsulated IPv6 packet in bytes
 *
 * NOTE: This structure is packed to avoid padding, ensuring consistent
 * wire format across all architectures.
 */
typedef struct __attribute__((packed)) {
    uint32_t magic;              /* Frame magic number (network byte order) */
    uint16_t version;            /* Protocol version (network byte order) */
    uint16_t flags;              /* Reserved flags (network byte order) */
    uint32_t length;             /* Payload length in bytes (network byte order) */
} pipesix_frame_header_t;

/* Size of the frame header on the wire */
#define PIPESIX_HEADER_SIZE         ((size_t)sizeof(pipesix_frame_header_t))

/*
 * Buffer Sizing Helper
 *
 * Maximum buffer size needed to hold a full received frame including
 * header and payload. Used for receive buffer allocation.
 */
#define PIPESIX_RECV_BUF_SIZE       (PIPESIX_MAX_FRAME + 64)

#endif /* PIPESIX_PROTO_H */
