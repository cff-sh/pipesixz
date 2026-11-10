/*
 * proto.h - pipesix Wire Protocol (version 4)
 *
 * Each UDP datagram carries a fixed 24-byte header. When a shared
 * secret is configured the header is authenticated as additional data
 * and the payload is encrypted with ChaCha20-Poly1305, followed by a
 * 16-byte tag.
 *
 * Frame Format (all multi-byte fields are big-endian):
 *
 *   +-------+-------+-------+-------+
 *   |          magic (4)             | 0x50495849 = "PIXI"
 *   +-------+-------+-------+-------+
 *   |  version (4)   |   flags (2)   | version = 4
 *   +-------+-------+-------+-------+
 *   |  length (2)    |  reserved (2) | payload length in bytes
 *   +-------+-------+-------+-------+
 *   |           salt (4)             | random per-session nonce salt
 *   +-------+-------+-------+-------+
 *   |                               |
 *   +        sequence (8)           | per-session anti-replay counter
 *   |                               |
 *   +-------+-------+-------+-------+
 *   |     IPv6 Packet (variable)     | encrypted when FLAG_AUTH is set
 *   +-------------------------------+
 *   |  ChaCha20-Poly1305 tag (16)    | present when FLAG_AUTH is set
 *   +-------------------------------+
 *
 * Flags:
 *   PIPESIX_FLAG_AUTH       - payload is encrypted and the tag verifies
 *   PIPESIX_FLAG_KEEPALIVE  - keepalive, payload length must be 0
 *   PIPESIX_FLAG_RESET      - resets the peer's replay window, payload
 *                             length must be 0 (sent on session start)
 *
 * A RESET frame tells the receiver to start a new session: the replay
 * window is cleared, so sequence numbers from a restarted peer are
 * accepted again. Keepalive and reset are mutually exclusive.
 *
 * The nonce is the 4-byte salt followed by the 8-byte sequence number.
 * The salt is freshly randomised whenever a session starts, so a key
 * never sees a repeated nonce even across restarts. The 64-bit
 * sequence number doubles as the anti-replay counter, which means it
 * cannot wrap in any realistic deployment; the window arithmetic is
 * nevertheless wrap-safe.
 *
 * Replay protection uses a 64-packet sliding window keyed on the
 * sequence number. Sequence numbers start at a random value.
 */

#ifndef PIPESIX_PROTO_H
#define PIPESIX_PROTO_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/* Magic number: "PIXI" in ASCII */
#define PIPESIX_MAGIC               0x50495849UL

/* Protocol version. Version 4 adds AEAD encryption and 64-bit sequence. */
#define PIPESIX_VERSION             4

/* Frame flags */
#define PIPESIX_FLAG_AUTH           0x0001u
#define PIPESIX_FLAG_KEEPALIVE      0x0002u
#define PIPESIX_FLAG_RESET          0x0004u
#define PIPESIX_FLAG_KNOWN          (PIPESIX_FLAG_AUTH | PIPESIX_FLAG_KEEPALIVE | \
                                     PIPESIX_FLAG_RESET)

/* Fixed header size on the wire */
#define PIPESIX_HEADER_SIZE         24

/* Size of the optional ChaCha20-Poly1305 authentication tag */
#define PIPESIX_AUTH_TAG_SIZE       PIPESIX_AEAD_TAG_LEN

/* Packet size limits */
#define PIPESIX_MAX_MTU             1500
#define PIPESIX_MAX_PACKET          (PIPESIX_MAX_MTU + 40)
#define PIPESIX_MAX_FRAME           (PIPESIX_HEADER_SIZE + PIPESIX_MAX_PACKET + \
                                     PIPESIX_AUTH_TAG_SIZE)
#define PIPESIX_RECV_BUF_SIZE       (PIPESIX_MAX_FRAME + 64)

/* Parse result codes */
#define PIPESIX_OK                  0
#define PIPESIX_ERR_SHORT          (-1)
#define PIPESIX_ERR_MAGIC          (-2)
#define PIPESIX_ERR_VERSION        (-3)
#define PIPESIX_ERR_FLAGS          (-4)
#define PIPESIX_ERR_LENGTH         (-5)
#define PIPESIX_ERR_AUTH           (-6)
#define PIPESIX_ERR_PARAM          (-7)

/*
 * Decoded frame view. Pointers reference the caller's receive buffer
 * and remain valid until that buffer is reused.
 */
typedef struct {
    uint16_t       flags;         /* Frame flags (host byte order) */
    uint32_t       salt;          /* Nonce salt (host byte order) */
    uint64_t       seq;           /* Sequence number (host byte order) */
    const uint8_t *payload;       /* IPv6 packet (may be NULL for keepalive) */
    size_t         payload_len;   /* Payload length in bytes */
    int            authenticated; /* Non-zero if the AEAD tag verified */
} pipesix_frame_t;

/*
 * Sliding-window replay tracker.
 * One instance per direction of a session.
 */
typedef struct {
    uint64_t last;
    uint64_t bitmap;
    int      initialized;
} pipesix_replay_t;

/*
 * Build a frame in the caller's buffer.
 *
 * Parameters:
 *   buf         - Output buffer
 *   bufsize     - Size of the output buffer
 *   flags       - PIPESIX_FLAG_KEEPALIVE, PIPESIX_FLAG_RESET, or 0
 *                 (AUTH is added automatically when key is not NULL)
 *   salt        - Nonce salt for this session
 *   seq         - Sequence number for this frame
 *   payload     - IPv6 packet, or NULL for a keepalive
 *   payload_len - Payload length (must be 0 for keepalive)
 *   key         - 32-byte encryption key, or NULL to disable encryption
 *
 * Returns:
 *   Total frame length on success, 0 on invalid parameters or a
 *   buffer that is too small.
 */
size_t pipesix_frame_build(uint8_t *buf, size_t bufsize, uint16_t flags,
                           uint32_t salt, uint64_t seq,
                           const uint8_t *payload, size_t payload_len,
                           const uint8_t *key);

/*
 * Validate and decode a received datagram.
 *
 * When key is non-NULL the frame must carry a valid AEAD tag and the
 * payload is decrypted in place inside buf; when key is NULL, frames
 * carrying a tag are rejected because they cannot be verified.
 * Trailing or missing bytes are treated as a length error.
 *
 * Parameters:
 *   buf  - Received datagram (modified in place when decrypting)
 *   len  - Datagram length
 *   out  - Decoded frame (must not be NULL)
 *   key  - 32-byte encryption key, or NULL for plaintext mode
 *
 * Returns:
 *   PIPESIX_OK on success, or a negative PIPESIX_ERR_* code.
 */
int pipesix_frame_parse(uint8_t *buf, size_t len, pipesix_frame_t *out,
                        const uint8_t *key);

/*
 * Reset a replay window (call when a new session starts).
 */
void pipesix_replay_reset(pipesix_replay_t *replay);

/*
 * Check and record a sequence number.
 *
 * Sequence comparisons use modular arithmetic (RFC 1982 style), so the
 * window behaves correctly across a counter wrap instead of rejecting
 * every subsequent frame.
 *
 * Returns 1 if the frame should be accepted, 0 if it is a duplicate,
 * replayed, or outside the window.
 */
int pipesix_replay_accept(pipesix_replay_t *replay, uint64_t seq);

/*
 * Human-readable description of a PIPESIX_ERR_* code.
 */
const char *pipesix_strerror(int code);

#endif /* PIPESIX_PROTO_H */
