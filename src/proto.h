/*
 * proto.h - pipesix Wire Protocol (version 5)
 *
 * Each UDP datagram carries a fixed 24-byte header. Data frames are
 * encrypted and authenticated with ChaCha20-Poly1305 under a key that
 * is unique to the client and to the session, so nonces and replay
 * windows can never be shared between peers.
 *
 * Frame Format (all multi-byte fields are big-endian):
 *
 *   +-------+-------+-------+-------+
 *   |          magic (4)             | 0x50495849 = "PIXI"
 *   +-------+-------+-------+-------+
 *   |  version (5)   |   flags (2)   | version = 5
 *   +-------+-------+-------+-------+
 *   |  length (2)    |  reserved (2) | payload length in bytes
 *   +-------+-------+-------+-------+
 *   |           salt (4)             | nonce salt for this direction
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
 *   PIPESIX_FLAG_AUTH              - payload is encrypted and the tag verifies
 *   PIPESIX_FLAG_KEEPALIVE         - keepalive, payload length must be 0
 *   PIPESIX_FLAG_HANDSHAKE_INIT    - client handshake request
 *   PIPESIX_FLAG_HANDSHAKE_RESP    - server handshake response
 *   PIPESIX_FLAG_HANDSHAKE_NEEDED  - server asks the client to handshake,
 *                                    payload length must be 0
 *
 * Handshake
 * ---------
 * Sessions are established by a pre-shared-key handshake. Every client
 * is configured with a unique client id and PSK; the server stores one
 * entry per client. The exchange is:
 *
 *   1. Client -> Server  INIT:   id_len, id, cnonce, MAC(psk, ...)
 *   2. Server -> Client  RESP:   cnonce, snonce, MAC(psk, ...)
 *
 * Both MACs are HMAC-SHA256 with the client's PSK and a fixed label, so
 * only a party holding that PSK can complete the exchange. The client
 * id travels in the clear (it is an identity, not a secret) and is
 * authenticated by the INIT MAC.
 *
 * Both sides then derive two independent session keys:
 *
 *   client-to-server = HKDF-SHA256(psk, salt = cnonce || snonce,
 *                                  info = "pipesix-v5-client-to-server")
 *   server-to-client = HKDF-SHA256(psk, salt = cnonce || snonce,
 *                                  info = "pipesix-v5-server-to-client")
 *
 * Because each direction has its own key and each handshake has fresh
 * random nonces, two clients can never share a keystream, even if they
 * were accidentally configured with the same PSK, and a restarted
 * session can never repeat a nonce.
 *
 * Data-frame nonces are the 4-byte salt followed by the 8-byte
 * sequence number. Handshake frames are sent in the clear because they
 * bootstrap the keys; their integrity comes from the embedded MAC.
 */

#ifndef PIPESIX_PROTO_H
#define PIPESIX_PROTO_H

#include <stddef.h>
#include <stdint.h>

#include "crypto.h"

/* Magic number: "PIXI" in ASCII */
#define PIPESIX_MAGIC               0x50495849UL

/* Protocol version. Version 5 adds the per-client handshake. */
#define PIPESIX_VERSION             5

/* Frame flags */
#define PIPESIX_FLAG_AUTH            0x0001u
#define PIPESIX_FLAG_KEEPALIVE       0x0002u
#define PIPESIX_FLAG_HANDSHAKE_INIT  0x0004u
#define PIPESIX_FLAG_HANDSHAKE_RESP  0x0008u
#define PIPESIX_FLAG_HANDSHAKE_NEEDED 0x0010u
#define PIPESIX_FLAG_KNOWN          (PIPESIX_FLAG_AUTH | PIPESIX_FLAG_KEEPALIVE | \
                                     PIPESIX_FLAG_HANDSHAKE_INIT | \
                                     PIPESIX_FLAG_HANDSHAKE_RESP | \
                                     PIPESIX_FLAG_HANDSHAKE_NEEDED)

/* Fixed header size on the wire */
#define PIPESIX_HEADER_SIZE         24

/* Size of the optional ChaCha20-Poly1305 authentication tag */
#define PIPESIX_AUTH_TAG_SIZE       PIPESIX_AEAD_TAG_LEN

/* Handshake sizes */
#define PIPESIX_HANDSHAKE_NONCE_LEN 32
#define PIPESIX_HANDSHAKE_MAC_LEN   PIPESIX_SHA256_LEN
#define PIPESIX_CLIENT_ID_MAX       31

#define PIPESIX_HANDSHAKE_INIT_MAX  (1u + PIPESIX_CLIENT_ID_MAX + \
                                     PIPESIX_HANDSHAKE_NONCE_LEN + \
                                     PIPESIX_HANDSHAKE_MAC_LEN)
#define PIPESIX_HANDSHAKE_RESP_MAX  (2u * PIPESIX_HANDSHAKE_NONCE_LEN + \
                                     PIPESIX_HANDSHAKE_MAC_LEN)

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
 *   flags       - A control flag (keepalive, handshake) or 0
 *                 (AUTH is added automatically when key is not NULL)
 *   salt        - Nonce salt for this direction
 *   seq         - Sequence number for this frame
 *   payload     - Payload, or NULL for an empty one
 *   payload_len - Payload length
 *   key         - 32-byte session key, or NULL for handshake frames
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
 * Read and validate just the frame header.
 *
 * This lets a receiver decide which session key to use, or whether the
 * datagram is a handshake message, before decrypting anything.
 *
 * Returns:
 *   PIPESIX_OK on success, or a negative PIPESIX_ERR_* code.
 */
int pipesix_frame_peek(const uint8_t *buf, size_t len, uint16_t *flags);

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
 *   key  - 32-byte session key, or NULL for handshake frames
 *
 * Returns:
 *   PIPESIX_OK on success, or a negative PIPESIX_ERR_* code.
 */
int pipesix_frame_parse(uint8_t *buf, size_t len, pipesix_frame_t *out,
                        const uint8_t *key);

/*
 * Build a handshake INIT payload.
 *
 * Returns the payload length, or 0 on invalid parameters. The caller
 * wraps the payload in a frame with PIPESIX_FLAG_HANDSHAKE_INIT and no
 * key.
 */
size_t pipesix_handshake_init_build(uint8_t *buf, size_t bufsize,
                                    const char *client_id,
                                    const uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN],
                                    const uint8_t psk[PIPESIX_KEY_LEN]);

/*
 * Structurally decode an INIT payload without verifying its MAC.
 *
 * The server needs the client id in the clear to select the right PSK;
 * the MAC is checked separately with pipesix_handshake_init_verify().
 */
int pipesix_handshake_init_peek(const uint8_t *payload, size_t len,
                                char *client_id, size_t id_size,
                                uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN]);

/*
 * Verify an INIT payload against a client PSK.
 *
 * Returns PIPESIX_OK when the MAC matches, PIPESIX_ERR_AUTH otherwise.
 */
int pipesix_handshake_init_verify(const uint8_t *payload, size_t len,
                                  const uint8_t psk[PIPESIX_KEY_LEN]);

/*
 * Build a handshake RESPONSE payload.
 *
 * Returns the payload length, or 0 on invalid parameters.
 */
size_t pipesix_handshake_resp_build(uint8_t *buf, size_t bufsize,
                                    const uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN],
                                    const uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN],
                                    const uint8_t psk[PIPESIX_KEY_LEN]);

/*
 * Verify a RESPONSE payload and return the echoed client nonce.
 *
 * The caller must compare the returned nonce with the one it sent, so
 * a replayed response from an earlier handshake cannot be adopted.
 *
 * Returns PIPESIX_OK when the MAC matches, PIPESIX_ERR_AUTH otherwise.
 */
int pipesix_handshake_resp_verify(const uint8_t *payload, size_t len,
                                  const uint8_t psk[PIPESIX_KEY_LEN],
                                  uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN]);

/*
 * Derive the two directional session keys from the handshake nonces.
 */
void pipesix_session_keys(const uint8_t psk[PIPESIX_KEY_LEN],
                          const uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN],
                          const uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN],
                          uint8_t client_to_server[PIPESIX_KEY_LEN],
                          uint8_t server_to_client[PIPESIX_KEY_LEN]);

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
