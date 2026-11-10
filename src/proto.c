/*
 * proto.c - pipesix Wire Protocol Implementation
 *
 * See proto.h for the frame layout and flag definitions.
 */

#include "proto.h"

#include <string.h>

static void put_u16(uint8_t *buf, uint16_t value)
{
    buf[0] = (uint8_t)(value >> 8);
    buf[1] = (uint8_t)value;
}

static void put_u32(uint8_t *buf, uint32_t value)
{
    buf[0] = (uint8_t)(value >> 24);
    buf[1] = (uint8_t)(value >> 16);
    buf[2] = (uint8_t)(value >> 8);
    buf[3] = (uint8_t)value;
}

static void put_u64(uint8_t *buf, uint64_t value)
{
    put_u32(buf, (uint32_t)(value >> 32));
    put_u32(buf + 4, (uint32_t)value);
}

static uint16_t get_u16(const uint8_t *buf)
{
    return (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
}

static uint32_t get_u32(const uint8_t *buf)
{
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) |
           (uint32_t)buf[3];
}

static uint64_t get_u64(const uint8_t *buf)
{
    return ((uint64_t)get_u32(buf) << 32) | (uint64_t)get_u32(buf + 4);
}

/*
 * Return non-zero when the control flags are self-consistent.
 */
static int flags_valid(uint16_t flags, size_t payload_len)
{
    if ((flags & (uint16_t)~PIPESIX_FLAG_KNOWN) != 0) {
        return 0;
    }
    if ((flags & PIPESIX_FLAG_KEEPALIVE) != 0 && payload_len != 0) {
        return 0;
    }
    if ((flags & PIPESIX_FLAG_RESET) != 0 && payload_len != 0) {
        return 0;
    }
    if ((flags & (PIPESIX_FLAG_KEEPALIVE | PIPESIX_FLAG_RESET)) ==
        (PIPESIX_FLAG_KEEPALIVE | PIPESIX_FLAG_RESET)) {
        return 0;
    }
    return 1;
}

size_t pipesix_frame_build(uint8_t *buf, size_t bufsize, uint16_t flags,
                           uint32_t salt, uint64_t seq,
                           const uint8_t *payload, size_t payload_len,
                           const uint8_t *key)
{
    size_t total;
    uint16_t wire_flags;

    if (buf == NULL) return 0;
    if (payload == NULL && payload_len > 0) return 0;
    if (!flags_valid(flags, payload_len)) return 0;
    if (payload_len > (size_t)PIPESIX_MAX_PACKET) return 0;

    total = PIPESIX_HEADER_SIZE + payload_len;
    if (key != NULL) total += PIPESIX_AUTH_TAG_SIZE;
    if (total > bufsize) return 0;

    wire_flags = flags;
    if (key != NULL) wire_flags |= PIPESIX_FLAG_AUTH;

    put_u32(buf, PIPESIX_MAGIC);
    put_u16(buf + 4, PIPESIX_VERSION);
    put_u16(buf + 6, wire_flags);
    put_u16(buf + 8, (uint16_t)payload_len);
    put_u16(buf + 10, 0);
    put_u32(buf + 12, salt);
    put_u64(buf + 16, seq);

    if (payload_len > 0) {
        memcpy(buf + PIPESIX_HEADER_SIZE, payload, payload_len);
    }

    if (key != NULL) {
        uint8_t nonce[PIPESIX_AEAD_NONCE_LEN];

        pipesix_aead_nonce(nonce, salt, seq);

        /*
         * The header travels as additional authenticated data, so the
         * flags, length, salt and sequence number cannot be altered.
         */
        if (pipesix_aead_seal(key, nonce, buf, PIPESIX_HEADER_SIZE,
                              buf + PIPESIX_HEADER_SIZE, payload_len,
                              buf + PIPESIX_HEADER_SIZE,
                              buf + PIPESIX_HEADER_SIZE + payload_len) != 0) {
            return 0;
        }
    }

    return total;
}

int pipesix_frame_parse(uint8_t *buf, size_t len, pipesix_frame_t *out,
                        const uint8_t *key)
{
    uint16_t flags;
    uint16_t payload_len;
    size_t needed;
    int authenticated;
    uint32_t salt;
    uint64_t seq;

    if (buf == NULL || out == NULL) return PIPESIX_ERR_PARAM;
    if (len < PIPESIX_HEADER_SIZE) return PIPESIX_ERR_SHORT;
    if (get_u32(buf) != PIPESIX_MAGIC) return PIPESIX_ERR_MAGIC;
    if (get_u16(buf + 4) != PIPESIX_VERSION) return PIPESIX_ERR_VERSION;

    flags = get_u16(buf + 6);
    payload_len = get_u16(buf + 8);

    if (!flags_valid(flags, (size_t)payload_len)) return PIPESIX_ERR_FLAGS;
    if (payload_len > PIPESIX_MAX_PACKET) return PIPESIX_ERR_LENGTH;

    authenticated = (flags & PIPESIX_FLAG_AUTH) != 0;
    needed = PIPESIX_HEADER_SIZE + (size_t)payload_len +
             (authenticated ? PIPESIX_AUTH_TAG_SIZE : 0);
    if (len != needed) return PIPESIX_ERR_LENGTH;

    salt = get_u32(buf + 12);
    seq = get_u64(buf + 16);

    if (key == NULL) {
        /* We cannot verify a tag we did not expect to receive. */
        if (authenticated) return PIPESIX_ERR_AUTH;
    } else {
        uint8_t nonce[PIPESIX_AEAD_NONCE_LEN];

        if (!authenticated) return PIPESIX_ERR_AUTH;

        pipesix_aead_nonce(nonce, salt, seq);

        if (pipesix_aead_open(key, nonce, buf, PIPESIX_HEADER_SIZE,
                              buf + PIPESIX_HEADER_SIZE, (size_t)payload_len,
                              buf + PIPESIX_HEADER_SIZE + payload_len,
                              buf + PIPESIX_HEADER_SIZE) != 0) {
            return PIPESIX_ERR_AUTH;
        }
    }

    out->flags = flags;
    out->salt = salt;
    out->seq = seq;
    out->payload = buf + PIPESIX_HEADER_SIZE;
    out->payload_len = (size_t)payload_len;
    out->authenticated = authenticated;

    return PIPESIX_OK;
}

void pipesix_replay_reset(pipesix_replay_t *replay)
{
    if (replay == NULL) return;

    replay->last = 0;
    replay->bitmap = 0;
    replay->initialized = 0;
}

int pipesix_replay_accept(pipesix_replay_t *replay, uint64_t seq)
{
    uint64_t diff;
    uint64_t distance;
    uint64_t bit;

    if (replay == NULL) return 0;

    if (!replay->initialized) {
        replay->initialized = 1;
        replay->last = seq;
        replay->bitmap = 1;
        return 1;
    }

    /*
     * Serial-number arithmetic (RFC 1982): the modular difference tells
     * us whether seq is ahead of or behind the window, which keeps the
     * window correct across a counter wrap.
     */
    diff = seq - replay->last;

    if (diff == 0) {
        return 0; /* Duplicate of the newest frame. */
    }

    if (diff < (UINT64_C(1) << 63)) {
        /* seq is ahead of the window. */
        if (diff >= 64u) {
            replay->bitmap = 1;
        } else {
            replay->bitmap = (replay->bitmap << diff) | 1u;
        }
        replay->last = seq;
        return 1;
    }

    /* seq is behind the window: distance is -diff. */
    distance = (uint64_t)0 - diff;
    if (distance >= 64u) return 0;

    bit = UINT64_C(1) << distance;
    if ((replay->bitmap & bit) != 0) return 0;

    replay->bitmap |= bit;
    return 1;
}

const char *pipesix_strerror(int code)
{
    switch (code) {
        case PIPESIX_OK:          return "ok";
        case PIPESIX_ERR_SHORT:   return "datagram shorter than frame header";
        case PIPESIX_ERR_MAGIC:   return "invalid frame magic";
        case PIPESIX_ERR_VERSION: return "unsupported protocol version";
        case PIPESIX_ERR_FLAGS:   return "invalid frame flags";
        case PIPESIX_ERR_LENGTH:  return "frame length mismatch";
        case PIPESIX_ERR_AUTH:    return "frame authentication failed";
        case PIPESIX_ERR_PARAM:   return "invalid argument";
        default:                  return "unknown protocol error";
    }
}
