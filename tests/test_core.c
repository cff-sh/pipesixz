/*
 * test_core.c - Unit tests for platform-independent pipesix modules
 *
 * Covers SHA-256/HMAC/ChaCha20-Poly1305 known-answer vectors, key
 * derivation, frame encryption and tamper detection, the replay
 * window (including counter wrap), IPv6 validation and the
 * configuration parser. Run with `make check`; no root required.
 */

#include "config.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
#include "proto.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(int condition, const char *name)
{
    g_checks++;
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", name);
        g_failures++;
    }
}

static void digest_hex(const void *data, size_t len, char out[65])
{
    uint8_t digest[PIPESIX_SHA256_LEN];

    pipesix_sha256_oneshot(data, len, digest);
    pipesix_hex_encode(digest, sizeof(digest), out);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Decode a hex string into out. Returns the number of bytes written,
 * or -1 when the input is malformed or does not fit.
 */
static int hex_decode(const char *hex, uint8_t *out, size_t out_size)
{
    size_t len = strlen(hex);
    size_t i;

    if (len % 2u != 0u || len / 2u > out_size) {
        return -1;
    }

    for (i = 0; i < len / 2u; i++) {
        int hi = hex_nibble(hex[i * 2u]);
        int lo = hex_nibble(hex[i * 2u + 1u]);

        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return (int)(len / 2u);
}

static void test_sha256(void)
{
    char hex[65];
    uint8_t digest[PIPESIX_SHA256_LEN];
    uint8_t expected[PIPESIX_SHA256_LEN];
    pipesix_sha256_t ctx;

    digest_hex("abc", 3, hex);
    check(strcmp(hex,
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
              == 0,
          "SHA-256(\"abc\") known-answer");

    digest_hex("", 0, hex);
    check(strcmp(hex,
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
              == 0,
          "SHA-256(\"\") known-answer");

    /* Incremental hashing must match the one-shot result. */
    pipesix_sha256_init(&ctx);
    pipesix_sha256_update(&ctx, "a", 1);
    pipesix_sha256_update(&ctx, "b", 1);
    pipesix_sha256_update(&ctx, "c", 1);
    pipesix_sha256_final(&ctx, digest);
    pipesix_sha256_oneshot("abc", 3, expected);
    check(memcmp(digest, expected, sizeof(digest)) == 0,
          "SHA-256 incremental update");
}

static void test_hmac(void)
{
    uint8_t key[20];
    uint8_t tag[PIPESIX_SHA256_LEN];
    char hex[65];

    memset(key, 0x0b, sizeof(key));
    pipesix_hmac_sha256(key, sizeof(key), "Hi There", 8, tag);
    pipesix_hex_encode(tag, sizeof(tag), hex);
    check(strcmp(hex,
                 "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
              == 0,
          "HMAC-SHA256 RFC 4231 case 1");
}

/*
 * ChaCha20 block function, RFC 8439 section 2.3.2.
 */
static void test_chacha20_block(void)
{
    static const char *expected_hex =
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t expected[64];
    uint8_t block[64];
    int i;

    for (i = 0; i < (int)sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }

    check(hex_decode("000000090000004a00000000", nonce, sizeof(nonce)) == 12,
          "decode ChaCha20 nonce");
    check(hex_decode(expected_hex, expected, sizeof(expected)) == 64,
          "decode ChaCha20 block vector");

    memset(block, 0, sizeof(block));
    pipesix_chacha20_xor(key, nonce, 1u, block, sizeof(block));

    check(memcmp(block, expected, sizeof(expected)) == 0,
          "ChaCha20 block RFC 8439 2.3.2");
}

/*
 * ChaCha20 encryption, RFC 8439 section 2.4.2.
 */
static void test_chacha20_encrypt(void)
{
    static const char plaintext[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    static const char *ciphertext_hex =
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42874d";
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t expected[256];
    uint8_t buffer[sizeof(plaintext)];
    size_t plain_len = sizeof(plaintext) - 1u;
    int expected_len;
    int i;

    for (i = 0; i < (int)sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }

    check(hex_decode("000000000000004a00000000", nonce, sizeof(nonce)) == 12,
          "decode ChaCha20 encryption nonce");

    expected_len = hex_decode(ciphertext_hex, expected, sizeof(expected));
    check(expected_len == (int)plain_len,
          "ChaCha20 encryption vector length");

    memcpy(buffer, plaintext, plain_len);
    pipesix_chacha20_xor(key, nonce, 1u, buffer, plain_len);

    check(memcmp(buffer, expected, plain_len) == 0,
          "ChaCha20 encryption RFC 8439 2.4.2");

    /* The transformation is its own inverse. */
    pipesix_chacha20_xor(key, nonce, 1u, buffer, plain_len);
    check(memcmp(buffer, plaintext, plain_len) == 0,
          "ChaCha20 round trip");
}

/*
 * ChaCha20-Poly1305 AEAD, RFC 8439 section 2.8.2.
 *
 * This vector exercises ChaCha20 (keystream and block 0 for the
 * Poly1305 one-time key) and Poly1305 together, so the whole
 * construction is validated through the public AEAD interface.
 */
static void test_aead_vector(void)
{
    static const char *key_hex =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    static const char *nonce_hex = "070000004041424344454647";
    static const char *aad_hex = "50515253c0c1c2c3c4c5c6c7";
    static const char *plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    static const char *ciphertext_hex =
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116";
    static const char *tag_hex = "1ae10b594f09e26a7e902ecbd0600691";
    uint8_t key[32];
    uint8_t nonce[PIPESIX_AEAD_NONCE_LEN];
    uint8_t aad[12];
    uint8_t expected_ct[256];
    uint8_t expected_tag[PIPESIX_AEAD_TAG_LEN];
    uint8_t ct[256];
    uint8_t pt[256];
    uint8_t tag[PIPESIX_AEAD_TAG_LEN];
    uint8_t derived_nonce[PIPESIX_AEAD_NONCE_LEN];
    size_t len = strlen(plaintext);
    int ct_len;

    check(hex_decode(key_hex, key, sizeof(key)) == 32, "decode AEAD key");
    check(hex_decode(nonce_hex, nonce, sizeof(nonce)) == 12,
          "decode AEAD nonce");
    check(hex_decode(aad_hex, aad, sizeof(aad)) == 12, "decode AEAD AAD");
    check(hex_decode(tag_hex, expected_tag, sizeof(expected_tag)) == 16,
          "decode AEAD tag");

    ct_len = hex_decode(ciphertext_hex, expected_ct, sizeof(expected_ct));
    check(ct_len == (int)len, "AEAD ciphertext length");

    check(pipesix_aead_seal(key, nonce, aad, sizeof(aad),
                            (const uint8_t *)plaintext, len, ct, tag) == 0,
          "AEAD seal succeeds");
    check(memcmp(ct, expected_ct, len) == 0,
          "AEAD ciphertext RFC 8439 2.8.2");
    check(memcmp(tag, expected_tag, sizeof(tag)) == 0,
          "AEAD tag RFC 8439 2.8.2");

    check(pipesix_aead_open(key, nonce, aad, sizeof(aad), ct, len,
                            tag, pt) == 0,
          "AEAD open succeeds");
    check(memcmp(pt, plaintext, len) == 0, "AEAD round trip");

    /* Any flipped bit in the tag, AAD or ciphertext must be fatal. */
    tag[0] ^= 0x01u;
    check(pipesix_aead_open(key, nonce, aad, sizeof(aad), ct, len, tag, pt)
              == -1,
          "AEAD rejects a modified tag");
    tag[0] ^= 0x01u;

    ct[5] ^= 0x01u;
    check(pipesix_aead_open(key, nonce, aad, sizeof(aad), ct, len, tag, pt)
              == -1,
          "AEAD rejects modified ciphertext");
    ct[5] ^= 0x01u;

    aad[0] ^= 0x01u;
    check(pipesix_aead_open(key, nonce, aad, sizeof(aad), ct, len, tag, pt)
              == -1,
          "AEAD rejects modified AAD");
    aad[0] ^= 0x01u;

    /* The nonce must be derived from salt and sequence number. */
    pipesix_aead_nonce(derived_nonce, 0x07000000u, UINT64_C(0x4041424344454647));
    check(memcmp(derived_nonce, nonce, sizeof(nonce)) == 0,
          "nonce derived from salt and sequence");
}

static void test_key_derivation(void)
{
    uint8_t key[PIPESIX_KEY_LEN];
    uint8_t derived[PIPESIX_KEY_LEN];
    uint8_t expected[PIPESIX_KEY_LEN];
    char hex[PIPESIX_KEY_LEN * 2 + 1];
    size_t i;

    for (i = 0; i < sizeof(key); i++) {
        key[i] = (uint8_t)i;
    }

    pipesix_hex_encode(key, sizeof(key), hex);
    check(pipesix_key_from_string(hex, derived) == 0, "hex secret accepted");
    check(memcmp(key, derived, sizeof(key)) == 0, "hex secret decoded exactly");

    check(pipesix_key_from_string("", derived) == -1, "empty secret rejected");

    pipesix_sha256_oneshot("passphrase", 10, expected);
    check(pipesix_key_from_string("passphrase", derived) == 0,
          "passphrase accepted");
    check(memcmp(expected, derived, sizeof(expected)) == 0,
          "passphrase hashed to a key");
}

static void test_frames(void)
{
    uint8_t key[PIPESIX_KEY_LEN];
    uint8_t other_key[PIPESIX_KEY_LEN];
    uint8_t payload[64];
    uint8_t frame[PIPESIX_MAX_FRAME];
    pipesix_frame_t parsed;
    size_t frame_len;
    size_t i;
    int rc;
    const uint32_t salt = 0xaabbccddu;
    const uint64_t seq = UINT64_C(0x1122334455667788);

    memset(key, 0x11, sizeof(key));
    memset(other_key, 0x22, sizeof(other_key));
    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)i;
    }

    frame_len = pipesix_frame_build(frame, sizeof(frame), 0, salt, seq,
                                    payload, sizeof(payload), key);
    check(frame_len == PIPESIX_HEADER_SIZE + sizeof(payload) +
                            PIPESIX_AUTH_TAG_SIZE,
          "encrypted frame size");
    check(frame_len > 0, "encrypted frame built");

    /*
     * The payload on the wire must not equal the plaintext, otherwise
     * the frame is not actually encrypted.
     */
    check(memcmp(frame + PIPESIX_HEADER_SIZE, payload, sizeof(payload)) != 0,
          "payload is encrypted on the wire");

    rc = pipesix_frame_parse(frame, frame_len, &parsed, key);
    check(rc == PIPESIX_OK, "encrypted frame parsed");
    check(parsed.seq == seq, "sequence number preserved");
    check(parsed.salt == salt, "salt preserved");
    check(parsed.payload_len == sizeof(payload), "payload length preserved");
    check(memcmp(parsed.payload, payload, sizeof(payload)) == 0,
          "payload decrypted");
    check(parsed.authenticated == 1, "frame marked authenticated");

    /* A single flipped payload byte must fail authentication. */
    frame[PIPESIX_HEADER_SIZE] ^= 0x01u;
    check(pipesix_frame_parse(frame, frame_len, &parsed, key) ==
              PIPESIX_ERR_AUTH,
          "tampered payload rejected");
    frame[PIPESIX_HEADER_SIZE] ^= 0x01u;

    /* Tampering with the header (salt) must also fail. */
    frame[12] ^= 0x01u;
    check(pipesix_frame_parse(frame, frame_len, &parsed, key) ==
              PIPESIX_ERR_AUTH,
          "tampered header rejected");
    frame[12] ^= 0x01u;

    check(pipesix_frame_parse(frame, frame_len, &parsed, other_key) ==
              PIPESIX_ERR_AUTH,
          "wrong key rejected");

    check(pipesix_frame_parse(frame, frame_len, &parsed, NULL) ==
              PIPESIX_ERR_AUTH,
          "unverifiable encrypted frame rejected");

    check(pipesix_frame_parse(frame, frame_len - 1, &parsed, key) ==
              PIPESIX_ERR_LENGTH,
          "truncated frame rejected");

    /* Plaintext mode */
    frame_len = pipesix_frame_build(frame, sizeof(frame), 0, salt, 7,
                                    payload, sizeof(payload), NULL);
    check(frame_len == PIPESIX_HEADER_SIZE + sizeof(payload),
          "plain frame size");
    check(pipesix_frame_parse(frame, frame_len, &parsed, NULL) == PIPESIX_OK,
          "plain frame parsed");
    check(parsed.authenticated == 0, "plain frame marked unauthenticated");

    /* Keepalive frames carry no payload. */
    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_KEEPALIVE, salt, 8,
                                    NULL, 0, key);
    check(frame_len == PIPESIX_HEADER_SIZE + PIPESIX_AUTH_TAG_SIZE,
          "keepalive frame size");
    check(pipesix_frame_parse(frame, frame_len, &parsed, key) == PIPESIX_OK,
          "keepalive parsed");
    check((parsed.flags & PIPESIX_FLAG_KEEPALIVE) != 0 &&
              parsed.payload_len == 0,
          "keepalive flag and empty payload");

    /* A keepalive with a payload is invalid. */
    check(pipesix_frame_build(frame, sizeof(frame), PIPESIX_FLAG_KEEPALIVE,
                              salt, 9, payload, 1, key) == 0,
          "keepalive with payload rejected");
}

static void test_replay(void)
{
    pipesix_replay_t replay;

    pipesix_replay_reset(&replay);
    check(pipesix_replay_accept(&replay, 10) == 1, "accept first sequence");
    check(pipesix_replay_accept(&replay, 10) == 0, "reject duplicate");
    check(pipesix_replay_accept(&replay, 11) == 1, "accept next sequence");
    check(pipesix_replay_accept(&replay, 9) == 1, "accept reordered in-window");
    check(pipesix_replay_accept(&replay, 9) == 0, "reject reordered duplicate");
    check(pipesix_replay_accept(&replay, 200) == 1, "accept large jump");
    check(pipesix_replay_accept(&replay, 100) == 0, "reject outside window");
}

/*
 * Regression: a 32-bit sequence counter used to wrap to zero, after
 * which every following frame compared as "older" and was rejected,
 * silently blackholing the tunnel. The window now uses modular
 * arithmetic over 64 bits.
 */
static void test_replay_wrap(void)
{
    pipesix_replay_t replay;

    pipesix_replay_reset(&replay);
    check(pipesix_replay_accept(&replay, UINT64_C(0xFFFFFFFE)) == 1,
          "accept sequence before 32-bit boundary");
    check(pipesix_replay_accept(&replay, UINT64_C(0xFFFFFFFF)) == 1,
          "accept last 32-bit sequence");
    check(pipesix_replay_accept(&replay, UINT64_C(0x100000000)) == 1,
          "accept sequence past the 32-bit boundary");
    check(pipesix_replay_accept(&replay, UINT64_C(0x100000001)) == 1,
          "accept sequence after 32-bit wrap");

    pipesix_replay_reset(&replay);
    check(pipesix_replay_accept(&replay, UINT64_MAX - 1u) == 1,
          "accept sequence before 64-bit wrap");
    check(pipesix_replay_accept(&replay, UINT64_MAX) == 1,
          "accept last 64-bit sequence");
    check(pipesix_replay_accept(&replay, 0) == 1, "accept wrap to zero");
    check(pipesix_replay_accept(&replay, 0) == 0,
          "reject duplicate after wrap");
    check(pipesix_replay_accept(&replay, 1) == 1, "accept after wrap");
    check(pipesix_replay_accept(&replay, UINT64_MAX) == 0,
          "reject pre-wrap replay when outside the window");
}

static void test_session_reset(void)
{
    uint8_t key[PIPESIX_KEY_LEN];
    uint8_t frame[PIPESIX_MAX_FRAME];
    pipesix_frame_t parsed;
    size_t frame_len;

    memset(key, 0x22, sizeof(key));

    frame_len = pipesix_frame_build(frame, sizeof(frame), PIPESIX_FLAG_RESET,
                                    0x01020304u, 100, NULL, 0, key);
    check(frame_len > 0, "reset frame built");
    check(pipesix_frame_parse(frame, frame_len, &parsed, key) == PIPESIX_OK,
          "reset frame parsed");
    check((parsed.flags & PIPESIX_FLAG_RESET) != 0, "reset flag preserved");
    check(parsed.payload_len == 0, "reset frame has no payload");

    check(pipesix_frame_build(frame, sizeof(frame), PIPESIX_FLAG_RESET,
                              0x01020304u, 101, (const uint8_t *)"x", 1,
                              key) == 0,
          "reset with payload rejected");
    check(pipesix_frame_build(frame, sizeof(frame),
                              PIPESIX_FLAG_RESET | PIPESIX_FLAG_KEEPALIVE,
                              0x01020304u, 102, NULL, 0, key) == 0,
          "reset plus keepalive rejected");
}

static void test_ipv6_validation(void)
{
    uint8_t packet[IPV6_HEADER_LEN];

    memset(packet, 0, sizeof(packet));
    packet[0] = 0x60; /* version 6 */

    check(ipv6_validate_packet(packet, sizeof(packet)) == 0,
          "valid empty IPv6 packet accepted");
    check(ipv6_validate_packet(packet, sizeof(packet) - 1) == -1,
          "short IPv6 packet rejected");

    packet[4] = 0;
    packet[5] = 1; /* payload length 1, but no payload bytes */
    check(ipv6_validate_packet(packet, sizeof(packet)) == -1,
          "IPv6 length mismatch rejected");

    packet[4] = 0;
    packet[5] = 0;
    packet[0] = 0x40; /* version 4 */
    check(ipv6_validate_packet(packet, sizeof(packet)) == -1,
          "non-IPv6 payload rejected");
}

static int write_temp_file(const char *contents, char *path, size_t path_size)
{
    int fd;
    FILE *fp;

    snprintf(path, path_size, "/tmp/pipesix_test_XXXXXX");
    fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }

    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        unlink(path);
        return -1;
    }

    fputs(contents, fp);
    fclose(fp);
    return 0;
}

static int write_file(const char *path, const char *contents)
{
    FILE *fp = fopen(path, "w");

    if (fp == NULL) {
        return -1;
    }

    fputs(contents, fp);
    fclose(fp);
    return 0;
}

static void test_config(void)
{
    static const char valid_config[] =
        "# pipesix test configuration\n"
        "mode = client\n"
        "tun_name = tun9\n"
        "tun_address = fd00::2/48\n"
        "tun_mtu = 1400\n"
        "remote_address = 198.51.100.9\n"
        "remote_port = 9999\n"
        "secret = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "keepalive = 15\n"
        "session_timeout = 90\n"
        "stats_interval = 30\n"
        "log_level = debug\n";
    static const char bad_port_config[] =
        "mode = client\n"
        "tun_address = fd00::2\n"
        "remote_address = 198.51.100.9\n"
        "remote_port = 999999\n";
    static const char bad_address_config[] =
        "mode = client\n"
        "tun_address = not-an-ipv6-address\n"
        "remote_address = 198.51.100.9\n";
    pipesix_config_t config;
    char path[64];

    check(write_temp_file(valid_config, path, sizeof(path)) == 0,
          "write valid config fixture");
    check(config_load(path, &config) == 0, "load valid config");
    unlink(path);

    check(strcmp(config.mode, "client") == 0, "mode parsed");
    check(strcmp(config.tun_name, "tun9") == 0, "tun_name parsed");
    check(strcmp(config.tun_address, "fd00::2") == 0, "address prefix split");
    check(config.tun_prefixlen == 48, "prefix length from address");
    check(config.tun_mtu == 1400, "MTU parsed");
    check(config.remote_port == 9999, "remote port parsed");
    check(config.keepalive == 15, "keepalive parsed");
    check(config.session_timeout == 90, "session timeout parsed");
    check(config.stats_interval == 30, "stats interval parsed");
    check(config.log_level == LOG_DEBUG, "log level parsed");
    check(config_validate(&config) == 0, "valid config validates");

    check(write_temp_file(bad_port_config, path, sizeof(path)) == 0,
          "write bad port fixture");
    check(config_load(path, &config) != 0, "out-of-range port rejected");
    unlink(path);

    check(write_temp_file(bad_address_config, path, sizeof(path)) == 0,
          "write bad address fixture");
    check(config_load(path, &config) == 0, "bad address config loads");
    unlink(path);
    check(config_validate(&config) != 0, "invalid IPv6 address rejected");
}

static void test_config_reload(void)
{
    static const char initial[] =
        "mode = client\n"
        "tun_address = fd00::5/64\n"
        "remote_address = 198.51.100.9\n"
        "keepalive = 5\n"
        "peer_timeout = 30\n"
        "stats_interval = 60\n"
        "log_level = info\n";
    static const char updated[] =
        "mode = client\n"
        "tun_address = fd00::9/48\n"
        "remote_address = 198.51.100.77\n"
        "keepalive = 99\n"
        "peer_timeout = 45\n"
        "stats_interval = 10\n"
        "log_level = debug\n";
    pipesix_config_t config;
    char path[64];

    check(write_temp_file(initial, path, sizeof(path)) == 0,
          "write reload fixture");
    check(config_load(path, &config) == 0, "load reload fixture");
    check(write_file(path, updated) == 0, "rewrite reload fixture");
    check(config_reload_runtime(&config) == 0, "reload runtime settings");
    unlink(path);

    check(config.keepalive == 99, "reload updates keepalive");
    check(config.peer_timeout == 45, "reload updates peer_timeout");
    check(config.stats_interval == 10, "reload updates stats_interval");
    check(config.log_level == LOG_DEBUG, "reload updates log_level");
    check(strcmp(config.tun_address, "fd00::5") == 0,
          "reload keeps tun settings");
    check(config.tun_prefixlen == 64, "reload keeps prefix length");
}

static void test_allow_client(void)
{
    static const char allowed_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "allow_client = 198.51.100.9, 2001:db8::3\n";
    static const char multi_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "allow_client = 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, "
        "192.0.2.5, 192.0.2.6, 192.0.2.7, 2001:db8::9\n";
    static const char bad_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "allow_client = not-an-address\n";
    pipesix_config_t config;
    char path[64];

    check(write_temp_file(allowed_config, path, sizeof(path)) == 0,
          "write allow-list fixture");
    check(config_load(path, &config) == 0, "load allow-list fixture");
    unlink(path);

    check(config.allow_client_count == 2, "allow-list entry count");
    check(strcmp(config.allow_client[0], "198.51.100.9") == 0,
          "allow-list IPv4 entry");
    check(strcmp(config.allow_client[1], "2001:db8::3") == 0,
          "allow-list IPv6 entry");

    /* The list must grow past the original four-entry limit. */
    check(write_temp_file(multi_config, path, sizeof(path)) == 0,
          "write multi-client allow-list fixture");
    check(config_load(path, &config) == 0, "load multi-client allow-list");
    unlink(path);

    check(config.allow_client_count == 8, "allow-list supports many clients");
    check(strcmp(config.allow_client[7], "2001:db8::9") == 0,
          "last allow-list entry parsed");

    check(write_temp_file(bad_config, path, sizeof(path)) == 0,
          "write bad allow-list fixture");
    check(config_load(path, &config) != 0, "invalid allow-list rejected");
    unlink(path);
}

int main(void)
{
    logger_init(NULL);
    logger_set_level(LOG_ERROR);

    test_sha256();
    test_hmac();
    test_chacha20_block();
    test_chacha20_encrypt();
    test_aead_vector();
    test_key_derivation();
    test_frames();
    test_session_reset();
    test_ipv6_validation();
    test_replay();
    test_replay_wrap();
    test_config();
    test_config_reload();
    test_allow_client();

    printf("%d checks, %d failure(s)\n", g_checks, g_failures);
    return (g_failures == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
