/*
 * test_core.c - Unit tests for platform-independent pipesix modules
 *
 * Covers SHA-256/HMAC/HKDF/ChaCha20-Poly1305 known-answer vectors, key
 * derivation, the PSK handshake, per-session key isolation, frame
 * encryption and tamper detection, the replay window (including
 * counter wrap), IPv6 validation and the configuration parser.
 * Run with `make check`; no root required.
 */

#include "config.h"
#include "crypto.h"
#include "ipv6.h"
#include "logger.h"
#include "proto.h"
#include "stats.h"

#include <arpa/inet.h>
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

static int parse_ipv6(const char *text, uint8_t out[16])
{
    struct in6_addr addr;

    if (inet_pton(AF_INET6, text, &addr) != 1) {
        return -1;
    }

    memcpy(out, &addr, 16);
    return 0;
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
 * HKDF-SHA256, RFC 5869 test case 1.
 */
static void test_hkdf(void)
{
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t okm[42];
    uint8_t expected[42];
    int i;

    memset(ikm, 0x0b, sizeof(ikm));
    for (i = 0; i < (int)sizeof(salt); i++) {
        salt[i] = (uint8_t)i;
    }
    for (i = 0; i < (int)sizeof(info); i++) {
        info[i] = (uint8_t)(0xf0 + i);
    }

    check(hex_decode("3cb25f25faacd57a90434f64d0362f2a"
                     "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                     "34007208d5b887185865",
                     expected, sizeof(expected)) == 42,
          "decode HKDF vector");

    pipesix_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt),
                        info, sizeof(info), okm, sizeof(okm));

    check(memcmp(okm, expected, sizeof(expected)) == 0,
          "HKDF-SHA256 RFC 5869 case 1");
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
    uint16_t flags;
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

    check(pipesix_frame_peek(frame, frame_len, &flags) == PIPESIX_OK,
          "header peek succeeds");
    check((flags & PIPESIX_FLAG_AUTH) != 0, "peek reports authentication");

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

    /* Handshake frames are plaintext and must never carry an AEAD tag. */
    frame_len = pipesix_frame_build(frame, sizeof(frame),
                                    PIPESIX_FLAG_HANDSHAKE_INIT, salt, 10,
                                    payload, 16, NULL);
    check(frame_len == PIPESIX_HEADER_SIZE + 16, "handshake frame is plaintext");
    check(pipesix_frame_build(frame, sizeof(frame),
                              PIPESIX_FLAG_HANDSHAKE_INIT, salt, 11,
                              payload, 16, key) == 0,
          "handshake frame cannot be AEAD protected");
    check(pipesix_frame_build(frame, sizeof(frame),
                              PIPESIX_FLAG_HANDSHAKE_NEEDED, salt, 12,
                              payload, 1, NULL) == 0,
          "handshake-needed frame must be empty");
}

/*
 * INIT and RESPONSE payloads, including tamper detection.
 */
static void test_handshake_payloads(void)
{
    uint8_t psk[PIPESIX_KEY_LEN];
    uint8_t other_psk[PIPESIX_KEY_LEN];
    uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t echoed[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t init[PIPESIX_HANDSHAKE_INIT_MAX];
    uint8_t resp[PIPESIX_HANDSHAKE_RESP_MAX];
    char id[CONFIG_MAX_CLIENT_ID];
    size_t len;
    size_t i;
    char long_id[CONFIG_MAX_CLIENT_ID + 1];

    memset(psk, 0x5a, sizeof(psk));
    memset(other_psk, 0xa5, sizeof(other_psk));
    for (i = 0; i < sizeof(cnonce); i++) {
        cnonce[i] = (uint8_t)(0x10 + i);
        snonce[i] = (uint8_t)(0x80 + i);
    }

    /* --- INIT --- */

    len = pipesix_handshake_init_build(init, sizeof(init), "alice", cnonce, psk);
    check(len == 1u + 5u + PIPESIX_HANDSHAKE_NONCE_LEN +
                  PIPESIX_HANDSHAKE_MAC_LEN,
          "INIT payload length");

    check(pipesix_handshake_init_peek(init, len, id, sizeof(id), NULL) ==
              PIPESIX_OK,
          "INIT peek succeeds");
    check(strcmp(id, "alice") == 0, "INIT carries the client id");

    check(pipesix_handshake_init_verify(init, len, psk) == PIPESIX_OK,
          "INIT verifies with the right PSK");
    check(pipesix_handshake_init_verify(init, len, other_psk) ==
              PIPESIX_ERR_AUTH,
          "INIT rejects the wrong PSK");

    /* A different client id must not authenticate. */
    init[1] = (uint8_t)'b';
    check(pipesix_handshake_init_verify(init, len, psk) == PIPESIX_ERR_AUTH,
          "INIT rejects a modified client id");
    init[1] = (uint8_t)'a';

    /* Nor may a modified nonce. */
    init[1 + 5] ^= 0x01u;
    check(pipesix_handshake_init_verify(init, len, psk) == PIPESIX_ERR_AUTH,
          "INIT rejects a modified nonce");
    init[1 + 5] ^= 0x01u;

    check(pipesix_handshake_init_verify(init, len - 1, psk) ==
              PIPESIX_ERR_LENGTH,
          "truncated INIT rejected");

    check(pipesix_handshake_init_build(init, sizeof(init), "", cnonce, psk) ==
              0,
          "empty client id rejected");
    memset(long_id, 'x', sizeof(long_id));
    long_id[sizeof(long_id) - 1] = '\0';
    check(pipesix_handshake_init_build(init, sizeof(init), long_id, cnonce,
                                       psk) == 0,
          "over-long client id rejected");

    /* --- RESPONSE --- */

    len = pipesix_handshake_resp_build(resp, sizeof(resp), cnonce, snonce, psk);
    check(len == 2u * PIPESIX_HANDSHAKE_NONCE_LEN +
                  PIPESIX_HANDSHAKE_MAC_LEN,
          "RESPONSE payload length");

    check(pipesix_handshake_resp_verify(resp, len, psk, echoed) == PIPESIX_OK,
          "RESPONSE verifies");
    check(memcmp(echoed, cnonce, sizeof(cnonce)) == 0,
          "RESPONSE echoes the client nonce");

    check(pipesix_handshake_resp_verify(resp, len, other_psk, echoed) ==
              PIPESIX_ERR_AUTH,
          "RESPONSE rejects the wrong PSK");

    resp[PIPESIX_HANDSHAKE_NONCE_LEN] ^= 0x01u;
    check(pipesix_handshake_resp_verify(resp, len, psk, echoed) ==
              PIPESIX_ERR_AUTH,
          "RESPONSE rejects a modified server nonce");
    resp[PIPESIX_HANDSHAKE_NONCE_LEN] ^= 0x01u;

    check(pipesix_handshake_resp_verify(resp, len - 1, psk, echoed) ==
              PIPESIX_ERR_LENGTH,
          "truncated RESPONSE rejected");
}

/*
 * Per-client key isolation: two clients never share a keystream, and
 * the two directions of one session are independent.
 */
static void test_session_isolation(void)
{
    uint8_t psk_a[PIPESIX_KEY_LEN];
    uint8_t psk_b[PIPESIX_KEY_LEN];
    uint8_t cnonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t snonce[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t cnonce2[PIPESIX_HANDSHAKE_NONCE_LEN];
    uint8_t a_c2s[PIPESIX_KEY_LEN];
    uint8_t a_s2c[PIPESIX_KEY_LEN];
    uint8_t a_c2s_again[PIPESIX_KEY_LEN];
    uint8_t b_c2s[PIPESIX_KEY_LEN];
    uint8_t b_s2c[PIPESIX_KEY_LEN];
    uint8_t c2s2[PIPESIX_KEY_LEN];
    uint8_t s2c2[PIPESIX_KEY_LEN];
    uint8_t payload[32];
    uint8_t frame[PIPESIX_MAX_FRAME];
    pipesix_frame_t parsed;
    size_t frame_len;

    memset(psk_a, 0x11, sizeof(psk_a));
    memset(psk_b, 0x22, sizeof(psk_b));
    memset(cnonce, 0x33, sizeof(cnonce));
    memset(snonce, 0x44, sizeof(snonce));
    memset(cnonce2, 0x35, sizeof(cnonce2));
    memset(payload, 0x77, sizeof(payload));

    pipesix_session_keys(psk_a, cnonce, snonce, a_c2s, a_s2c);
    pipesix_session_keys(psk_a, cnonce, snonce, a_c2s_again, b_s2c);
    pipesix_session_keys(psk_b, cnonce, snonce, b_c2s, b_s2c);
    pipesix_session_keys(psk_a, cnonce2, snonce, c2s2, s2c2);

    check(memcmp(a_c2s, a_c2s_again, sizeof(a_c2s)) == 0,
          "session keys are deterministic");
    check(memcmp(a_c2s, a_s2c, sizeof(a_c2s)) != 0,
          "the two directions use different keys");
    check(memcmp(a_c2s, b_c2s, sizeof(a_c2s)) != 0,
          "different PSKs produce different keys");
    check(memcmp(a_c2s, c2s2, sizeof(a_c2s)) != 0,
          "a different handshake produces a different key");
    check(memcmp(a_c2s, b_s2c, sizeof(a_c2s)) != 0,
          "client A key differs from client B reverse key");

    /* A frame sealed by client A must not open under any other key. */
    frame_len = pipesix_frame_build(frame, sizeof(frame), 0, 0x01020304u, 1,
                                    payload, sizeof(payload), a_c2s);
    check(frame_len > 0, "client A frame built");

    check(pipesix_frame_parse(frame, frame_len, &parsed, a_c2s) == PIPESIX_OK,
          "client A frame opens under its own key");

    frame_len = pipesix_frame_build(frame, sizeof(frame), 0, 0x01020304u, 1,
                                    payload, sizeof(payload), a_c2s);
    check(pipesix_frame_parse(frame, frame_len, &parsed, a_s2c) ==
              PIPESIX_ERR_AUTH,
          "the reverse key cannot open a client frame");

    frame_len = pipesix_frame_build(frame, sizeof(frame), 0, 0x01020304u, 1,
                                    payload, sizeof(payload), a_c2s);
    check(pipesix_frame_parse(frame, frame_len, &parsed, b_c2s) ==
              PIPESIX_ERR_AUTH,
          "client B cannot open client A's frame");

    /* Two clients using the same sequence and salt still differ. */
    {
        uint8_t frame_a[PIPESIX_MAX_FRAME];
        uint8_t frame_b[PIPESIX_MAX_FRAME];
        size_t len_a;
        size_t len_b;

        len_a = pipesix_frame_build(frame_a, sizeof(frame_a), 0, 7u, 7,
                                    payload, sizeof(payload), a_c2s);
        len_b = pipesix_frame_build(frame_b, sizeof(frame_b), 0, 7u, 7,
                                    payload, sizeof(payload), b_c2s);
        check(len_a == len_b && len_a > 0,
              "identical inputs produce the same frame length");
        check(memcmp(frame_a + PIPESIX_HEADER_SIZE,
                     frame_b + PIPESIX_HEADER_SIZE,
                     sizeof(payload)) != 0,
              "identical sequence numbers yield different ciphertext");
    }
}

static void test_ipv6_prefix_match(void)
{
    uint8_t prefix[16];
    uint8_t addr[16];

    check(parse_ipv6("fd00:dead:beef::", prefix) == 0, "parse /64 prefix");
    check(parse_ipv6("fd00:dead:beef::2", addr) == 0, "parse address in /64");
    check(ipv6_prefix_match(prefix, 64, addr) == 1,
          "/64 matches an address inside it");

    check(parse_ipv6("fd00:dead:beee::2", addr) == 0,
          "parse address outside /64");
    check(ipv6_prefix_match(prefix, 64, addr) == 0,
          "/64 rejects another range");

    check(parse_ipv6("fd00:dead:beef::2", prefix) == 0, "parse host prefix");
    check(parse_ipv6("fd00:dead:beef::2", addr) == 0, "parse host address");
    check(ipv6_prefix_match(prefix, 128, addr) == 1,
          "/128 matches itself");

    check(parse_ipv6("fd00:dead:beef::3", addr) == 0,
          "parse neighbouring host");
    check(ipv6_prefix_match(prefix, 128, addr) == 0,
          "/128 rejects another host");
    check(ipv6_prefix_match(prefix, 127, addr) == 1,
          "/127 covers two addresses");

    check(ipv6_prefix_match(prefix, 0, addr) == 1, "/0 matches everything");
    check(ipv6_prefix_match(prefix, 129, addr) == 0,
          "prefix length 129 rejected");
    check(ipv6_prefix_match(prefix, -1, addr) == 0,
          "negative prefix length rejected");

    /* Non-byte-aligned prefixes must compare the trailing bits. */
    check(parse_ipv6("fd00::", prefix) == 0, "parse /16 prefix");
    check(parse_ipv6("fd00:1::", addr) == 0, "parse address in /16");
    check(ipv6_prefix_match(prefix, 16, addr) == 1,
          "/16 matches its own range");
    check(parse_ipv6("fd01::", addr) == 0, "parse address outside /16");
    check(ipv6_prefix_match(prefix, 16, addr) == 0,
          "/16 rejects another range");
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
        "client_id = alice\n"
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
    check(strcmp(config.client_id, "alice") == 0, "client_id parsed");
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

static void test_config_credentials(void)
{
    static const char server_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client = bob: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
    static const char duplicate_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client = alice: cccccccccccccccccccccccccccccccc\n";
    static const char malformed_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice\n";
    static const char bad_id_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = al ice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    static const char no_clients_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n";
    static const char client_without_id[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 198.51.100.9\n"
        "secret = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    static const char client_without_secret[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 198.51.100.9\n"
        "client_id = alice\n";
    const pipesix_client_cred_t *cred;
    pipesix_config_t config;
    char path[64];

    check(write_temp_file(server_config, path, sizeof(path)) == 0,
          "write server credentials fixture");
    check(config_load(path, &config) == 0, "load server credentials");
    unlink(path);

    check(config.client_count == 2, "client entries parsed");
    check(strcmp(config.clients[0].id, "alice") == 0, "first client id");
    check(strcmp(config.clients[1].id, "bob") == 0, "second client id");
    check(config_validate(&config) == 0, "server credentials validate");

    cred = config_find_client(&config, "bob");
    check(cred != NULL, "credential lookup by id");
    check(cred != NULL && strcmp(cred->secret, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") == 0,
          "credential lookup returns the right secret");
    check(config_find_client(&config, "carol") == NULL,
          "unknown client id is not found");

    check(write_temp_file(duplicate_config, path, sizeof(path)) == 0,
          "write duplicate credential fixture");
    check(config_load(path, &config) != 0, "duplicate client id rejected");
    unlink(path);

    check(write_temp_file(malformed_config, path, sizeof(path)) == 0,
          "write malformed credential fixture");
    check(config_load(path, &config) != 0, "credential without a secret rejected");
    unlink(path);

    check(write_temp_file(bad_id_config, path, sizeof(path)) == 0,
          "write bad client id fixture");
    check(config_load(path, &config) != 0, "client id with spaces rejected");
    unlink(path);

    check(write_temp_file(no_clients_config, path, sizeof(path)) == 0,
          "write server without clients fixture");
    check(config_load(path, &config) == 0, "server config without clients loads");
    unlink(path);
    check(config_validate(&config) != 0, "server without clients rejected");

    check(write_temp_file(client_without_id, path, sizeof(path)) == 0,
          "write client without id fixture");
    check(config_load(path, &config) == 0, "client config without id loads");
    unlink(path);
    check(config_validate(&config) != 0, "client without client_id rejected");

    check(write_temp_file(client_without_secret, path, sizeof(path)) == 0,
          "write client without secret fixture");
    check(config_load(path, &config) == 0, "client config without secret loads");
    unlink(path);
    check(config_validate(&config) != 0, "client without secret rejected");
}

static int overwrite_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "w");
    size_t len;

    if (fp == NULL) {
        return -1;
    }

    len = strlen(text);
    if (fwrite(text, 1, len, fp) != len) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static void test_client_routes(void)
{
    static const char routed_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00:dead:beef::2/128\n"
        "client = bob: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "client_route = bob fd00:dead:beef:1::/64\n";
    static const char bare_route_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00:dead:beef::2\n";
    static const char unknown_client_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = carol fd00::1/128\n";
    static const char malformed_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice not-an-address/64\n";
    static const char bad_len_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00::1/129\n";
    static const char zero_len_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice ::/0\n";
    static const char duplicate_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00::1/128\n"
        "client_route = alice fd00::2/128\n";
    static const char clash_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client = bob: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "client_route = alice fd00:dead:beef::2/128\n"
        "client_route = bob fd00:dead:beef::2/128\n";
    const pipesix_client_cred_t *cred;
    pipesix_config_t config;
    uint8_t addr[16];
    char path[64];

    check(write_temp_file(routed_config, path, sizeof(path)) == 0,
          "write routed credentials fixture");
    check(config_load(path, &config) == 0, "load routed credentials");
    unlink(path);
    check(config_validate(&config) == 0, "routed credentials validate");

    cred = config_find_client(&config, "alice");
    check(cred != NULL && cred->prefix_len == 128, "host route parsed");
    check(parse_ipv6("fd00:dead:beef::2", addr) == 0,
          "parse routed host address");
    check(cred != NULL &&
              ipv6_prefix_match(cred->prefix, cred->prefix_len, addr) == 1,
          "host route matches its address");

    cred = config_find_client(&config, "bob");
    check(cred != NULL && cred->prefix_len == 64, "prefix route parsed");
    check(parse_ipv6("fd00:dead:beef:1::9", addr) == 0,
          "parse address inside the prefix");
    check(cred != NULL &&
              ipv6_prefix_match(cred->prefix, cred->prefix_len, addr) == 1,
          "prefix route matches an address inside it");
    check(parse_ipv6("fd00:dead:beef::2", addr) == 0,
          "parse address outside the prefix");
    check(cred != NULL &&
              ipv6_prefix_match(cred->prefix, cred->prefix_len, addr) == 0,
          "prefix route rejects a neighbouring prefix");

    check(write_temp_file(bare_route_config, path, sizeof(path)) == 0,
          "write bare route fixture");
    check(config_load(path, &config) == 0, "load bare route");
    unlink(path);
    cred = config_find_client(&config, "alice");
    check(cred != NULL && cred->prefix_len == 128,
          "bare address defaults to /128");

    check(write_temp_file(unknown_client_config, path, sizeof(path)) == 0,
          "write route for an unknown client fixture");
    check(config_load(path, &config) != 0,
          "route for an unknown client rejected");
    unlink(path);

    check(write_temp_file(malformed_config, path, sizeof(path)) == 0,
          "write malformed route fixture");
    check(config_load(path, &config) != 0, "malformed route prefix rejected");
    unlink(path);

    check(write_temp_file(bad_len_config, path, sizeof(path)) == 0,
          "write bad route length fixture");
    check(config_load(path, &config) != 0, "prefix length 129 rejected");
    unlink(path);

    check(write_temp_file(zero_len_config, path, sizeof(path)) == 0,
          "write /0 route fixture");
    check(config_load(path, &config) != 0,
          "default route to a single client rejected");
    unlink(path);

    check(write_temp_file(duplicate_config, path, sizeof(path)) == 0,
          "write duplicate route fixture");
    check(config_load(path, &config) != 0,
          "second route for the same client rejected");
    unlink(path);

    check(write_temp_file(clash_config, path, sizeof(path)) == 0,
          "write clashing route fixture");
    check(config_load(path, &config) == 0, "clashing routes load");
    unlink(path);
    check(config_validate(&config) != 0,
          "duplicate prefixes across clients rejected");
}

static void test_config_reload(void)
{
    static const char initial[] =
        "mode = client\n"
        "tun_address = fd00::5/64\n"
        "remote_address = 198.51.100.9\n"
        "client_id = alice\n"
        "secret = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "keepalive = 5\n"
        "peer_timeout = 30\n"
        "stats_interval = 60\n"
        "log_level = info\n";
    static const char updated[] =
        "mode = client\n"
        "tun_address = fd00::9/48\n"
        "remote_address = 198.51.100.77\n"
        "client_id = alice\n"
        "secret = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
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
    check(strcmp(config.client_id, "alice") == 0,
          "reload keeps the client identity");
}

static void test_credential_rotation(void)
{
    static const char initial[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "keepalive = 20\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00:dead:beef::2/128\n";
    static const char rotated[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "keepalive = 45\n"
        "client = alice: cccccccccccccccccccccccccccccccc\n"
        "client_route = alice fd00:dead:beef::9/128\n"
        "client = bob: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
    const pipesix_client_cred_t *cred;
    pipesix_config_t config;
    uint8_t addr[16];
    char path[64];

    check(write_temp_file(initial, path, sizeof(path)) == 0,
          "write initial credential fixture");
    check(config_load(path, &config) == 0, "load initial credentials");
    check(config_reload_runtime(&config) == 0,
          "reload an unchanged configuration");
    cred = config_find_client(&config, "alice");
    check(cred != NULL &&
              strcmp(cred->secret, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0,
          "unchanged reload keeps the current key");

    /* Rewrite the same file, as an operator doing a rotation would. */
    check(overwrite_file(config.config_path, rotated) == 0,
          "rewrite the configuration for rotation");
    check(config_reload_runtime(&config) == 0, "reload rotated credentials");
    unlink(path);

    check(config.keepalive == 45, "reload applied the timing settings");
    check(config.client_count == 2, "reload adopted the new client count");

    cred = config_find_client(&config, "alice");
    check(cred != NULL &&
              strcmp(cred->secret, "cccccccccccccccccccccccccccccccc") == 0,
          "reload replaced the client's key");
    check(parse_ipv6("fd00:dead:beef::9", addr) == 0,
          "parse the rotated route");
    check(cred != NULL &&
              ipv6_prefix_match(cred->prefix, cred->prefix_len, addr) == 1,
          "reload applied the new return route");
    check(config_find_client(&config, "bob") != NULL,
          "reload added a new client");

    /* Removing a client from the file must remove it from the table. */
    check(write_temp_file(initial, path, sizeof(path)) == 0,
          "write the pre-rotation fixture again");
    check(overwrite_file(path, initial) == 0, "restore the initial file");
    check(config_load(path, &config) == 0, "reload the initial credentials");
    unlink(path);
    check(config_find_client(&config, "bob") == NULL,
          "a client absent from the file is gone after reload");
    check(config.client_count == 1, "reload adopted the smaller client count");
}

static void test_client_secret_rotation(void)
{
    static const char initial[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 203.0.113.1\n"
        "client_id = alice\n"
        "secret = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    static const char changed[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 203.0.113.1\n"
        "client_id = alice\n"
        "secret = cccccccccccccccccccccccccccccccc\n";
    static const char renamed[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 203.0.113.1\n"
        "client_id = alice2\n"
        "secret = cccccccccccccccccccccccccccccccc\n";
    static const char broken[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 203.0.113.1\n"
        "client_id = alice\n"
        "secret = \n";
    pipesix_config_t config;
    char path[64];

    check(write_temp_file(initial, path, sizeof(path)) == 0,
          "write client credential fixture");
    check(config_load(path, &config) == 0, "load client credentials");
    check(overwrite_file(config.config_path, changed) == 0,
          "rewrite the client key");
    check(config_reload_runtime(&config) == 0, "reload a client with a new key");
    check(strcmp(config.secret, "cccccccccccccccccccccccccccccccc") == 0,
          "a client adopts a rotated key on reload");

    check(overwrite_file(config.config_path, renamed) == 0,
          "rewrite the client id");
    check(config_reload_runtime(&config) == 0,
          "reload a client with a new id");
    check(strcmp(config.client_id, "alice2") == 0,
          "a client adopts a new id on reload");

    /* An unusable key must be rejected, leaving the current one in place. */
    check(overwrite_file(config.config_path, broken) == 0,
          "empty the client key");
    check(config_reload_runtime(&config) != 0,
          "a missing client key is rejected");
    check(strcmp(config.secret, "cccccccccccccccccccccccccccccccc") == 0,
          "a rejected reload keeps the working key");
    unlink(path);
}

/*
 * --rotate-all: every configured client gets a fresh key, written into
 * the file with comments and layout intact, and the result still loads.
 */
static void test_rotate_all_keys(void)
{
    static const char initial[] =
        "# rotation fixture: comments and spacing must survive\n"
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "\n"
        "client   = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00:dead:beef::2/128\n"
        "client = bob:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n";
    static const char client_conf[] =
        "mode = client\n"
        "tun_address = fd00::2/64\n"
        "remote_address = 203.0.113.1\n"
        "client_id = alice\n"
        "secret = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
    char path[512];
    char client_path[512];
    char text[4096];
    char alice_key[CONFIG_MAX_SECRET];
    pipesix_config_t config;
    pipesix_config_t reloaded;
    const pipesix_client_cred_t *cred;
    FILE *fp;
    size_t got;

    check(write_temp_file(initial, path, sizeof(path)) == 0,
          "write the rotate-all fixture");
    check(config_load(path, &config) == 0, "load the rotate-all fixture");
    check(config.client_count == 2, "the fixture has two clients");

    check(config_rotate_all_keys(&config) == 0, "rotate every client key");
    check(strcmp(config.clients[0].secret,
                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") != 0,
          "alice's key changed");
    check(strcmp(config.clients[1].secret,
                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") != 0,
          "bob's key changed");
    check(strlen(config.clients[0].secret) == 64,
          "the rotated key is 64 characters");
    check(strspn(config.clients[0].secret, "0123456789abcdef") == 64,
          "the rotated key is hexadecimal");
    check(strcmp(config.clients[0].secret, config.clients[1].secret) != 0,
          "each client gets its own key");

    memcpy(alice_key, config.clients[0].secret, sizeof(alice_key));

    check(config_load(path, &reloaded) == 0, "the rewritten file still loads");
    cred = config_find_client(&reloaded, "alice");
    check(cred != NULL && strcmp(cred->secret, alice_key) == 0,
          "the file holds alice's new key");
    check(cred != NULL && cred->prefix_len == 128,
          "the rewrite kept alice's route");
    cred = config_find_client(&reloaded, "bob");
    check(cred != NULL &&
              strcmp(cred->secret, config.clients[1].secret) == 0,
          "the file holds bob's new key");

    fp = fopen(path, "r");
    check(fp != NULL, "reopen the rewritten file");
    if (fp != NULL) {
        got = fread(text, 1, sizeof(text) - 1, fp);
        fclose(fp);
        text[got] = '\0';

        check(strstr(text, "# rotation fixture") != NULL,
              "the rewrite kept the comment");
        check(strstr(text, "client   = alice: ") != NULL,
              "the rewrite kept the spacing around '='");
        check(strstr(text, "client = bob:") != NULL,
              "the rewrite kept the spacing around ':'");
        check(strstr(text, "client_route = alice fd00:dead:beef::2/128") != NULL,
              "the rewrite kept the client_route line");
    }

    /* A second rotation must not hand out a key again. */
    check(config_rotate_all_keys(&config) == 0, "rotate every key again");
    check(strcmp(config.clients[0].secret, alice_key) != 0,
          "the second rotation produced a different key");

    /* Only a server has a client table to rotate. */
    check(write_temp_file(client_conf, client_path, sizeof(client_path)) == 0,
          "write a client-mode fixture");
    check(config_load(client_path, &config) == 0, "load the client fixture");
    check(config_rotate_all_keys(&config) != 0,
          "rotate-all refuses a client configuration");

    unlink(client_path);
    unlink(path);
}

static void test_allow_client(void)
{
    static const char allowed_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "allow_client = 198.51.100.9, 2001:db8::3\n";
    static const char multi_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "allow_client = 192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, "
        "192.0.2.5, 192.0.2.6, 192.0.2.7, 2001:db8::9\n";
    static const char bad_config[] =
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
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

static void test_client_provisioning(void)
{
    static const char fixture[] =
        "# provisioning fixture\n"
        "mode = server\n"
        "tun_address = fd00::1/64\n"
        "client = alice: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "client_route = alice fd00::2/128\n"
        "log_level = error\n";
    pipesix_config_t config;
    pipesix_config_t reloaded;
    const pipesix_client_cred_t *cred;
    char path[64];
    char secret[PIPESIX_KEY_LEN * 2 + 1];
    char contents[2048];
    FILE *fp;
    size_t len;

    check(write_temp_file(fixture, path, sizeof(path)) == 0,
          "write provisioning fixture");
    check(config_load(path, &config) == 0, "load provisioning fixture");
    check(config_validate(&config) == 0, "provisioning fixture validates");

    check(config_add_client(&config, "bob", "fd00::3/128", secret,
                            sizeof(secret)) == 0,
          "add-client rewrites the configuration");
    check(strlen(secret) == (size_t)PIPESIX_KEY_LEN * 2u,
          "add-client prints a 256-bit key");

    check(config_load(path, &reloaded) == 0, "reload provisioned file");
    check(reloaded.client_count == 2, "provisioned client is in the file");
    cred = config_find_client(&reloaded, "bob");
    check(cred != NULL, "provisioned client is found by id");
    check(cred != NULL && strcmp(cred->secret, secret) == 0,
          "printed key is the key in the file");
    check(cred != NULL && cred->prefix_len == 128,
          "provisioned client got its route");

    check(config_add_client(&reloaded, "bob", NULL, secret,
                            sizeof(secret)) != 0,
          "duplicate id is refused");
    check(config_add_client(&reloaded, "carol", "fd00::3/128", secret,
                            sizeof(secret)) != 0,
          "duplicate route is refused");
    check(config_add_client(&reloaded, "bad id", NULL, secret,
                            sizeof(secret)) != 0,
          "invalid client id is refused");

    check(config_remove_client(&reloaded, "bob") == 0,
          "remove-client rewrites the configuration");
    check(config_load(path, &reloaded) == 0, "reload after removal");
    check(reloaded.client_count == 1, "removed client is gone");
    check(config_find_client(&reloaded, "bob") == NULL,
          "removed client is no longer configured");
    check(config_remove_client(&reloaded, "bob") != 0,
          "removing an unknown client is refused");
    check(config_remove_client(&reloaded, "alice") != 0,
          "removing the last client is refused");

    fp = fopen(path, "r");
    len = (fp != NULL) ? fread(contents, 1, sizeof(contents) - 1, fp) : 0;
    if (fp != NULL) {
        fclose(fp);
    }
    contents[len] = '\0';
    check(strstr(contents, "bob") == NULL, "removal left no line behind");
    check(strstr(contents, "# provisioning fixture") != NULL,
          "comments survive a rewrite");

    unlink(path);
}

static void test_stats_json(void)
{
    pipesix_stats_t stats;
    char json[512];

    stats_init(&stats);
    stats_add_tx(&stats, 300);
    stats_add_rx(&stats, 120);
    stats_add_dropped(&stats);
    stats_add_invalid(&stats);
    stats_add_auth_failure(&stats);
    stats_add_replayed(&stats);
    stats_add_error(&stats);

    stats_format_json(&stats, "server", json, sizeof(json));

    check(json[0] == '{' && json[strlen(json) - 1] == '}',
          "stats JSON is an object");
    check(strstr(json, "\"role\":\"server\"") != NULL,
          "stats JSON carries the role");
    check(strstr(json, "\"tx_packets\":1") != NULL,
          "stats JSON counts transmitted packets");
    check(strstr(json, "\"tx_bytes\":300") != NULL,
          "stats JSON counts transmitted bytes");
    check(strstr(json, "\"rx_bytes\":120") != NULL,
          "stats JSON counts received bytes");
    check(strstr(json, "\"dropped\":1") != NULL,
          "stats JSON counts drops");
    check(strstr(json, "\"auth_failures\":1") != NULL,
          "stats JSON counts authentication failures");
    check(strstr(json, "\"last_rx_unix\":") != NULL,
          "stats JSON carries the receive timestamp");
}

/*
 * The Prometheus body is what a scraper parses, so check the wire shape
 * rather than the exact formatting: a TYPE line per metric, the mode
 * label, and values that match the counters.
 */
static void test_stats_prometheus(void)
{
    pipesix_stats_t stats;
    char body[4096];

    stats_init(&stats);
    stats_add_tx(&stats, 100);
    stats_add_rx(&stats, 40);
    stats_add_dropped(&stats);

    check(stats_format_prometheus(&stats, "server", body, sizeof(body)) == 0,
          "prometheus body formats");
    check(strstr(body, "# TYPE pipesix_tx_packets_total counter") != NULL,
          "prometheus metrics carry TYPE lines");
    check(strstr(body, "pipesix_tx_packets_total{mode=\"server\"} 1") != NULL,
          "prometheus reports one transmitted packet");
    check(strstr(body, "pipesix_tx_bytes_total{mode=\"server\"} 100") != NULL,
          "prometheus reports transmitted bytes");
    check(strstr(body, "pipesix_rx_bytes_total{mode=\"server\"} 40") != NULL,
          "prometheus reports received bytes");
    check(strstr(body, "pipesix_dropped_total{mode=\"server\"} 1") != NULL,
          "prometheus reports dropped packets");
    check(strstr(body,
                 "pipesix_last_rx_timestamp_seconds{mode=\"server\"} ") !=
              NULL,
          "prometheus reports last_rx as a timestamp");
    check(body[0] != '\0' && body[strlen(body) - 1] == '\n',
          "prometheus body ends with a newline");

    check(stats_format_prometheus(&stats, "client", body, 16) != 0,
          "prometheus formatting reports a buffer that is too small");
}

int main(void)
{
    logger_init(NULL);
    logger_set_level(LOG_ERROR);

    test_sha256();
    test_hmac();
    test_hkdf();
    test_chacha20_block();
    test_chacha20_encrypt();
    test_aead_vector();
    test_key_derivation();
    test_frames();
    test_handshake_payloads();
    test_session_isolation();
    test_ipv6_validation();
    test_ipv6_prefix_match();
    test_replay();
    test_replay_wrap();
    test_config();
    test_config_credentials();
    test_client_routes();
    test_config_reload();
    test_credential_rotation();
    test_client_secret_rotation();
    test_rotate_all_keys();
    test_allow_client();
    test_client_provisioning();
    test_stats_json();
    test_stats_prometheus();

    printf("%d checks, %d failure(s)\n", g_checks, g_failures);
    return (g_failures == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
