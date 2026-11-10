/*
 * crypto.h - Minimal Cryptographic Helpers for pipesix
 *
 * Provides SHA-256, HMAC-SHA256, constant-time comparison, secure random
 * bytes, and hex encoding. These primitives back the optional frame
 * authentication feature (see proto.h) without requiring an external
 * crypto library.
 *
 * This module is self-contained and has no OS dependencies beyond
 * /dev/urandom for random byte generation.
 */

#ifndef PIPESIX_CRYPTO_H
#define PIPESIX_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* Size of a SHA-256 digest / HMAC tag in bytes */
#define PIPESIX_SHA256_LEN 32

/* Size of an authentication key used by the tunnel */
#define PIPESIX_KEY_LEN 32

/* Size of a ChaCha20 key in bytes */
#define PIPESIX_CHACHA20_KEY_LEN 32

/* Size of a ChaCha20-Poly1305 nonce in bytes */
#define PIPESIX_AEAD_NONCE_LEN 12

/* Size of a Poly1305 authentication tag in bytes */
#define PIPESIX_AEAD_TAG_LEN 16

/* Incremental SHA-256 state */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} pipesix_sha256_t;

/* Initialize an incremental SHA-256 context. */
void pipesix_sha256_init(pipesix_sha256_t *ctx);

/* Feed data into an incremental SHA-256 context. */
void pipesix_sha256_update(pipesix_sha256_t *ctx, const void *data, size_t len);

/* Finalize an incremental SHA-256 context and write the 32-byte digest. */
void pipesix_sha256_final(pipesix_sha256_t *ctx, uint8_t out[PIPESIX_SHA256_LEN]);

/* One-shot SHA-256 of a buffer. */
void pipesix_sha256_oneshot(const void *data, size_t len,
                            uint8_t out[PIPESIX_SHA256_LEN]);

/*
 * Compute HMAC-SHA256 over a buffer.
 *
 * Parameters:
 *   key     - Key bytes (any length; long keys are hashed)
 *   keylen  - Key length in bytes
 *   data    - Message bytes
 *   len     - Message length in bytes
 *   out     - 32-byte output tag
 */
void pipesix_hmac_sha256(const uint8_t *key, size_t keylen,
                         const void *data, size_t len,
                         uint8_t out[PIPESIX_SHA256_LEN]);

/*
 * Compare two buffers in constant time (independent of where they differ).
 *
 * Returns 1 if equal, 0 otherwise.
 */
int pipesix_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

/*
 * Derive a 32-byte tunnel key from a configured secret.
 *
 * A 64-character hexadecimal string is decoded directly (this is the
 * format produced by `pipesix --genkey`). Any other non-empty string is
 * hashed with SHA-256, so passphrases are accepted as-is.
 *
 * Returns 0 on success, -1 if the secret is NULL or empty.
 */
int pipesix_key_from_string(const char *secret, uint8_t out[PIPESIX_KEY_LEN]);

/*
 * HKDF-SHA256 (RFC 5869).
 *
 * Extracts a pseudo-random key from ikm and expands it with the given
 * info string into out_len bytes. A NULL or empty salt is treated as
 * HashLen zero bytes, as the RFC specifies.
 *
 * Parameters:
 *   ikm      - Input keying material
 *   ikm_len  - IKM length
 *   salt     - Optional salt (may be NULL when salt_len is 0)
 *   salt_len - Salt length
 *   info     - Context/domain-separation string (may be binary)
 *   info_len - Info length
 *   out      - Output buffer
 *   out_len  - Number of bytes to produce (at most 255 * 32)
 */
void pipesix_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                         const uint8_t *salt, size_t salt_len,
                         const void *info, size_t info_len,
                         uint8_t *out, size_t out_len);

/*
 * XOR a buffer with the ChaCha20 keystream (RFC 8439, section 2.4).
 *
 * The transformation is its own inverse, so the same call encrypts
 * and decrypts.
 *
 * Parameters:
 *   key     - 32-byte key
 *   nonce   - 12-byte nonce (must never repeat for a given key)
 *   counter - Initial block counter; use 1 for payload encryption and
 *             0 only to derive the Poly1305 one-time key
 *   data    - Buffer to transform in place
 *   len     - Number of bytes
 */
void pipesix_chacha20_xor(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                          const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                          uint32_t counter, uint8_t *data, size_t len);

/*
 * Build the 96-bit nonce used by the tunnel from a 32-bit session salt
 * and a 64-bit sequence number.
 *
 * The salt is random per session and the sequence number never repeats
 * within a session, so a given key never sees a repeated nonce.
 */
void pipesix_aead_nonce(uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                        uint32_t salt, uint64_t seq);

/*
 * Encrypt and authenticate a message with ChaCha20-Poly1305
 * (RFC 8439, section 2.8).
 *
 * Parameters:
 *   key        - 32-byte key
 *   nonce      - 12-byte nonce
 *   aad        - Additional authenticated data (may be NULL if 0 bytes)
 *   aad_len    - Length of the AAD
 *   plaintext  - Message to seal
 *   len        - Message length
 *   ciphertext - Output buffer of len bytes; may alias plaintext
 *   tag        - Output 16-byte authentication tag
 *
 * Returns:
 *   0 on success, -1 on invalid parameters
 */
int pipesix_aead_seal(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                      const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *plaintext, size_t len,
                      uint8_t *ciphertext,
                      uint8_t tag[PIPESIX_AEAD_TAG_LEN]);

/*
 * Verify and decrypt a ChaCha20-Poly1305 message.
 *
 * The tag is compared in constant time before any plaintext is
 * produced, so a failed call leaves the output buffer untouched.
 *
 * Returns:
 *   0 on success, -1 if the tag does not verify or on invalid
 *   parameters
 */
int pipesix_aead_open(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                      const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ciphertext, size_t len,
                      const uint8_t tag[PIPESIX_AEAD_TAG_LEN],
                      uint8_t *plaintext);

/*
 * Fill a buffer with cryptographically secure random bytes.
 *
 * Returns 0 on success, -1 on failure.
 */
int pipesix_random_bytes(void *buf, size_t len);

/*
 * Encode bytes as lowercase hexadecimal.
 *
 * Parameters:
 *   in   - Input bytes
 *   len  - Number of bytes
 *   out  - Output buffer of at least (2 * len + 1) bytes
 */
void pipesix_hex_encode(const uint8_t *in, size_t len, char *out);

#endif /* PIPESIX_CRYPTO_H */
