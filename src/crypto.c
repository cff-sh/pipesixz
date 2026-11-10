/*
 * crypto.c - Minimal Cryptographic Helpers for pipesix
 *
 * Implements SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104), and the
 * small helpers used by the tunnel's frame authentication layer.
 */

#include "crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/* SHA-256 round constants (FIPS 180-4, section 4.2.2) */
static const uint32_t s_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr32(uint32_t value, unsigned int bits)
{
    return (value >> bits) | (value << (32u - bits));
}

static void sha256_transform(pipesix_sha256_t *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned int i;

    for (i = 0; i < 16; i++) {
        size_t off = (size_t)i * 4u;
        w[i] = ((uint32_t)block[off] << 24) |
               ((uint32_t)block[off + 1] << 16) |
               ((uint32_t)block[off + 2] << 8) |
               (uint32_t)block[off + 3];
    }

    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + s_sha256_k[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void pipesix_sha256_init(pipesix_sha256_t *ctx)
{
    if (ctx == NULL) return;

    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->bitlen = 0;
    ctx->buflen = 0;
}

void pipesix_sha256_update(pipesix_sha256_t *ctx, const void *data, size_t len)
{
    const uint8_t *input = (const uint8_t *)data;

    if (ctx == NULL || (input == NULL && len > 0)) return;

    ctx->bitlen += (uint64_t)len * 8u;

    while (len > 0) {
        size_t space = sizeof(ctx->buf) - ctx->buflen;
        size_t take = (len < space) ? len : space;

        memcpy(ctx->buf + ctx->buflen, input, take);
        ctx->buflen += take;
        input += take;
        len -= take;

        if (ctx->buflen == sizeof(ctx->buf)) {
            sha256_transform(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void pipesix_sha256_final(pipesix_sha256_t *ctx, uint8_t out[PIPESIX_SHA256_LEN])
{
    uint8_t pad[64];
    uint8_t lenbuf[8];
    uint64_t bitlen;
    size_t padlen;
    unsigned int i;

    if (ctx == NULL || out == NULL) return;

    bitlen = ctx->bitlen;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;

    /*
     * Pad until the message length is 448 bits (mod 512), leaving room
     * for the 64-bit length field.
     */
    padlen = (ctx->buflen < 56) ? (56 - ctx->buflen)
                                : (120 - ctx->buflen);
    pipesix_sha256_update(ctx, pad, padlen);

    for (i = 0; i < 8; i++) {
        lenbuf[i] = (uint8_t)(bitlen >> (56u - 8u * i));
    }
    pipesix_sha256_update(ctx, lenbuf, sizeof(lenbuf));

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)ctx->state[i];
    }

    memset(ctx, 0, sizeof(*ctx));
}

void pipesix_sha256_oneshot(const void *data, size_t len,
                            uint8_t out[PIPESIX_SHA256_LEN])
{
    pipesix_sha256_t ctx;

    pipesix_sha256_init(&ctx);
    pipesix_sha256_update(&ctx, data, len);
    pipesix_sha256_final(&ctx, out);
}

void pipesix_hmac_sha256(const uint8_t *key, size_t keylen,
                         const void *data, size_t len,
                         uint8_t out[PIPESIX_SHA256_LEN])
{
    uint8_t normalized[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[PIPESIX_SHA256_LEN];
    pipesix_sha256_t ctx;
    size_t i;

    memset(normalized, 0, sizeof(normalized));

    if (key != NULL && keylen > sizeof(normalized)) {
        pipesix_sha256_oneshot(key, keylen, normalized);
    } else if (key != NULL) {
        memcpy(normalized, key, keylen);
    }

    for (i = 0; i < sizeof(normalized); i++) {
        ipad[i] = (uint8_t)(normalized[i] ^ 0x36u);
        opad[i] = (uint8_t)(normalized[i] ^ 0x5cu);
    }

    pipesix_sha256_init(&ctx);
    pipesix_sha256_update(&ctx, ipad, sizeof(ipad));
    pipesix_sha256_update(&ctx, data, len);
    pipesix_sha256_final(&ctx, inner);

    pipesix_sha256_init(&ctx);
    pipesix_sha256_update(&ctx, opad, sizeof(opad));
    pipesix_sha256_update(&ctx, inner, sizeof(inner));
    pipesix_sha256_final(&ctx, out);
}

/*
 * ---------------------------------------------------------------------
 * ChaCha20-Poly1305 (RFC 8439)
 * ---------------------------------------------------------------------
 */

static uint32_t rotl32(uint32_t value, unsigned int bits)
{
    return (value << bits) | (value >> (32u - bits));
}

static uint32_t load32_le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

#define CHACHA_QUARTERROUND(a, b, c, d) \
    do { \
        (a) += (b); (d) ^= (a); (d) = rotl32((d), 16); \
        (c) += (d); (b) ^= (c); (b) = rotl32((b), 12); \
        (a) += (b); (d) ^= (a); (d) = rotl32((d), 8);  \
        (c) += (d); (b) ^= (c); (b) = rotl32((b), 7);  \
    } while (0)

/*
 * Build the initial ChaCha20 state: constants, key, counter and nonce.
 */
static void chacha20_init_state(uint32_t state[16],
                                const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                                const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                                uint32_t counter)
{
    /* "expand 32-byte k" */
    static const uint8_t sigma[16] = {
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
        '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };
    unsigned int i;

    for (i = 0; i < 4u; i++) {
        state[i] = load32_le(sigma + (size_t)i * 4u);
    }
    for (i = 0; i < 8u; i++) {
        state[4u + i] = load32_le(key + (size_t)i * 4u);
    }

    state[12] = counter;

    for (i = 0; i < 3u; i++) {
        state[13u + i] = load32_le(nonce + (size_t)i * 4u);
    }
}

/*
 * Run 20 ChaCha20 rounds over the state and add the input.
 */
static void chacha20_block(const uint32_t state[16], uint8_t out[64])
{
    uint32_t x[16];
    unsigned int i;

    memcpy(x, state, sizeof(x));

    for (i = 0; i < 10u; i++) {
        CHACHA_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTERROUND(x[3], x[7], x[11], x[15]);
        CHACHA_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16u; i++) {
        store32_le(out + (size_t)i * 4u, x[i] + state[i]);
    }

    memset(x, 0, sizeof(x));
}

void pipesix_chacha20_xor(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                          const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                          uint32_t counter, uint8_t *data, size_t len)
{
    uint32_t state[16];
    uint8_t block[64];
    size_t offset = 0;

    if (key == NULL || nonce == NULL || (data == NULL && len > 0)) {
        return;
    }

    chacha20_init_state(state, key, nonce, counter);

    while (offset < len) {
        size_t take = len - offset;
        size_t i;

        if (take > sizeof(block)) {
            take = sizeof(block);
        }

        chacha20_block(state, block);

        for (i = 0; i < take; i++) {
            data[offset + i] ^= block[i];
        }

        state[12]++;
        offset += take;
    }

    memset(block, 0, sizeof(block));
    memset(state, 0, sizeof(state));
}

void pipesix_aead_nonce(uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                        uint32_t salt, uint64_t seq)
{
    unsigned int i;

    if (nonce == NULL) return;

    nonce[0] = (uint8_t)(salt >> 24);
    nonce[1] = (uint8_t)(salt >> 16);
    nonce[2] = (uint8_t)(salt >> 8);
    nonce[3] = (uint8_t)salt;

    for (i = 0; i < 8u; i++) {
        nonce[4u + i] = (uint8_t)(seq >> (56u - 8u * i));
    }
}

/*
 * Poly1305 with 26-bit limbs (the classic portable formulation).
 * All products stay below 2^62, so no 128-bit arithmetic is needed.
 */
typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t  buffer[16];
    size_t   leftover;
} pipesix_poly1305_t;

#define POLY_MASK26 0x3ffffffu
#define POLY_HIBIT  (1u << 24)

static void poly1305_init(pipesix_poly1305_t *ctx, const uint8_t key[32])
{
    uint32_t t0 = load32_le(key);
    uint32_t t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8);
    uint32_t t3 = load32_le(key + 12);

    ctx->r[0] = t0 & POLY_MASK26;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03u;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
    ctx->r[4] = (t3 >> 8) & 0x00fffffu;

    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);

    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    ctx->leftover = 0;
}

/*
 * Absorb whole 16-byte blocks. hibit is 2^128 (1 << 24 in limb 4) for
 * complete blocks and 0 for the final padded block.
 */
static void poly1305_blocks(pipesix_poly1305_t *ctx, const uint8_t *m,
                            size_t bytes, uint32_t hibit)
{
    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];
    uint32_t r0 = ctx->r[0];
    uint32_t r1 = ctx->r[1];
    uint32_t r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3];
    uint32_t r4 = ctx->r[4];
    uint32_t s1 = r1 * 5u;
    uint32_t s2 = r2 * 5u;
    uint32_t s3 = r3 * 5u;
    uint32_t s4 = r4 * 5u;

    while (bytes >= 16u) {
        uint64_t d0, d1, d2, d3, d4;
        uint32_t carry;

        h0 += load32_le(m) & POLY_MASK26;
        h1 += (load32_le(m + 3) >> 2) & POLY_MASK26;
        h2 += (load32_le(m + 6) >> 4) & POLY_MASK26;
        h3 += (load32_le(m + 9) >> 6) & POLY_MASK26;
        h4 += (load32_le(m + 12) >> 8) | hibit;

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
             (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
             (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
             (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
             (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
             (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        carry = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & POLY_MASK26;
        d1 += carry;
        carry = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & POLY_MASK26;
        d2 += carry;
        carry = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & POLY_MASK26;
        d3 += carry;
        carry = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & POLY_MASK26;
        d4 += carry;
        carry = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & POLY_MASK26;
        h0 += carry * 5u;
        carry = h0 >> 26; h0 &= POLY_MASK26; h1 += carry;

        m += 16;
        bytes -= 16u;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

static void poly1305_update(pipesix_poly1305_t *ctx, const uint8_t *data,
                            size_t len)
{
    if (len == 0) return;

    if (ctx->leftover > 0) {
        size_t want = 16u - ctx->leftover;

        if (want > len) {
            want = len;
        }
        memcpy(ctx->buffer + ctx->leftover, data, want);
        ctx->leftover += want;
        data += want;
        len -= want;

        if (ctx->leftover == 16u) {
            poly1305_blocks(ctx, ctx->buffer, 16u, POLY_HIBIT);
            ctx->leftover = 0;
        }
    }

    if (len >= 16u) {
        size_t whole = len & ~(size_t)15u;

        poly1305_blocks(ctx, data, whole, POLY_HIBIT);
        data += whole;
        len -= whole;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->leftover = len;
    }
}

static void poly1305_finish(pipesix_poly1305_t *ctx,
                            uint8_t tag[PIPESIX_AEAD_TAG_LEN])
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t carry, mask;
    uint64_t f;

    if (ctx->leftover > 0) {
        uint8_t block[16];

        memset(block, 0, sizeof(block));
        memcpy(block, ctx->buffer, ctx->leftover);
        block[ctx->leftover] = 1;
        poly1305_blocks(ctx, block, 16u, 0);
        memset(block, 0, sizeof(block));
        ctx->leftover = 0;
    }

    h0 = ctx->h[0];
    h1 = ctx->h[1];
    h2 = ctx->h[2];
    h3 = ctx->h[3];
    h4 = ctx->h[4];

    carry = h1 >> 26; h1 &= POLY_MASK26; h2 += carry;
    carry = h2 >> 26; h2 &= POLY_MASK26; h3 += carry;
    carry = h3 >> 26; h3 &= POLY_MASK26; h4 += carry;
    carry = h4 >> 26; h4 &= POLY_MASK26; h0 += carry * 5u;
    carry = h0 >> 26; h0 &= POLY_MASK26; h1 += carry;

    /* Compute h + -p, keeping the result if h >= p. */
    g0 = h0 + 5u; carry = g0 >> 26; g0 &= POLY_MASK26;
    g1 = h1 + carry; carry = g1 >> 26; g1 &= POLY_MASK26;
    g2 = h2 + carry; carry = g2 >> 26; g2 &= POLY_MASK26;
    g3 = h3 + carry; carry = g3 >> 26; g3 &= POLY_MASK26;
    g4 = h4 + carry - (1u << 26);

    mask = (g4 >> 31) - 1u;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;

    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    h0 = (h0 | (h1 << 26)) & 0xffffffffu;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffffu;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffffu;

    f = (uint64_t)h0 + ctx->pad[0];
    h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32);
    h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32);
    h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32);
    h3 = (uint32_t)f;

    store32_le(tag, h0);
    store32_le(tag + 4, h1);
    store32_le(tag + 8, h2);
    store32_le(tag + 12, h3);
}

/*
 * Feed data plus the zero padding that Poly1305 requires for the AEAD
 * construction (RFC 8439, section 2.8).
 */
static void poly1305_update_padded(pipesix_poly1305_t *ctx,
                                   const uint8_t *data, size_t len)
{
    static const uint8_t zeros[16];
    size_t remainder;

    if (len > 0) {
        poly1305_update(ctx, data, len);
    }

    remainder = len % 16u;
    if (remainder != 0) {
        poly1305_update(ctx, zeros, 16u - remainder);
    }
}

/*
 * Derive the Poly1305 one-time key from the first ChaCha20 block.
 */
static void aead_poly_key(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                          const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                          uint8_t out[32])
{
    uint32_t state[16];
    uint8_t block[64];

    chacha20_init_state(state, key, nonce, 0);
    chacha20_block(state, block);
    memcpy(out, block, 32);

    memset(block, 0, sizeof(block));
    memset(state, 0, sizeof(state));
}

int pipesix_aead_seal(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                      const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *plaintext, size_t len,
                      uint8_t *ciphertext,
                      uint8_t tag[PIPESIX_AEAD_TAG_LEN])
{
    pipesix_poly1305_t poly;
    uint8_t polykey[32];
    uint8_t lengths[16];
    unsigned int i;

    if (key == NULL || nonce == NULL || tag == NULL) return -1;
    if (len > 0 && (plaintext == NULL || ciphertext == NULL)) return -1;
    if (aad_len > 0 && aad == NULL) return -1;

    aead_poly_key(key, nonce, polykey);
    poly1305_init(&poly, polykey);

    poly1305_update_padded(&poly, aad, aad_len);

    if (ciphertext != plaintext && len > 0) {
        memcpy(ciphertext, plaintext, len);
    }
    pipesix_chacha20_xor(key, nonce, 1u, ciphertext, len);

    poly1305_update_padded(&poly, ciphertext, len);

    /* RFC 8439 encodes both lengths as 64-bit little-endian integers. */
    for (i = 0; i < 8u; i++) {
        lengths[i]      = (uint8_t)((uint64_t)aad_len >> (8u * i));
        lengths[8u + i] = (uint8_t)((uint64_t)len >> (8u * i));
    }
    poly1305_update(&poly, lengths, sizeof(lengths));

    poly1305_finish(&poly, tag);

    memset(polykey, 0, sizeof(polykey));
    memset(&poly, 0, sizeof(poly));
    return 0;
}

int pipesix_aead_open(const uint8_t key[PIPESIX_CHACHA20_KEY_LEN],
                      const uint8_t nonce[PIPESIX_AEAD_NONCE_LEN],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ciphertext, size_t len,
                      const uint8_t tag[PIPESIX_AEAD_TAG_LEN],
                      uint8_t *plaintext)
{
    pipesix_poly1305_t poly;
    uint8_t polykey[32];
    uint8_t expected[PIPESIX_AEAD_TAG_LEN];
    uint8_t lengths[16];
    unsigned int i;

    if (key == NULL || nonce == NULL || tag == NULL) return -1;
    if (len > 0 && (ciphertext == NULL || plaintext == NULL)) return -1;
    if (aad_len > 0 && aad == NULL) return -1;

    aead_poly_key(key, nonce, polykey);
    poly1305_init(&poly, polykey);

    poly1305_update_padded(&poly, aad, aad_len);
    poly1305_update_padded(&poly, ciphertext, len);

    /* RFC 8439 encodes both lengths as 64-bit little-endian integers. */
    for (i = 0; i < 8u; i++) {
        lengths[i]      = (uint8_t)((uint64_t)aad_len >> (8u * i));
        lengths[8u + i] = (uint8_t)((uint64_t)len >> (8u * i));
    }
    poly1305_update(&poly, lengths, sizeof(lengths));

    poly1305_finish(&poly, expected);

    memset(polykey, 0, sizeof(polykey));
    memset(&poly, 0, sizeof(poly));

    if (!pipesix_constant_time_eq(expected, tag, PIPESIX_AEAD_TAG_LEN)) {
        memset(expected, 0, sizeof(expected));
        return -1;
    }

    memset(expected, 0, sizeof(expected));

    if (plaintext != ciphertext && len > 0) {
        memcpy(plaintext, ciphertext, len);
    }
    pipesix_chacha20_xor(key, nonce, 1u, plaintext, len);

    return 0;
}

int pipesix_constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    size_t i;

    if (a == NULL || b == NULL) return 0;

    for (i = 0; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }

    return diff == 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int pipesix_key_from_string(const char *secret, uint8_t out[PIPESIX_KEY_LEN])
{
    size_t len;

    if (secret == NULL || out == NULL) return -1;

    len = strlen(secret);
    if (len == 0) return -1;

    /* 64 hex characters is the canonical key format from --genkey. */
    if (len == PIPESIX_KEY_LEN * 2u) {
        uint8_t decoded[PIPESIX_KEY_LEN];
        int valid = 1;
        size_t i;

        for (i = 0; i < PIPESIX_KEY_LEN; i++) {
            int hi = hex_nibble(secret[i * 2]);
            int lo = hex_nibble(secret[i * 2 + 1]);

            if (hi < 0 || lo < 0) {
                valid = 0;
                break;
            }
            decoded[i] = (uint8_t)((hi << 4) | lo);
        }

        if (valid) {
            memcpy(out, decoded, sizeof(decoded));
            return 0;
        }
    }

    /* Fall back to hashing the passphrase. */
    pipesix_sha256_oneshot(secret, len, out);
    return 0;
}

int pipesix_random_bytes(void *buf, size_t len)
{
    uint8_t *out = (uint8_t *)buf;
    size_t offset = 0;
    int fd;

    if (buf == NULL) return -1;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    while (offset < len) {
        ssize_t n = read(fd, out + offset, len - offset);

        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)n;
    }

    close(fd);
    return 0;
}

void pipesix_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;

    if (in == NULL || out == NULL) return;

    for (i = 0; i < len; i++) {
        out[i * 2]     = hex[(in[i] >> 4) & 0x0Fu];
        out[i * 2 + 1] = hex[in[i] & 0x0Fu];
    }
    out[len * 2] = '\0';
}
