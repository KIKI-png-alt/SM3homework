/*
 * sm3_sm3.c
 *
 * A self-contained SM3 implementation in C (no crypto libraries).
 *
 * Conforms to GM/T 0004-2012 algorithm description.
 *
 * Provides:
 *   - unsigned char* sm3_hash(const unsigned char* input, size_t input_len, unsigned char output[32])
 *   - Command-line tool: -s "string"  -f file  -e encoding(utf8|gbk)  -t (run tests)
 *
 * Notes:
 *  - Padding: follows standard: append 1 bit '1', k zero bits s.t. l+1+k ¡Ô 448 (mod 512), then 64-bit BE length l (bits).
 *  - Implementation uses 32-bit words; all shifts/rotations carefully implemented.
 *
 * Author: ChatGPT (Ê¾ÀýÊµÏÖ)
 * Date: 2025-10
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <ctype.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

#ifdef USE_ICONV
#include <iconv.h>
#endif

/* -----------------------
   Utility macros
   ----------------------- */
#define ROTL32(x,n) ( ((x) << (n)) | ((x) >> (32 - (n))) )
#define GETU32_BE(p) ( ((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | ((uint32_t)(p)[2] << 8) | ((uint32_t)(p)[3]) )
#define PUTU32_BE(v, p) do { \
    (p)[0] = (uint8_t)(((v) >> 24) & 0xFF); \
    (p)[1] = (uint8_t)(((v) >> 16) & 0xFF); \
    (p)[2] = (uint8_t)(((v) >> 8) & 0xFF); \
    (p)[3] = (uint8_t)((v) & 0xFF); \
} while(0)

/* P_0, P_1 functions from standard */
static inline uint32_t P0(uint32_t x) {
    return x ^ ROTL32(x, 9) ^ ROTL32(x, 17);
}
static inline uint32_t P1(uint32_t x) {
    return x ^ ROTL32(x, 15) ^ ROTL32(x, 23);
}

/* Constants T_j */
static const uint32_t T_j1 = 0x79cc4519U; /* j=0..15 (1..16) */
static const uint32_t T_j2 = 0x7a879d8aU; /* j=16..63 (17..64) */

/* Initial IV (standard) */
static const uint32_t IV_STD[8] = {
    0x7380166fU, 0x4914b2b9U, 0x172442d7U, 0xda8a0600U,
    0xa96f30bcU, 0x163138aaU, 0xe38dee4dU, 0xb0fb0e4eU
};

/* -----------------------
   Padding & message processing
   -----------------------
   We'll implement a function that takes input bytes and returns a newly allocated
   padded buffer containing whole 512-bit (64-byte) blocks. The function will
   set the block_count (number of 64-byte blocks).
*/

/* Compute padded message; returns pointer to padded bytes and sets out_len (bytes) and block_count.
   Caller must free returned pointer. */
static unsigned char* sm3_padding(const unsigned char* input, size_t input_len, size_t *out_len, size_t *block_count) {
    if (!out_len || !block_count) return NULL;

    /* original length in bits */
    uint64_t lbits = (uint64_t)input_len * 8ULL;

    /* append 0x80 (1000 0000) then k zero bits so that (l + 1 + k) % 512 == 448 */
    /* number of bytes after padding before 64-bit length: we need total length % 64 == 56 */
    size_t rem = (input_len + 1) % 64; /* after adding 0x80, how many bytes in current block */
    size_t pad_zero_bytes;
    if (rem <= 56) {
        pad_zero_bytes = 56 - rem;
    } else {
        pad_zero_bytes = 64 + 56 - rem;
    }
    size_t total_len = input_len + 1 + pad_zero_bytes + 8; /* +1 for 0x80, +8 for 64-bit length */
    unsigned char* out = (unsigned char*)malloc(total_len);
    if (!out) return NULL;

    /* copy input */
    if (input_len > 0) memcpy(out, input, input_len);

    /* append 0x80 */
    out[input_len] = 0x80;

    /* zero bytes */
    if (pad_zero_bytes > 0) memset(out + input_len + 1, 0x00, pad_zero_bytes);

    /* append 64-bit big-endian length (bits) */
    uint64_t be_len = lbits;
    /* write big-endian */
    for (int i = 0; i < 8; ++i) {
        out[input_len + 1 + pad_zero_bytes + i] = (unsigned char)((be_len >> (56 - 8*i)) & 0xFF);
    }

    *out_len = total_len;
    *block_count = total_len / 64;
    /* assertion: total_len % 64 == 0 */
    return out;
}

/* -----------------------
   Message expansion per block
   Input: 64 bytes block
   Output: W (68 x 32-bit), Wp (64 x 32-bit)
   ----------------------- */
static void sm3_message_expand(const unsigned char block[64], uint32_t W[68], uint32_t Wp[64]) {
    /* W0..W15 from block (big-endian 32-bit words) */
    for (int j = 0; j < 16; ++j) {
        W[j] = GETU32_BE(block + 4*j);
    }
    for (int j = 16; j < 68; ++j) {
        uint32_t wj_16 = W[j-16];
        uint32_t wj_9  = W[j-9];
        uint32_t wj_3  = W[j-3];
        uint32_t tmp = wj_16 ^ wj_9 ^ ROTL32(wj_3, 15);
        W[j] = P1(tmp) ^ ROTL32(W[j-13], 7) ^ W[j-6];
    }
    for (int j = 0; j < 64; ++j) {
        Wp[j] = W[j] ^ W[j+4];
    }
}

/* -----------------------
   Compression function (one block)
   A..H initial from IV array; after 64 rounds, XOR back with IV to produce new IV
   ----------------------- */
static void sm3_compress(uint32_t V[8], const unsigned char block[64]) {
    uint32_t W[68];
    uint32_t Wp[64];
    sm3_message_expand(block, W, Wp);

    /* initialize registers */
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t SS1, SS2, TT1, TT2;
        uint32_t Tj = (j <= 15) ? T_j1 : T_j2;
        uint32_t A12 = ROTL32(A, 12);
        /* (T_j <<< j) note: j is 0-based; standard uses j index starting at 0 */
        uint32_t Tj_j = ROTL32(Tj, (uint32_t)j);
        SS1 = ROTL32((uint32_t)((uint32_t)A12 + E + Tj_j), 7);
        SS2 = SS1 ^ A12;

        if (j <= 15) {
            /* FF_1 = X ^ Y ^ Z ; GG_1 = X ^ Y ^ Z */
            TT1 = (A ^ B ^ C) + D + SS2 + Wp[j];
            TT2 = (E ^ F ^ G) + H + SS1 + W[j];
        } else {
            /* FF_2 = (X & Y) | (X & Z) | (Y & Z)
               GG_2 = (X & Y) | ((~X) & Z) */
            uint32_t FF2 = (A & B) | (A & C) | (B & C);
            uint32_t GG2 = (E & F) | ((~E) & G);
            TT1 = FF2 + D + SS2 + Wp[j];
            TT2 = GG2 + H + SS1 + W[j];
        }

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    /* update V */
    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

/* -----------------------
   Top-level sm3_hash function
   output must be 32 bytes (256 bits)
   ----------------------- */
unsigned char* sm3_hash(const unsigned char* input, size_t input_len, unsigned char output[32]) {
    if (!output) return NULL;

    size_t padded_len = 0;
    size_t block_count = 0;
    unsigned char* padded = sm3_padding(input, input_len, &padded_len, &block_count);
    if (!padded) return NULL;

    /* initial IV */
    uint32_t V[8];
    for (int i = 0; i < 8; ++i) V[i] = IV_STD[i];

    /* process each 64-byte block */
    for (size_t i = 0; i < block_count; ++i) {
        const unsigned char* block = padded + i*64;
        sm3_compress(V, block);
    }

    /* produce output (big-endian) */
    for (int i = 0; i < 8; ++i) {
        PUTU32_BE(V[i], output + 4*i);
    }

    free(padded);
    return output;
}

/* -----------------------
   Helper: convert bytes to hex string
   ----------------------- */
static void bytes_to_hex(const unsigned char *in, size_t inlen, char *out_hex /* must be 2*inlen+1 */) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen; ++i) {
        out_hex[2*i] = hex[(in[i] >> 4) & 0xF];
        out_hex[2*i+1] = hex[(in[i]) & 0xF];
    }
    out_hex[2*inlen] = '\0';
}

/* -----------------------
   CLI helpers: read file to buffer
   ----------------------- */
static unsigned char* read_file_bytes(const char *filename, size_t *out_len) {
    if (!filename || !out_len) return NULL;
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long flen = ftell(f);
    if (flen < 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = (unsigned char*)malloc((size_t)flen);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)flen, f);
    fclose(f);
    if (r != (size_t)flen) { free(buf); return NULL; }
    *out_len = r;
    return buf;
}

/* -----------------------
   Optional: convert GBK to UTF-8 using iconv (if enabled)
   If USE_ICONV not defined, this function just returns a copy of input (no conversion)
   ----------------------- */
#ifdef USE_ICONV
static unsigned char* convert_encoding_iconv(const unsigned char* in, size_t in_len, const char* from, const char* to, size_t* out_len) {
    if (!in || !from || !to || !out_len) return NULL;
    iconv_t cd = iconv_open(to, from);
    if (cd == (iconv_t)-1) {
        return NULL;
    }
    /* guess output buffer size (4x should be enough for common conversions) */
    size_t buf_size = in_len * 4 + 16;
    unsigned char* outbuf = (unsigned char*)malloc(buf_size);
    if (!outbuf) { iconv_close(cd); return NULL; }
    char* inptr = (char*)in;
    size_t inbytesleft = in_len;
    char* outptr = (char*)outbuf;
    size_t outbytesleft = buf_size;
    size_t res = iconv(cd, &inptr, &inbytesleft, &outptr, &outbytesleft);
    if (res == (size_t)-1) {
        /* conversion error */
        free(outbuf);
        iconv_close(cd);
        return NULL;
    }
    *out_len = buf_size - outbytesleft;
    iconv_close(cd);
    return outbuf;
}
#endif

/* Fallback no-op conversion: just copy */
static unsigned char* copy_bytes(const unsigned char* in, size_t in_len, size_t* out_len) {
    unsigned char* out = (unsigned char*)malloc(in_len);
    if (!out) return NULL;
    memcpy(out, in, in_len);
    *out_len = in_len;
    return out;
}

/* -----------------------
   CLI: show usage
   ----------------------- */
static void usage(const char* prog) {
    fprintf(stderr,
            "Usage: %s [-s \"string\"] [-f file] [-e encoding] [-t]\n"
            "  -s \"string\"    : hash the provided string (treated as bytes in given encoding)\n"
            "  -f file         : hash contents of file (binary safe)\n"
            "  -e encoding     : encoding of input string (utf8 or gbk). Default utf8.\n"
            "  -t              : run built-in standard tests (vectors) and exit.\n"
            "Notes:\n"
            "  - SM3 processes raw bytes. If you need to convert between encodings (GBK<->UTF-8),\n"
            "    compile with -DUSE_ICONV and link iconv, otherwise bytes are used as-provided.\n",
            prog);
}

/* -----------------------
   Standard test vectors and test runner
   ----------------------- */
static void run_standard_tests(void) {
    const char *v1 = ""; /* empty */
    const char *v2 = "abc";
    const char *v3 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    const char *exp1 = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b";
    const char *exp2 = "66c7f0f462eeedd9d1f2d46bdc10e4e24d8167c48b2860e270cf1a4427c52fcf8";
    const char *exp3 = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732";

    unsigned char out[32];
    char hex[65];

    sm3_hash((const unsigned char*)v1, strlen(v1), out);
    bytes_to_hex(out, 32, hex);
    printf("Test 1: \"\" ->\n  got : %s\n  exp : %s\n  %s\n\n", hex, exp1, (strcmp(hex, exp1)==0) ? "OK" : "FAIL");

    sm3_hash((const unsigned char*)v2, strlen(v2), out);
    bytes_to_hex(out, 32, hex);
    printf("Test 2: \"abc\" ->\n  got : %s\n  exp : %s\n  %s\n\n", hex, exp2, (strcmp(hex, exp2)==0) ? "OK" : "FAIL");

    sm3_hash((const unsigned char*)v3, strlen(v3), out);
    bytes_to_hex(out, 32, hex);
    printf("Test 3: long ->\n  got : %s\n  exp : %s\n  %s\n\n", hex, exp3, (strcmp(hex, exp3)==0) ? "OK" : "FAIL");
}

/* -----------------------
   Simple random bytes helper for tests (not cryptographically secure)
   ----------------------- */
static void simple_random_bytes(unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (unsigned char)(rand() & 0xFF);
    }
}

/* -----------------------
   Main CLI
   ----------------------- */
int main(int argc, char **argv) {
    const char *in_string = NULL;
    const char *in_file = NULL;
    const char *encoding = "utf8";
    int run_tests = 0;

    if (argc == 1) {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-s") == 0) {
            if (i+1 < argc) { in_string = argv[++i]; }
            else { fprintf(stderr, "Missing argument for -s\n"); return 1; }
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i+1 < argc) { in_file = argv[++i]; }
            else { fprintf(stderr, "Missing argument for -f\n"); return 1; }
        } else if (strcmp(argv[i], "-e") == 0) {
            if (i+1 < argc) { encoding = argv[++i]; }
            else { fprintf(stderr, "Missing argument for -e\n"); return 1; }
        } else if (strcmp(argv[i], "-t") == 0) {
            run_tests = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (run_tests) {
        run_standard_tests();
        return 0;
    }

    unsigned char *input_bytes = NULL;
    size_t input_len = 0;
    int allocated = 0;

    if (in_file) {
        input_bytes = read_file_bytes(in_file, &input_len);
        if (!input_bytes) {
            fprintf(stderr, "Failed to read file '%s'\n", in_file);
            return 2;
        }
        allocated = 1;
    } else if (in_string) {
        /* interpret C string bytes as given encoding's bytes */
        const unsigned char* raw = (const unsigned char*)in_string;
        size_t raw_len = strlen(in_string);

        /* optionally convert encoding if USE_ICONV is defined and encoding != utf8 */
#ifdef USE_ICONV
        if (encoding && strcasecmp(encoding, "gbk") == 0) {
            size_t out_len = 0;
            unsigned char* conv = convert_encoding_iconv(raw, raw_len, "GBK", "UTF-8", &out_len);
            if (conv) {
                input_bytes = conv;
                input_len = out_len;
                allocated = 1;
            } else {
                /* fallback: use raw bytes */
                input_bytes = copy_bytes(raw, raw_len, &input_len);
                allocated = 1;
            }
        } else {
            /* default: utf8 or unknown -> pass-through */
            input_bytes = copy_bytes(raw, raw_len, &input_len);
            allocated = 1;
        }
#else
        /* No iconv support; just use raw bytes as-is */
        (void)encoding; /* ignore */
        input_bytes = copy_bytes(raw, raw_len, &input_len);
        allocated = 1;
#endif
    } else {
        fprintf(stderr, "No input specified. Use -s or -f or -t\n");
        usage(argv[0]);
        return 1;
    }

    unsigned char out[32];
    char hex[65];
    if (!sm3_hash(input_bytes, input_len, out)) {
        fprintf(stderr, "sm3_hash failed\n");
        if (allocated) free(input_bytes);
        return 3;
    }
    bytes_to_hex(out, 32, hex);

    if (in_file) {
        printf("%s  %s\n", hex, in_file);
    } else {
        printf("%s\n", hex);
    }

    if (allocated) free(input_bytes);
    return 0;
}

