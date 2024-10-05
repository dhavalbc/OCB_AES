#include <cstring>
#include <openssl/rand.h>
#include "CryptState.h"

// TODO : enable following code for 64bit env, commented for now.
/*
 * T qbswap(T source).
 * Changes the byte order of a value from big endian to little endian or vice versa.
 * This function can be used if you are not concerned about alignment issues,
 * and it is therefore a bit more convenient and in most cases more efficient.
*/

// template <typename T> constexpr T qbswap(T source);
// // These definitions are written so that they are recognized by most compilers
// // as bswap and replaced with single instruction builtins if available.
// template <> inline constexpr  uint64  qbswap< uint64 >(uint64 source)
// {
//     return 0
//         | ((source & static_cast<uint64>(0x00000000000000ff)) << 56)
//         | ((source & static_cast<uint64>(0x000000000000ff00)) << 40)
//         | ((source & static_cast<uint64>(0x0000000000ff0000)) << 24)
//         | ((source & static_cast<uint64>(0x00000000ff000000)) << 8)
//         | ((source & static_cast<uint64>(0x000000ff00000000)) >> 8)
//         | ((source & static_cast<uint64>(0x0000ff0000000000)) >> 24)
//         | ((source & static_cast<uint64>(0x00ff000000000000)) >> 40)
//         | ((source & static_cast<uint64>(0xff00000000000000)) >> 56);
// }

// TODO remove ByteSwap.h below copied byte swap logic from 
// https://codebrowser.dev/qt5/qtbase/src/corelib/global/qendian.h.html
// #include "ByteSwap.h"
// #define SWAP64(x) qbswap<uint64>(x)

CryptState::CryptState() {
    for (int i=0;i<0x100;i++)
        decrypt_history[i] = 0;
    bInit = false;
    memset(raw_key, 0, AES_KEY_SIZE_BYTES);
    memset(encrypt_iv, 0, AES_BLOCK_SIZE);
    memset(decrypt_iv, 0, AES_BLOCK_SIZE);
    uiGood=uiLate=uiLost=uiResync=0;
    uiRemoteGood=uiRemoteLate=uiRemoteLost=uiRemoteResync=0;
}

bool CryptState::isValid() const {
    return bInit;
}

void CryptState::genKey() {
    RAND_bytes(raw_key, AES_KEY_SIZE_BYTES);
    RAND_bytes(encrypt_iv, AES_BLOCK_SIZE);
    RAND_bytes(decrypt_iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(raw_key, AES_KEY_SIZE_BITS, &encrypt_key);
    AES_set_decrypt_key(raw_key, AES_KEY_SIZE_BITS, &decrypt_key);
    bInit = true;
}

void CryptState::setKey(const unsigned char *rkey, const unsigned char *eiv, const unsigned char *div) {
    memcpy(raw_key, rkey, AES_KEY_SIZE_BYTES);
    memcpy(encrypt_iv, eiv, AES_BLOCK_SIZE);
    memcpy(decrypt_iv, div, AES_BLOCK_SIZE);
    AES_set_encrypt_key(raw_key, AES_KEY_SIZE_BITS, &encrypt_key);
    AES_set_decrypt_key(raw_key, AES_KEY_SIZE_BITS, &decrypt_key);
    bInit = true;
}

void CryptState::setDecryptIV(const unsigned char *iv) {
    memcpy(decrypt_iv, iv, AES_BLOCK_SIZE);
}

void CryptState::encrypt(const unsigned char *source, unsigned char *dst, unsigned int plain_length) {
    unsigned char tag[AES_BLOCK_SIZE];

    // First, increase our IV.
    for (int i=0;i<AES_BLOCK_SIZE;i++)
        if (++encrypt_iv[i])
            break;

    ocb_encrypt(source, dst+4, plain_length, encrypt_iv, tag);

    dst[0] = encrypt_iv[0];
    dst[1] = tag[0];
    dst[2] = tag[1];
    dst[3] = tag[2];
}

bool CryptState::decrypt(const unsigned char *source, unsigned char *dst, unsigned int crypted_length) {
    if (crypted_length < 4)
        return false;

    unsigned int plain_length = crypted_length - 4;

    unsigned char saveiv[AES_BLOCK_SIZE];
    unsigned char ivbyte = source[0];
    bool restore = false;
    unsigned char tag[AES_BLOCK_SIZE];

    int lost = 0;
    int late = 0;

    memcpy(saveiv, decrypt_iv, AES_BLOCK_SIZE);

    if (((decrypt_iv[0] + 1) & 0xFF) == ivbyte) {
        // In order as expected.
        if (ivbyte > decrypt_iv[0]) {
            decrypt_iv[0] = ivbyte;
        } else if (ivbyte < decrypt_iv[0]) {
            decrypt_iv[0] = ivbyte;
            for (int i=1;i<AES_BLOCK_SIZE;i++)
                if (++decrypt_iv[i])
                    break;
        } else {
            return false;
        }
    } else {
        // This is either out of order or a repeat.

        int diff = ivbyte - decrypt_iv[0];
        if (diff > 128)
            diff = diff-256;
        else if (diff < -128)
            diff = diff+256;

        if ((ivbyte < decrypt_iv[0]) && (diff > -30) && (diff < 0)) {
            // Late packet, but no wraparound.
            late = 1;
            lost = -1;
            decrypt_iv[0] = ivbyte;
            restore = true;
        } else if ((ivbyte > decrypt_iv[0]) && (diff > -30) && (diff < 0)) {
            // Last was 0x02, here comes 0xff from last round
            late = 1;
            lost = -1;
            decrypt_iv[0] = ivbyte;
            for (int i=1;i<AES_BLOCK_SIZE;i++)
                if (decrypt_iv[i]--)
                    break;
            restore = true;
        } else if ((ivbyte > decrypt_iv[0]) && (diff > 0)) {
            // Lost a few packets, but beyond that we're good.
            lost = ivbyte - decrypt_iv[0] - 1;
            decrypt_iv[0] = ivbyte;
        } else if ((ivbyte < decrypt_iv[0]) && (diff > 0)) {
            // Lost a few packets, and wrapped around
            lost = 256 - decrypt_iv[0] + ivbyte - 1;
            decrypt_iv[0] = ivbyte;
            for (int i=1;i<AES_BLOCK_SIZE;i++)
                if (++decrypt_iv[i])
                    break;
        } else {
            return false;
        }

        if (decrypt_history[decrypt_iv[0]] == decrypt_iv[1]) {
            memcpy(decrypt_iv, saveiv, AES_BLOCK_SIZE);
            return false;
        }
    }

    ocb_decrypt(source+4, dst, plain_length, decrypt_iv, tag);

    if (memcmp(tag, source+1, 3) != 0) {
        memcpy(decrypt_iv, saveiv, AES_BLOCK_SIZE);
        return false;
    }
    decrypt_history[decrypt_iv[0]] = decrypt_iv[1];

    if (restore)
        memcpy(decrypt_iv, saveiv, AES_BLOCK_SIZE);

    uiGood++;
    uiLate += late;
    uiLost += lost;

    tLastGood.restart();
    return true;
}

// TODO : we only support 32bit env for now
// #if defined(__LP64__)
// #define BLOCKSIZE 2
// #define SHIFTBITS 63
// typedef quint64 subblock;
// #define SWAPPED(x) SWAP64(x)
// #else

#define BLOCKSIZE 4
#define SHIFTBITS 31
//typedef quint32 subblock;
typedef unsigned int subblock;
#define SWAPPED(x) htonl(x)
// #endif

typedef subblock keyblock[BLOCKSIZE];

#define HIGHBIT (1<<SHIFTBITS);


static void inline XOR(subblock *dst, const subblock *a, const subblock *b) {
    for (int i=0;i<BLOCKSIZE;i++) {
        dst[i] = a[i] ^ b[i];
    }
}

static void inline S2(subblock *block) {
    subblock carry = SWAPPED(block[0]) >> SHIFTBITS;
    for (int i=0;i<BLOCKSIZE-1;i++)
        block[i] = SWAPPED((SWAPPED(block[i]) << 1) | (SWAPPED(block[i+1]) >> SHIFTBITS));
    block[BLOCKSIZE-1] = SWAPPED((SWAPPED(block[BLOCKSIZE-1]) << 1) ^(carry * 0x87));
}

static void inline S3(subblock *block) {
    subblock carry = SWAPPED(block[0]) >> SHIFTBITS;
    for (int i=0;i<BLOCKSIZE-1;i++)
        block[i] ^= SWAPPED((SWAPPED(block[i]) << 1) | (SWAPPED(block[i+1]) >> SHIFTBITS));
    block[BLOCKSIZE-1] ^= SWAPPED((SWAPPED(block[BLOCKSIZE-1]) << 1) ^(carry * 0x87));
}

static void inline ZERO(keyblock &block) {
    for (int i=0;i<BLOCKSIZE;i++)
        block[i]=0;
}

#define AESencrypt(src,dst,key) AES_encrypt(reinterpret_cast<const unsigned char *>(src),reinterpret_cast<unsigned char *>(dst), key);
#define AESdecrypt(src,dst,key) AES_decrypt(reinterpret_cast<const unsigned char *>(src),reinterpret_cast<unsigned char *>(dst), key);

void CryptState::ocb_encrypt(const unsigned char *plain, unsigned char *encrypted, unsigned int len, const unsigned char *nonce, unsigned char *tag) {
    keyblock checksum, delta, tmp, pad;

    // Initialize
    AESencrypt(nonce, delta, &encrypt_key);
    ZERO(checksum);

    while (len > AES_BLOCK_SIZE) {
        S2(delta);
        XOR(tmp, delta, reinterpret_cast<const subblock *>(plain));
        AESencrypt(tmp, tmp, &encrypt_key);
        XOR(reinterpret_cast<subblock *>(encrypted), delta, tmp);
        XOR(checksum, checksum, reinterpret_cast<const subblock *>(plain));
        len -= AES_BLOCK_SIZE;
        plain += AES_BLOCK_SIZE;
        encrypted += AES_BLOCK_SIZE;
    }

    S2(delta);
    ZERO(tmp);
    tmp[BLOCKSIZE - 1] = SWAPPED(len * 8);
    XOR(tmp, tmp, delta);
    AESencrypt(tmp, pad, &encrypt_key);
    memcpy(tmp, plain, len);
    memcpy(reinterpret_cast<unsigned char *>(tmp)+len, reinterpret_cast<const unsigned char *>(pad)+len, AES_BLOCK_SIZE - len);
    XOR(checksum, checksum, tmp);
    XOR(tmp, pad, tmp);
    memcpy(encrypted, tmp, len);

    S3(delta);
    XOR(tmp, delta, checksum);
    AESencrypt(tmp, tag, &encrypt_key);
}

void CryptState::ocb_decrypt(const unsigned char *encrypted, unsigned char *plain, unsigned int len, const unsigned char *nonce, unsigned char *tag) {
    keyblock checksum, delta, tmp, pad;

    // Initialize
    AESencrypt(nonce, delta, &encrypt_key);
    ZERO(checksum);

    while (len > AES_BLOCK_SIZE) {
        S2(delta);
        XOR(tmp, delta, reinterpret_cast<const subblock *>(encrypted));
        AESdecrypt(tmp, tmp, &decrypt_key);
        XOR(reinterpret_cast<subblock *>(plain), delta, tmp);
        XOR(checksum, checksum, reinterpret_cast<const subblock *>(plain));
        len -= AES_BLOCK_SIZE;
        plain += AES_BLOCK_SIZE;
        encrypted += AES_BLOCK_SIZE;
    }

    S2(delta);
    ZERO(tmp);
    tmp[BLOCKSIZE - 1] = SWAPPED(len * 8);
    XOR(tmp, tmp, delta);
    AESencrypt(tmp, pad, &encrypt_key);
    memset(tmp, 0, AES_BLOCK_SIZE);
    memcpy(tmp, encrypted, len);
    XOR(tmp, tmp, pad);
    XOR(checksum, checksum, tmp);
    memcpy(plain, tmp, len);

    S3(delta);
    XOR(tmp, delta, checksum);
    AESencrypt(tmp, tag, &encrypt_key);
}
