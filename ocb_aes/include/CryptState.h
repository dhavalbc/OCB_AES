#ifndef CRYPTSTATE_H_
#define CRYPTSTATE_H_

#include <openssl/aes.h>
#include "Timer.h"

#define AES_KEY_SIZE_BITS   128
#define AES_KEY_SIZE_BYTES  (AES_KEY_SIZE_BITS/8)


class CryptState {
    private:
        CryptState(const CryptState &) = delete;
        CryptState &operator=(const CryptState &) = delete;

    public:
        unsigned char raw_key[AES_KEY_SIZE_BYTES];
        unsigned char encrypt_iv[AES_BLOCK_SIZE];
        unsigned char decrypt_iv[AES_BLOCK_SIZE];
        unsigned char decrypt_history[0x100];

        unsigned int uiGood;
        unsigned int uiLate;
        unsigned int uiLost;
        unsigned int uiResync;

        unsigned int uiRemoteGood;
        unsigned int uiRemoteLate;
        unsigned int uiRemoteLost;
        unsigned int uiRemoteResync;

        AES_KEY	encrypt_key;
        AES_KEY decrypt_key;
        Timer tLastGood;
        Timer tLastRequest;
        bool bInit;
        CryptState();

        bool isValid() const;
        void genKey();
        void setKey(const unsigned char *rkey, const unsigned char *eiv, const unsigned char *div);
        void setDecryptIV(const unsigned char *iv);

        void ocb_encrypt(const unsigned char *plain, unsigned char *encrypted, unsigned int len, const unsigned char *nonce, unsigned char *tag);
        void ocb_decrypt(const unsigned char *encrypted, unsigned char *plain, unsigned int len, const unsigned char *nonce, unsigned char *tag);

        bool decrypt(const unsigned char *source, unsigned char *dst, unsigned int crypted_length);
        void encrypt(const unsigned char *source, unsigned char *dst, unsigned int plain_length);
};

#endif
