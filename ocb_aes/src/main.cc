#include <iostream>
#include <string>

#include "CryptState.h"

using namespace std;
#define STACKVAR(type, varname, count) type *varname=reinterpret_cast<type *>(_alloca(sizeof(type) * (count)))

int main() {
    const unsigned char rawkey[AES_BLOCK_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const unsigned char nonce[AES_BLOCK_SIZE]  = { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                                                0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 };
    CryptState cs;
    cs.setKey(rawkey, nonce, nonce);

    const unsigned char msg[] = "Testing OCB-AES encrypted string...";
    int len = sizeof(msg);

    cout << "before msg :" << msg << endl;

    // encrypted msg should be allocated 4 additional bytes
    // 1st byte for encryption_iv / nonce
    // and next 3 bytes are for tag added by encryption algorithm
    unsigned char encrypted[len+4];
    unsigned char decrypted[len];

    cs.encrypt(msg, encrypted, len);
    cs.decrypt(encrypted, decrypted, len+4);

    cout << "msg :" << msg << endl;
    cout << "encrypted msg :" << encrypted << endl;
    cout << "decrypted msg :" << decrypted << endl;

    return 0;
}
