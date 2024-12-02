#include "utils.h"

void string2hexString(unsigned char* input, int clen, char* output) {
    int i;
    for (i = 0; i < clen; i++) {
        sprintf((char*)(output + i * 2), "%02X", input[i]);
    }
    output[clen * 2] = '\0';  // Null-terminate the string
}

void hextobyte(char* hexstring, unsigned char* bytearray) {
    int i;
    int str_len = strlen(hexstring);

    for (i = 0; i < str_len / 2; i++) {
        sscanf(hexstring + 2 * i, "%02x", &bytearray[i]);
    }
}
