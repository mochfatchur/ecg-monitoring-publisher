#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <string.h>

/**
 * @brief Converts a byte array to a hexadecimal string.
 * 
 * @param input The byte array to convert.
 * @param clen Length of the byte array.
 * @param output Output buffer for the hexadecimal string.
 */
void string2hexString(unsigned char* input, int clen, char* output);

/**
 * @brief Converts a hexadecimal string to a byte array.
 * 
 * @param hexstring The hexadecimal string to convert.
 * @param bytearray Output byte array.
 */
void hextobyte(char* hexstring, unsigned char* bytearray);

#endif // UTILS_H
