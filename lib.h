#include "aes.h"

#define KEY "abcdefghijklmnopqrstuvwabcdefghi"
#define AES_KEY "admin12345678abcdefghi"

uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

struct AES_ctx ctx = {0};