#include <stdio.h>
#include <string.h>

// The accepted key is obfuscated by XOR 0x2a but fully recoverable from the binary.
int check_key(const char *k) {
    const unsigned char enc[] = {0x77,0x4b,0x59,0x49,0x0b,0x18,0x18,0x59,0x00};
    char dec[16]; int i;
    for (i = 0; i < 9; i++) dec[i] = enc[i] ^ 0x2a;   // -> plaintext key
    dec[9] = 0;
    return strcmp(k, dec) == 0;
}

int main() {
    char in[64];
    printf("key: ");
    if (scanf("%63s", in) == 1 && check_key(in)) puts("Correct");
    else puts("Wrong");
    return 0;
}
