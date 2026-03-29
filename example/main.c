// x86_64-w64-mingw32-gcc main.c -g -o xor.exe  
#include <stdio.h>
#include <string.h>

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof(*(a)))
#endif


void crackable_xor(char *input, size_t size, char *output, char key) {
    // Actual XOR algo
    for (int i = 0; i < size; i++) {
        output[i] = input[i] ^ key;  // XOR each character with the key
    }
    output[strlen( input)] = '\0'; // Null-terminate the output string

}

int main() {
    char crackable_msg[] = {0xE2, 0xCF, 0xC6, 0xC6, 0xC5, 0x86, 0x8A, 0xFD  , 0xC5, 0xD8, 0xC6, 0xCE, 0x8B};

    char decrypted[100] = {0};
    char key = 0xAA; // XOR key, can be any byte value

    printf("Crackable Encrypted message: ");
    for (int i = 0; i < ARRAYSIZE(crackable_msg); i++) {
        printf("\\x%02X", (unsigned char)crackable_msg[i]);  // Print in hex
    }
    printf("\n");

    // Decrypt the message using the crackable XOR - floss will recover this
    crackable_xor(crackable_msg, ARRAYSIZE(crackable_msg),decrypted, key);
    printf("Decrypted message: %s\n", decrypted);


    return 0;
}
