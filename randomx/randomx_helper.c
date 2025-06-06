// randomx_helper.c - Standalone RandomX mining helper
// Compiled with gcc to avoid Zig C++ linking issues
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wrapper.h"

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("Usage: %s <input_hex> <key> <difficulty_bytes>\n", argv[0]);
        return 1;
    }
    
    const char* input_hex = argv[1];
    const char* key = argv[2];
    int difficulty_bytes = atoi(argv[3]);
    
    // Convert hex input to bytes
    size_t input_len = strlen(input_hex) / 2;
    unsigned char* input = malloc(input_len);
    for (size_t i = 0; i < input_len; i++) {
        sscanf(input_hex + 2*i, "%2hhx", &input[i]);
    }
    
    // Initialize RandomX
    randomx_context* ctx = randomx_init_light(key, strlen(key));
    if (!ctx) {
        printf("ERROR: Failed to initialize RandomX\n");
        free(input);
        return 1;
    }
    
    // Calculate hash
    unsigned char hash[32];
    int result = randomx_calculate_hash_wrapper(ctx, input, input_len, hash);
    if (result == 0) {
        printf("ERROR: Hash calculation failed\n");
        randomx_destroy_context(ctx);
        free(input);
        return 1;
    }
    
    // Check difficulty
    int meets_difficulty = 1;
    for (int i = 0; i < difficulty_bytes && i < 32; i++) {
        if (hash[i] != 0) {
            meets_difficulty = 0;
            break;
        }
    }
    
    // Output result: HASH_HEX:MEETS_DIFFICULTY
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf(":%d\n", meets_difficulty);
    
    // Cleanup
    randomx_destroy_context(ctx);
    free(input);
    return 0;
}