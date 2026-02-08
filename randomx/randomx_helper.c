// randomx_helper.c - Standalone RandomX mining helper
// Compiled with gcc to avoid Zig C++ linking issues
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wrapper.h"

// Server mode - keep-alive subprocess for mining
void run_server_mode() {
    char line[8192];
    randomx_context* ctx = NULL;
    char current_key[256] = {0};
    char current_mode[16] = {0};

    while (fgets(line, sizeof(line), stdin)) {
        // Trim newline
        line[strcspn(line, "\n")] = 0;

        // Check for exit command
        if (strcmp(line, "exit") == 0) break;

        // Parse: hex_input:hex_key:difficulty_bytes:mode
        char* hex_input = strtok(line, ":");
        char* hex_key = strtok(NULL, ":");
        char* difficulty_str = strtok(NULL, ":");
        char* mode_str = strtok(NULL, ":");

        if (!hex_input || !hex_key || !difficulty_str || !mode_str) {
            printf("ERROR:Invalid protocol format\n");
            fflush(stdout);
            continue;
        }

        int difficulty_bytes = atoi(difficulty_str);

        // Reinitialize RandomX if key or mode changed
        if (!ctx || strcmp(current_key, hex_key) != 0 || strcmp(current_mode, mode_str) != 0) {
            if (ctx) {
                randomx_destroy_context(ctx);
                ctx = NULL;
            }

            if (strcmp(mode_str, "light") == 0) {
                ctx = randomx_init_light(hex_key, strlen(hex_key));
            } else if (strcmp(mode_str, "fast") == 0) {
                ctx = randomx_init_fast(hex_key, strlen(hex_key));
            } else {
                printf("ERROR:Invalid mode '%s'\n", mode_str);
                fflush(stdout);
                continue;
            }

            if (!ctx) {
                printf("ERROR:Failed to initialize RandomX\n");
                fflush(stdout);
                continue;
            }

            strncpy(current_key, hex_key, sizeof(current_key) - 1);
            strncpy(current_mode, mode_str, sizeof(current_mode) - 1);
        }

        // Convert hex input to bytes
        size_t input_len = strlen(hex_input) / 2;
        unsigned char* input = malloc(input_len);
        if (!input) {
            printf("ERROR:Memory allocation failed\n");
            fflush(stdout);
            continue;
        }

        for (size_t i = 0; i < input_len; i++) {
            sscanf(hex_input + 2*i, "%2hhx", &input[i]);
        }

        // Calculate hash
        unsigned char hash[32];
        int result = randomx_calculate_hash_wrapper(ctx, input, input_len, hash);
        free(input);

        if (result == 0) {
            printf("ERROR:Hash calculation failed\n");
            fflush(stdout);
            continue;
        }

        // Check difficulty
        int meets_difficulty = 1;
        for (int i = 0; i < difficulty_bytes && i < 32; i++) {
            if (hash[i] != 0) {
                meets_difficulty = 0;
                break;
            }
        }

        // Output result: hash_hex:meets_difficulty
        for (int i = 0; i < 32; i++) {
            printf("%02x", hash[i]);
        }
        printf(":%d\n", meets_difficulty);
        fflush(stdout);  // Critical: flush after each response
    }

    // Cleanup
    if (ctx) {
        randomx_destroy_context(ctx);
    }
}

// Legacy mode - one-shot hash calculation (backward compatibility)
int run_legacy_mode(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Usage: %s <input_hex> <key> <difficulty_bytes> <mode>\n", argv[0]);
        printf("Mode: 'light' or 'fast'\n");
        return 1;
    }

    const char* input_hex = argv[1];
    const char* key = argv[2];
    int difficulty_bytes = atoi(argv[3]);
    const char* mode = argv[4];

    // Convert hex input to bytes
    size_t input_len = strlen(input_hex) / 2;
    unsigned char* input = malloc(input_len);
    for (size_t i = 0; i < input_len; i++) {
        sscanf(input_hex + 2*i, "%2hhx", &input[i]);
    }

    // Initialize RandomX based on mode
    randomx_context* ctx = NULL;
    if (strcmp(mode, "light") == 0) {
        ctx = randomx_init_light(key, strlen(key));
    } else if (strcmp(mode, "fast") == 0) {
        ctx = randomx_init_fast(key, strlen(key));
    } else {
        printf("ERROR: Invalid mode '%s'. Use 'light' or 'fast'\n", mode);
        free(input);
        return 1;
    }

    if (!ctx) {
        printf("ERROR: Failed to initialize RandomX in %s mode\n", mode);
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

int main(int argc, char* argv[]) {
    if (argc == 1) {
        // No args = server mode (keep-alive for mining)
        run_server_mode();
        return 0;
    } else {
        // Args = legacy one-shot mode (backward compatibility)
        return run_legacy_mode(argc, argv);
    }
}