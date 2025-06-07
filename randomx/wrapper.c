// randomx_wrapper_lib.c - C wrapper for RandomX (library version without main)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "randomx.h"
#include "wrapper.h"

// Simple C wrapper functions to avoid C++ linking in Zig

struct randomx_context {
    randomx_cache* cache;
    randomx_dataset* dataset;
    randomx_vm* vm;
};

// Initialize RandomX in light mode
randomx_context* randomx_init_light(const char* key, size_t key_size) {
    randomx_context* ctx = malloc(sizeof(randomx_context));
    if (!ctx) return NULL;
    
    ctx->dataset = NULL;
    
    // Create cache
    ctx->cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
    if (!ctx->cache) {
        free(ctx);
        return NULL;
    }
    
    // Initialize cache
    randomx_init_cache(ctx->cache, key, key_size);
    
    // Create VM
    ctx->vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, ctx->cache, NULL);
    if (!ctx->vm) {
        randomx_release_cache(ctx->cache);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

// Calculate hash
int randomx_calculate_hash_wrapper(randomx_context* ctx, const void* input, size_t input_size, void* output) {
    if (!ctx || !ctx->vm) return 0;
    
    randomx_calculate_hash(ctx->vm, input, input_size, output);
    return 1;
}

// Clean up
void randomx_destroy_context(randomx_context* ctx) {
    if (!ctx) return;
    
    if (ctx->vm) {
        randomx_destroy_vm(ctx->vm);
    }
    if (ctx->dataset) {
        randomx_release_dataset(ctx->dataset);
    }
    if (ctx->cache) {
        randomx_release_cache(ctx->cache);
    }
    free(ctx);
}

// Initialize RandomX in fast mode (with 2GB dataset)
randomx_context* randomx_init_fast(const char* key, size_t key_size) {
    randomx_context* ctx = malloc(sizeof(randomx_context));
    if (!ctx) return NULL;
    
    // Create cache
    ctx->cache = randomx_alloc_cache(RANDOMX_FLAG_DEFAULT);
    if (!ctx->cache) {
        free(ctx);
        return NULL;
    }
    
    // Initialize cache
    randomx_init_cache(ctx->cache, key, key_size);
    
    // Allocate dataset (2GB)
    ctx->dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
    if (!ctx->dataset) {
        randomx_release_cache(ctx->cache);
        free(ctx);
        return NULL;
    }
    
    // Initialize dataset from cache
    randomx_init_dataset(ctx->dataset, ctx->cache, 0, randomx_dataset_item_count());
    
    // Create VM with dataset (fast mode)
    ctx->vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, NULL, ctx->dataset);
    if (!ctx->vm) {
        randomx_release_dataset(ctx->dataset);
        randomx_release_cache(ctx->cache);
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

// Test function
int test_randomx_wrapper() {
    const char* key = "ZeiCoin Test Key";
    const char* input = "Hello RandomX";
    unsigned char output[32];
    
    printf("Testing RandomX C wrapper...\n");
    
    randomx_context* ctx = randomx_init_light(key, strlen(key));
    if (!ctx) {
        printf("Failed to initialize RandomX\n");
        return 1; // Error
    }
    
    if (!randomx_calculate_hash_wrapper(ctx, input, strlen(input), output)) {
        printf("Failed to calculate hash\n");
        randomx_destroy_context(ctx);
        return 1; // Error
    }
    
    printf("Hash calculated successfully: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x", output[i]);
    }
    printf("...\n");
    
    randomx_destroy_context(ctx);
    return 0; // Success
}