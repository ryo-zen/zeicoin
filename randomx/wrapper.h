// randomx_wrapper.h - Header for RandomX C wrapper
#ifndef RANDOMX_WRAPPER_H
#define RANDOMX_WRAPPER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque context structure
typedef struct randomx_context randomx_context;

// Initialize RandomX in light mode
randomx_context* randomx_init_light(const char* key, size_t key_size);

// Initialize RandomX in fast mode (2GB dataset)
randomx_context* randomx_init_fast(const char* key, size_t key_size);

// Calculate hash
int randomx_calculate_hash_wrapper(randomx_context* ctx, const void* input, size_t input_size, void* output);

// Clean up
void randomx_destroy_context(randomx_context* ctx);

// Test function
int test_randomx_wrapper(void);

#ifdef __cplusplus
}
#endif

#endif // RANDOMX_WRAPPER_H