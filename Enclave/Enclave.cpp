// Enclave/Enclave.cpp
#include "Enclave_t.h"
#include <stdint.h>
#include <string.h>

static __inline__ uint64_t rdtsc(void) {
    __builtin_ia32_lfence();
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    __builtin_ia32_lfence();
    return ((uint64_t)hi << 32) | lo;
}

static volatile int dummy_work(int x) {
    return x * 2 + 1;
}

// Original benchmarks
void ecall_benchmark_without_mfence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    volatile int result = 0;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        result += dummy_work(i);
    }
    end = rdtsc();
    *total_cycles = end - start;
}

void ecall_benchmark_with_mfence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    volatile int result = 0;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        result += dummy_work(i);
        __asm__ __volatile__("mfence" ::: "memory");
    }
    end = rdtsc();
    *total_cycles = end - start;
}

// CPU-intensive workload with mathematical operations
void ecall_cpu_intensive(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    volatile double result = 1.0;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        result *= 1.000001;
        result += (double)(i % 1000) / 1000.0;
        result = result > 2.0 ? result / 2.0 : result;
    }
    end = rdtsc();
    *total_cycles = end - start;
}

// Memory access workload
void ecall_memory_workload(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    const int buffer_size = 1024 * 1024; // 1MB
    volatile char* buffer = (volatile char*)malloc(buffer_size);

    if (!buffer) {
        *total_cycles = 0;
        return;
    }

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        // Sequential access
        for (int j = 0; j < buffer_size; j += 64) { // Cache line size
            buffer[j] = (char)(i + j);
        }
        // Random access pattern
        for (int j = 0; j < 1000; j++) {
            int idx = (i * 1337 + j * 7919) % buffer_size;
            buffer[idx] = (char)(buffer[idx] + 1);
        }
    }
    end = rdtsc();

    free((void*)buffer);
    *total_cycles = end - start;
}

// Simple hash function for crypto workload
static uint32_t simple_hash(const char* data, int len) {
    uint32_t hash = 5381;
    for (int i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

// Cryptographic workload
void ecall_crypto_workload(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char data[256];
    volatile uint32_t result = 0;

    // Initialize data
    for (int i = 0; i < 256; i++) {
        data[i] = (char)(i ^ 0xAA);
    }

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        // Multiple hash rounds
        for (int round = 0; round < 100; round++) {
            result ^= simple_hash(data, 256);
            // Modify data for next round
            data[round % 256] = (char)(result & 0xFF);
        }
    }
    end = rdtsc();
    *total_cycles = end - start;
}

// System call overhead simulation
void ecall_syscall_overhead(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    volatile int result = 0;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        // Simulate enclave exit/entry overhead with memory barriers
        __asm__ __volatile__("mfence" ::: "memory");
        result += dummy_work(i);
        __asm__ __volatile__("mfence" ::: "memory");
        __asm__ __volatile__("lfence" ::: "memory");
    }
    end = rdtsc();
    *total_cycles = end - start;
}

void ecall_ocall_benchmark(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        // This makes the enclave call out to the untrusted App
        ocall_do_nothing();
    }
    end = rdtsc();

    *total_cycles = end - start;
}

void ecall_benchmark_with_lfence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    volatile int result = 0;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        result += dummy_work(i);
        __asm__ __volatile__("lfence" ::: "memory");
    }
    end = rdtsc();
    *total_cycles = end - start;
}
