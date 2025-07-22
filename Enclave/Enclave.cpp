// Enclave/Enclave.cpp
#include "Enclave_t.h"
#include <stdint.h>
#include <string.h>
#include <sgx_tseal.h>
#include <stdlib.h>

// Custom snprintf implementation for SGX enclave
static int my_snprintf(char* str, size_t size, const char* format, int value) {
    const char* prefix = "test_file_";
    const char* suffix = ".tmp";
    char num_str[16];

    // Convert integer to string
    int temp = value;
    int digits = 0;
    if (temp == 0) digits = 1;
    else {
        while (temp > 0) {
            temp /= 10;
            digits++;
        }
    }

    // Build number string backwards
    temp = value;
    for (int i = digits - 1; i >= 0; i--) {
        num_str[i] = '0' + (temp % 10);
        temp /= 10;
    }
    num_str[digits] = '\0';

    // Concatenate parts
    size_t pos = 0;
    for (const char* p = prefix; *p && pos < size - 1; p++, pos++) {
        str[pos] = *p;
    }
    for (int i = 0; i < digits && pos < size - 1; i++, pos++) {
        str[pos] = num_str[i];
    }
    for (const char* p = suffix; *p && pos < size - 1; p++, pos++) {
        str[pos] = *p;
    }
    str[pos] = '\0';

    return pos;
}

static __inline__ uint64_t rdtsc(void) {
    __builtin_ia32_lfence();
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    __builtin_ia32_lfence();
    return ((uint64_t)hi << 32) | lo;
}

static int dummy_work(int x) {
    return x * 2 + 1;
}

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

void ecall_memory_workload(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    const int buffer_size = 1024 * 1024;
    volatile char* buffer = (volatile char*)malloc(buffer_size);

    if (!buffer) {
        *total_cycles = 0;
        return;
    }

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        for (int j = 0; j < buffer_size; j += 64) {
            buffer[j] = (char)(i + j);
        }
        for (int j = 0; j < 1000; j++) {
            int idx = (i * 1337 + j * 7919) % buffer_size;
            buffer[idx] = (char)(buffer[idx] + 1);
        }
    }
    end = rdtsc();

    free((void*)buffer);
    *total_cycles = end - start;
}

static uint32_t simple_hash(const char* data, int len) {
    uint32_t hash = 5381;
    for (int i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

void ecall_crypto_workload(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char data[256];
    volatile uint32_t result = 0;

    for (int i = 0; i < 256; i++) {
        data[i] = (char)(i ^ 0xAA);
    }

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        for (int round = 0; round < 100; round++) {
            result ^= simple_hash(data, 256);
            data[round % 256] = (char)(result & 0xFF);
        }
    }
    end = rdtsc();
    *total_cycles = end - start;
}

void ecall_syscall_overhead(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    volatile int result = 0;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
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
        ocall_do_nothing();
    }
    end = rdtsc();

    *total_cycles = end - start;
}

void ecall_file_creation_without_fence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char filename[64];
    int result;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        my_snprintf(filename, sizeof(filename), "test_file_%d.tmp", i);
        ocall_create_file(filename, &result);
        ocall_delete_file(filename);
    }
    end = rdtsc();
    *total_cycles = end - start;
}

void ecall_file_creation_with_fence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char filename[64];
    int result;

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        __asm__ __volatile__("mfence" ::: "memory");
        my_snprintf(filename, sizeof(filename), "test_file_%d.tmp", i);
        ocall_create_file(filename, &result);
        __asm__ __volatile__("mfence" ::: "memory");
        ocall_delete_file(filename);
    }
    end = rdtsc();
    *total_cycles = end - start;
}

void ecall_untrusted_file_read_without_fence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char buffer[256];
    int bytes_read;
    int result;

    ocall_create_file("benchmark_test.txt", &result);

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        ocall_read_file("benchmark_test.txt", buffer, sizeof(buffer), &bytes_read);
    }
    end = rdtsc();

    ocall_delete_file("benchmark_test.txt");
    *total_cycles = end - start;
}

void ecall_untrusted_file_read_with_fence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char buffer[256];
    int bytes_read;
    int result;

    ocall_create_file("benchmark_test.txt", &result);

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        __asm__ __volatile__("mfence" ::: "memory");
        ocall_read_file("benchmark_test.txt", buffer, sizeof(buffer), &bytes_read);
        __asm__ __volatile__("mfence" ::: "memory");
    }
    end = rdtsc();

    ocall_delete_file("benchmark_test.txt");
    *total_cycles = end - start;
}

void ecall_sealed_file_read_without_fence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char plaintext[] = "This is test data for sealing benchmark";
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, strlen(plaintext));
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_data_size);
    uint8_t* unsealed_data = (uint8_t*)malloc(strlen(plaintext) + 1);
    uint32_t unsealed_len;

    if (!sealed_data || !unsealed_data) {
        *total_cycles = 0;
        return;
    }

    sgx_seal_data(0, NULL, strlen(plaintext), (uint8_t*)plaintext, sealed_data_size, (sgx_sealed_data_t*)sealed_data);

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        unsealed_len = strlen(plaintext);
        sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, unsealed_data, &unsealed_len);
    }
    end = rdtsc();

    free(sealed_data);
    free(unsealed_data);
    *total_cycles = end - start;
}

void ecall_sealed_file_read_with_fence(uint64_t* total_cycles, int iterations) {
    uint64_t start, end;
    char plaintext[] = "This is test data for sealing benchmark";
    uint32_t sealed_data_size = sgx_calc_sealed_data_size(0, strlen(plaintext));
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_data_size);
    uint8_t* unsealed_data = (uint8_t*)malloc(strlen(plaintext) + 1);
    uint32_t unsealed_len;

    if (!sealed_data || !unsealed_data) {
        *total_cycles = 0;
        return;
    }

    sgx_seal_data(0, NULL, strlen(plaintext), (uint8_t*)plaintext, sealed_data_size, (sgx_sealed_data_t*)sealed_data);

    start = rdtsc();
    for (int i = 0; i < iterations; i++) {
        __asm__ __volatile__("mfence" ::: "memory");
        unsealed_len = strlen(plaintext);
        sgx_unseal_data((sgx_sealed_data_t*)sealed_data, NULL, NULL, unsealed_data, &unsealed_len);
        __asm__ __volatile__("mfence" ::: "memory");
    }
    end = rdtsc();

    free(sealed_data);
    free(unsealed_data);
    *total_cycles = end - start;
}
