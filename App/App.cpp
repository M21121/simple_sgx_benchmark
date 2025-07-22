// App/App.cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sgx_urts.h>
#include "Enclave_u.h"
#include <fcntl.h>
#include <sys/stat.h>

#define ENCLAVE_FILENAME "enclave.signed.so"
#define NUM_ITERATIONS 1000000

void ocall_do_nothing() {
    // Intentionally empty. We only want to measure the cost of calling it.
    return;
}

void ocall_create_file(const char* filename, int* result) {
    int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, "test data", 9);
        close(fd);
        *result = 0;
    } else {
        *result = -1;
    }
}

void ocall_read_file(const char* filename, char* buffer, size_t buffer_size, int* bytes_read) {
    int fd = open(filename, O_RDONLY);
    if (fd >= 0) {
        *bytes_read = read(fd, buffer, buffer_size - 1);
        if (*bytes_read > 0) {
            buffer[*bytes_read] = '\0';
        }
        close(fd);
    } else {
        *bytes_read = -1;
    }
}

void ocall_delete_file(const char* filename) {
    unlink(filename);
}

int main() {
    sgx_enclave_id_t eid = 0;
    sgx_status_t ret = SGX_SUCCESS;
    sgx_launch_token_t token = {0};
    int updated = 0;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave: %d\n", ret);
        return -1;
    }

    printf("SGX Performance Benchmark Suite\n");
    printf("Iterations: %d\n\n", NUM_ITERATIONS);

    // Memory fence comparison benchmark
    printf("=== Memory Fence Benchmark ===\n");
    uint64_t cycles_without_fence, cycles_with_mfence, cycles_with_lfence;

    ecall_benchmark_without_mfence(eid, &cycles_without_fence, NUM_ITERATIONS);
    ecall_benchmark_with_mfence(eid, &cycles_with_mfence, NUM_ITERATIONS);
    ecall_benchmark_with_lfence(eid, &cycles_with_lfence, NUM_ITERATIONS);

    double avg_without = (double)cycles_without_fence / NUM_ITERATIONS;
    double avg_mfence = (double)cycles_with_mfence / NUM_ITERATIONS;
    double avg_lfence = (double)cycles_with_lfence / NUM_ITERATIONS;
    double mfence_overhead = avg_mfence - avg_without;
    double lfence_overhead = avg_lfence - avg_without;

    printf("Without fence: %lu cycles (%.2f cycles/iter)\n", cycles_without_fence, avg_without);
    printf("With MFENCE:   %lu cycles (%.2f cycles/iter)\n", cycles_with_mfence, avg_mfence);
    printf("With LFENCE:   %lu cycles (%.2f cycles/iter)\n", cycles_with_lfence, avg_lfence);
    printf("MFENCE overhead: %.2f cycles/iter (%.2f%%)\n", mfence_overhead, (mfence_overhead/avg_without)*100.0);
    printf("LFENCE overhead: %.2f cycles/iter (%.2f%%)\n\n", lfence_overhead, (lfence_overhead/avg_without)*100.0);

    // CPU-intensive workload
    printf("=== CPU Intensive Workload ===\n");
    uint64_t cpu_cycles;
    ecall_cpu_intensive(eid, &cpu_cycles, NUM_ITERATIONS/10);
    printf("CPU workload: %lu cycles (%.2f cycles/iter)\n\n", cpu_cycles, (double)cpu_cycles/(NUM_ITERATIONS/10));

    // Memory workload
    printf("=== Memory Access Workload ===\n");
    uint64_t mem_cycles;
    ecall_memory_workload(eid, &mem_cycles, NUM_ITERATIONS/100);
    printf("Memory workload: %lu cycles (%.2f cycles/iter)\n\n", mem_cycles, (double)mem_cycles/(NUM_ITERATIONS/100));

    // Crypto workload
    printf("=== Cryptographic Workload ===\n");
    uint64_t crypto_cycles;
    ecall_crypto_workload(eid, &crypto_cycles, 1000);
    printf("Crypto workload: %lu cycles (%.2f cycles/iter)\n\n", crypto_cycles, (double)crypto_cycles/1000);

    // System call overhead simulation
    printf("=== System Call Overhead ===\n");
    uint64_t syscall_cycles;
    ecall_syscall_overhead(eid, &syscall_cycles, 10000);
    printf("Syscall overhead: %lu cycles (%.2f cycles/iter)\n\n", syscall_cycles, (double)syscall_cycles/10000);

    // OCALL Benchmark
    printf("=== OCALL Benchmark ===\n");
    uint64_t ocall_cycles;
    int ocall_iterations = 10000;
    ecall_ocall_benchmark(eid, &ocall_cycles, ocall_iterations);
    printf("OCALL transition: %lu cycles (%.2f cycles/iter)\n\n", ocall_cycles, (double)ocall_cycles / ocall_iterations);

    // File Creation Benchmark
    printf("=== File Creation Benchmark ===\n");
    uint64_t file_create_without_fence, file_create_with_fence;
    int file_iterations = 1000;

    ecall_file_creation_without_fence(eid, &file_create_without_fence, file_iterations);
    ecall_file_creation_with_fence(eid, &file_create_with_fence, file_iterations);

    double avg_create_without = (double)file_create_without_fence / file_iterations;
    double avg_create_with = (double)file_create_with_fence / file_iterations;
    double create_overhead = avg_create_with - avg_create_without;

    printf("File creation without fence: %lu cycles (%.2f cycles/iter)\n", file_create_without_fence, avg_create_without);
    printf("File creation with fence:    %lu cycles (%.2f cycles/iter)\n", file_create_with_fence, avg_create_with);
    printf("Fence overhead: %.2f cycles/iter (%.2f%%)\n\n", create_overhead, (create_overhead/avg_create_without)*100.0);

    // Untrusted File Read Benchmark
    printf("=== Untrusted File Read Benchmark ===\n");
    uint64_t file_read_without_fence, file_read_with_fence;

    ecall_untrusted_file_read_without_fence(eid, &file_read_without_fence, file_iterations);
    ecall_untrusted_file_read_with_fence(eid, &file_read_with_fence, file_iterations);

    double avg_read_without = (double)file_read_without_fence / file_iterations;
    double avg_read_with = (double)file_read_with_fence / file_iterations;
    double read_overhead = avg_read_with - avg_read_without;

    printf("Untrusted read without fence: %lu cycles (%.2f cycles/iter)\n", file_read_without_fence, avg_read_without);
    printf("Untrusted read with fence:    %lu cycles (%.2f cycles/iter)\n", file_read_with_fence, avg_read_with);
    printf("Fence overhead: %.2f cycles/iter (%.2f%%)\n\n", read_overhead, (read_overhead/avg_read_without)*100.0);

    // Sealed File Read Benchmark
    printf("=== Sealed File Read Benchmark ===\n");
    uint64_t sealed_read_without_fence, sealed_read_with_fence;
    int sealed_iterations = 100;

    ecall_sealed_file_read_without_fence(eid, &sealed_read_without_fence, sealed_iterations);
    ecall_sealed_file_read_with_fence(eid, &sealed_read_with_fence, sealed_iterations);

    double avg_sealed_without = (double)sealed_read_without_fence / sealed_iterations;
    double avg_sealed_with = (double)sealed_read_with_fence / sealed_iterations;
    double sealed_overhead = avg_sealed_with - avg_sealed_without;

    printf("Sealed read without fence: %lu cycles (%.2f cycles/iter)\n", sealed_read_without_fence, avg_sealed_without);
    printf("Sealed read with fence:    %lu cycles (%.2f cycles/iter)\n", sealed_read_with_fence, avg_sealed_with);
    printf("Fence overhead: %.2f cycles/iter (%.2f%%)\n\n", sealed_overhead, (sealed_overhead/avg_sealed_without)*100.0);

    sgx_destroy_enclave(eid);
    return 0;
}
