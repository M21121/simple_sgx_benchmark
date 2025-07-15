// App/App.cpp
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sgx_urts.h>
#include "Enclave_u.h"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define NUM_ITERATIONS 1000000

void ocall_do_nothing() {
    // Intentionally empty. We only want to measure the cost of calling it.
    return;
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

    sgx_destroy_enclave(eid);
    return 0;
}
