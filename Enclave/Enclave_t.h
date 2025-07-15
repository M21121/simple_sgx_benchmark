#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_benchmark_without_mfence(uint64_t* total_cycles, int iterations);
void ecall_benchmark_with_mfence(uint64_t* total_cycles, int iterations);
void ecall_benchmark_with_lfence(uint64_t* total_cycles, int iterations);
void ecall_cpu_intensive(uint64_t* total_cycles, int iterations);
void ecall_memory_workload(uint64_t* total_cycles, int iterations);
void ecall_crypto_workload(uint64_t* total_cycles, int iterations);
void ecall_syscall_overhead(uint64_t* total_cycles, int iterations);
void ecall_ocall_benchmark(uint64_t* total_cycles, int iterations);

sgx_status_t SGX_CDECL ocall_do_nothing(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
