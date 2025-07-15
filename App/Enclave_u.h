#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_DO_NOTHING_DEFINED__
#define OCALL_DO_NOTHING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_do_nothing, (void));
#endif

sgx_status_t ecall_benchmark_without_mfence(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_benchmark_with_mfence(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_benchmark_with_lfence(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_cpu_intensive(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_memory_workload(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_crypto_workload(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_syscall_overhead(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);
sgx_status_t ecall_ocall_benchmark(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
