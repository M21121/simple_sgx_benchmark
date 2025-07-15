#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_benchmark_without_mfence_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_benchmark_without_mfence_t;

typedef struct ms_ecall_benchmark_with_mfence_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_benchmark_with_mfence_t;

typedef struct ms_ecall_benchmark_with_lfence_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_benchmark_with_lfence_t;

typedef struct ms_ecall_cpu_intensive_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_cpu_intensive_t;

typedef struct ms_ecall_memory_workload_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_memory_workload_t;

typedef struct ms_ecall_crypto_workload_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_crypto_workload_t;

typedef struct ms_ecall_syscall_overhead_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_syscall_overhead_t;

typedef struct ms_ecall_ocall_benchmark_t {
	uint64_t* ms_total_cycles;
	int ms_iterations;
} ms_ecall_ocall_benchmark_t;

static sgx_status_t SGX_CDECL Enclave_ocall_do_nothing(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_do_nothing();
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_do_nothing,
	}
};
sgx_status_t ecall_benchmark_without_mfence(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_benchmark_without_mfence_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_benchmark_with_mfence(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_benchmark_with_mfence_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_benchmark_with_lfence(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_benchmark_with_lfence_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_cpu_intensive(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_cpu_intensive_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_memory_workload(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_memory_workload_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_crypto_workload(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_crypto_workload_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_syscall_overhead(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_syscall_overhead_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_ocall_benchmark(sgx_enclave_id_t eid, uint64_t* total_cycles, int iterations)
{
	sgx_status_t status;
	ms_ecall_ocall_benchmark_t ms;
	ms.ms_total_cycles = total_cycles;
	ms.ms_iterations = iterations;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

