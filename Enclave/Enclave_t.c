#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_benchmark_without_mfence(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_benchmark_without_mfence_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_benchmark_without_mfence_t* ms = SGX_CAST(ms_ecall_benchmark_without_mfence_t*, pms);
	ms_ecall_benchmark_without_mfence_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_benchmark_without_mfence_t), ms, sizeof(ms_ecall_benchmark_without_mfence_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_benchmark_without_mfence(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_benchmark_with_mfence(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_benchmark_with_mfence_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_benchmark_with_mfence_t* ms = SGX_CAST(ms_ecall_benchmark_with_mfence_t*, pms);
	ms_ecall_benchmark_with_mfence_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_benchmark_with_mfence_t), ms, sizeof(ms_ecall_benchmark_with_mfence_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_benchmark_with_mfence(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_benchmark_with_lfence(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_benchmark_with_lfence_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_benchmark_with_lfence_t* ms = SGX_CAST(ms_ecall_benchmark_with_lfence_t*, pms);
	ms_ecall_benchmark_with_lfence_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_benchmark_with_lfence_t), ms, sizeof(ms_ecall_benchmark_with_lfence_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_benchmark_with_lfence(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_cpu_intensive(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_cpu_intensive_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_cpu_intensive_t* ms = SGX_CAST(ms_ecall_cpu_intensive_t*, pms);
	ms_ecall_cpu_intensive_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_cpu_intensive_t), ms, sizeof(ms_ecall_cpu_intensive_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_cpu_intensive(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_memory_workload(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_memory_workload_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_memory_workload_t* ms = SGX_CAST(ms_ecall_memory_workload_t*, pms);
	ms_ecall_memory_workload_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_memory_workload_t), ms, sizeof(ms_ecall_memory_workload_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_memory_workload(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_crypto_workload(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_crypto_workload_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_crypto_workload_t* ms = SGX_CAST(ms_ecall_crypto_workload_t*, pms);
	ms_ecall_crypto_workload_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_crypto_workload_t), ms, sizeof(ms_ecall_crypto_workload_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_crypto_workload(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_syscall_overhead(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_syscall_overhead_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_syscall_overhead_t* ms = SGX_CAST(ms_ecall_syscall_overhead_t*, pms);
	ms_ecall_syscall_overhead_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_syscall_overhead_t), ms, sizeof(ms_ecall_syscall_overhead_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_syscall_overhead(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_ocall_benchmark(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_ocall_benchmark_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_ocall_benchmark_t* ms = SGX_CAST(ms_ecall_ocall_benchmark_t*, pms);
	ms_ecall_ocall_benchmark_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_ocall_benchmark_t), ms, sizeof(ms_ecall_ocall_benchmark_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	uint64_t* _tmp_total_cycles = __in_ms.ms_total_cycles;
	size_t _len_total_cycles = sizeof(uint64_t);
	uint64_t* _in_total_cycles = NULL;

	CHECK_UNIQUE_POINTER(_tmp_total_cycles, _len_total_cycles);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_total_cycles != NULL && _len_total_cycles != 0) {
		if ( _len_total_cycles % sizeof(*_tmp_total_cycles) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_total_cycles = (uint64_t*)malloc(_len_total_cycles)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_total_cycles, 0, _len_total_cycles);
	}
	ecall_ocall_benchmark(_in_total_cycles, __in_ms.ms_iterations);
	if (_in_total_cycles) {
		if (memcpy_verw_s(_tmp_total_cycles, _len_total_cycles, _in_total_cycles, _len_total_cycles)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_total_cycles) free(_in_total_cycles);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_benchmark_without_mfence, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_benchmark_with_mfence, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_benchmark_with_lfence, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_cpu_intensive, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_memory_workload, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_crypto_workload, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_syscall_overhead, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_ocall_benchmark, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][8];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_do_nothing(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(0, NULL);

	return status;
}
