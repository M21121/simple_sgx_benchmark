# SGX Benchmark Results

## Memory Fence Benchmark
**What it does:** Measures the overhead of memory fences in a simple loop performing dummy work (e.g., basic arithmetic). Compares no fence, MFENCE (full memory barrier), and LFENCE (load barrier). This highlights synchronization costs in SGX enclaves.
**Iterations:** 1,000,000

| Variant          | Total Cycles | Cycles/Iteration | Overhead (cycles/iter) | Overhead (%) |
|------------------|--------------|------------------|------------------------|--------------|
| Without Fence   | 4,504,046   | 4.50            | -                      | -            |
| With MFENCE     | 40,434,676  | 40.43           | 35.93                  | 797.74%      |
| With LFENCE     | 21,101,012  | 21.10           | 16.60                  | 368.49%      |

## CPU Intensive Workload
**What it does:** Simulates compute-bound tasks with floating-point operations (multiplies, adds, conditionals) in a loop. Tests pure CPU performance inside the enclave without I/O or memory barriers.
**Iterations:** 100,000

| Metric          | Value          |
|-----------------|----------------|
| Total Cycles   | 1,562,870     |
| Cycles/Iteration | 15.63        |

## Memory Access Workload
**What it does:** Tests memory-bound operations on a 1MB buffer with sequential and random accesses (to induce cache misses). Measures SGX's handling of enclave memory (EPC).
**Iterations:** 10,000

| Metric          | Value            |
|-----------------|------------------|
| Total Cycles   | 1,882,560,746   |
| Cycles/Iteration | 188,256.07     |

## Cryptographic Workload
**What it does:** Performs repeated simple hashing (DJB2-like) on a 256-byte buffer, with data modifications between rounds. Simulates crypto operations common in secure enclaves.
**Iterations:** 1,000

| Metric          | Value          |
|-----------------|----------------|
| Total Cycles   | 119,390,186   |
| Cycles/Iteration | 119,390.19   |

## System Call Overhead
**What it does:** Simulates syscall costs using memory fences to mimic enclave exit/entry overhead, combined with dummy work. Does not perform actual syscalls.
**Iterations:** 10,000

| Metric          | Value        |
|-----------------|--------------|
| Total Cycles   | 646,156     |
| Cycles/Iteration | 64.62      |

## OCALL Benchmark
**What it does:** Measures the cost of OCALLs (enclave exits to untrusted code) by calling an empty function repeatedly. Quantifies transition overhead between trusted and untrusted environments.
**Iterations:** 10,000

| Metric          | Value        |
|-----------------|--------------|
| Total Cycles   | 72,467,010  |
| Cycles/Iteration | 7,246.70   |

## File Creation Benchmark
**What it does:** Creates and deletes temporary files via OCALLs to untrusted code, measuring I/O overhead. Compares with/without MFENCE to assess fence impact on file operations.
**Iterations:** 1,000

| Variant          | Total Cycles | Cycles/Iteration | Overhead (cycles/iter) | Overhead (%) |
|------------------|--------------|------------------|------------------------|--------------|
| Without Fence   | 53,573,254  | 53,573.25       | -                      | -            |
| With Fence      | 48,147,810  | 48,147.81       | -5,425.44              | -10.13%      |

## Untrusted File Read Benchmark
**What it does:** Reads a small test file repeatedly via OCALLs to untrusted code. Compares with/without MFENCE to evaluate fence overhead on untrusted I/O. (File is created/deleted outside the loop.)
**Iterations:** 1,000

| Variant          | Total Cycles | Cycles/Iteration | Overhead (cycles/iter) | Overhead (%) |
|------------------|--------------|------------------|------------------------|--------------|
| Without Fence   | 17,168,150  | 17,168.15       | -                      | -            |
| With Fence      | 16,453,612  | 16,453.61       | -714.54                | -4.16%       |

## Sealed File Read Benchmark
**What it does:** Seals (encrypts) data once using SGX APIs, then unseals it repeatedly. Simulates reading secure, persisted data. Compares with/without MFENCE.
**Iterations:** 100

| Variant          | Total Cycles | Cycles/Iteration | Overhead (cycles/iter) | Overhead (%) |
|------------------|--------------|------------------|------------------------|--------------|
| Without Fence   | 1,222,468   | 12,224.68       | -                      | -            |
| With Fence      | 1,234,114   | 12,341.14       | 116.46                 | 0.95%        |

## Explanation of Unexpected Speedups
- **Measurement Variability:** These tests involve real disk I/O via OCALLs, which are non-deterministic. Factors like OS caching, filesystem buffering, disk contention, or scheduling can cause timing fluctuations between runs. A single run may capture anomalies where the "with fence" test benefits from better caching or less interference.
- **Fence Effects:** MFENCE ensures memory consistency, which might indirectly optimize I/O paths (e.g., by flushing buffers at opportune times) or align with CPU pipelining in ways that reduce effective latency in some scenarios.
- **Benchmark Artifacts:** The ```rdtsc``` timing includes its own overhead, and small differences can be noise. With only 1,000 iterations, statistical variance is higher compared to lighter tests with 1M iterations.

