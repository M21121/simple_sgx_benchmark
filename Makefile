# Makefile
SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
	SGX_COMMON_CFLAGS += -O0 -g
else
	SGX_COMMON_CFLAGS += -O2
endif

SGX_COMMON_CFLAGS += -Wall -Wextra -fPIC
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_CFLAGS) -std=c++11

App_Cpp_Files := App/App.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) $(App_Include_Paths)
App_Cpp_Flags := $(SGX_COMMON_CXXFLAGS) $(App_Include_Paths)

# Force use of system linker and avoid math libraries
ifeq ($(SGX_MODE), HW)
	App_Link_Flags := -fuse-ld=bfd -L$(SGX_LIBRARY_PATH) -lsgx_urts -lsgx_uae_service -lpthread -ldl -Wl,--as-needed
else
	App_Link_Flags := -fuse-ld=bfd -L$(SGX_LIBRARY_PATH) -lsgx_urts_sim -lsgx_uae_service_sim -lpthread -ldl -Wl,--as-needed
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(SGX_COMMON_CXXFLAGS) -nostdinc++ $(Enclave_Include_Paths)

ifeq ($(SGX_MODE), HW)
	Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
		-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
		-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
		-Wl,--defsym,__ImageBase=0
else
	Enclave_Link_Flags := -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
		-Wl,--whole-archive -lsgx_trts_sim -Wl,--no-whole-archive \
		-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -lsgx_tservice_sim -Wl,--end-group \
		-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
		-Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
		-Wl,--defsym,__ImageBase=0
endif

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

.PHONY: all clean

all: app enclave.signed.so

######## App Objects ########

App/Enclave_u.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

app: App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

Enclave/Enclave_t.c: $(SGX_EDGER8R) Enclave/Enclave.edl
	cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

enclave.so: Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

enclave.signed.so: enclave.so
	$(SGX_ENCLAVE_SIGNER) sign -key Enclave/Enclave_private.pem -enclave enclave.so -out $@ -config Enclave/Enclave.config.xml
	@echo "SIGN =>  $@"

clean:
	@rm -f app enclave.* $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
