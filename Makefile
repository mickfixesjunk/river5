# Minimal Makefile so the C bench builds on systems without CMake.
# CMakeLists.txt is the source of truth for Windows / proper builds.

CC      ?= cc
CXX     ?= c++
CFLAGS  ?= -O3 -Wall -Wextra -fno-strict-aliasing -std=c11
CXXFLAGS ?= -O3 -Wall -Wextra -fno-strict-aliasing -std=c++11
# _POSIX_C_SOURCE for clock_gettime; _DEFAULT_SOURCE for lstat/DT_*.
CPPFLAGS = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
INCLUDES = -Iinclude -Icsrc -Ithird_party/xxhash -Ithird_party/blake3 \
           -Ithird_party/metrohash -Ithird_party/meow_hash -Ibench

LIB_SRC  = csrc/river5.c csrc/river5_stub.c csrc/river5_aesni.c \
           csrc/river5_aesni_v2.c csrc/river5_aesni_v3.c \
           csrc/river5_aesni_v6.c csrc/river5_aesni_v11.c csrc/river5_aesni_v14.c \
           third_party/xxhash/xxhash.c
BENCH_SRC = bench/main.c bench/hashes.c bench/micro.c bench/file.c

BUILD = build

# ---- BLAKE3 objects (portable + SIMD with per-file flags) ----
B3_DIR = third_party/blake3
B3_PORTABLE_OBJS = \
    $(BUILD)/blake3.o \
    $(BUILD)/blake3_dispatch.o \
    $(BUILD)/blake3_portable.o \
    $(BUILD)/blake3_wrap.o
B3_SIMD_OBJS = \
    $(BUILD)/blake3_sse2.o \
    $(BUILD)/blake3_sse41.o \
    $(BUILD)/blake3_avx2.o
B3_OBJS = $(B3_PORTABLE_OBJS) $(B3_SIMD_OBJS)

# ---- MetroHash object (C++) ----
METRO_OBJS = \
    $(BUILD)/metrohash128.o \
    $(BUILD)/metrohash_wrap.o

# ---- Meow Hash object (needs AES-NI + SSE4) ----
MEOW_OBJS = $(BUILD)/meow_wrap.o

EXTRA_OBJS = $(B3_OBJS) $(METRO_OBJS) $(MEOW_OBJS)

all: $(BUILD)/river5-bench $(BUILD)/river5-quality

quality: $(BUILD)/river5-quality
	@$(BUILD)/river5-quality

$(BUILD)/river5-quality: test/quality.c $(BUILD)/libriver5.a | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) test/quality.c $(BUILD)/libriver5.a -o $@

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/libriver5.a: $(LIB_SRC) include/river5.h csrc/river5_internal.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5.c       -o $(BUILD)/river5.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_stub.c  -o $(BUILD)/river5_stub.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_aesni.c -o $(BUILD)/river5_aesni.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_aesni_v2.c -o $(BUILD)/river5_aesni_v2.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_aesni_v3.c -o $(BUILD)/river5_aesni_v3.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_aesni_v6.c -o $(BUILD)/river5_aesni_v6.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_aesni_v11.c -o $(BUILD)/river5_aesni_v11.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c csrc/river5_aesni_v14.c -o $(BUILD)/river5_aesni_v14.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c third_party/xxhash/xxhash.c -o $(BUILD)/xxhash.o
	ar rcs $@ $(BUILD)/river5.o $(BUILD)/river5_stub.o $(BUILD)/river5_aesni.o $(BUILD)/river5_aesni_v2.o $(BUILD)/river5_aesni_v3.o $(BUILD)/river5_aesni_v6.o $(BUILD)/river5_aesni_v11.o $(BUILD)/river5_aesni_v14.o $(BUILD)/xxhash.o

# ---- BLAKE3 portable build (no SIMD flags) ----
# We disable AVX-512 in the dispatch because we don't compile blake3_avx512.c
# (it needs more isolated flag setup and isn't worth it on most desktop CPUs).
B3_DISPATCH_FLAGS = -DBLAKE3_NO_AVX512

$(BUILD)/blake3.o: $(B3_DIR)/blake3.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@
$(BUILD)/blake3_dispatch.o: $(B3_DIR)/blake3_dispatch.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) $(B3_DISPATCH_FLAGS) -c $< -o $@
$(BUILD)/blake3_portable.o: $(B3_DIR)/blake3_portable.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@
$(BUILD)/blake3_wrap.o: $(B3_DIR)/blake3_wrap.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@

# ---- BLAKE3 SIMD builds (per-file ISA flags) ----
$(BUILD)/blake3_sse2.o: $(B3_DIR)/blake3_sse2.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -msse2 -c $< -o $@
$(BUILD)/blake3_sse41.o: $(B3_DIR)/blake3_sse41.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -msse4.1 -c $< -o $@
$(BUILD)/blake3_avx2.o: $(B3_DIR)/blake3_avx2.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -mavx2 -c $< -o $@

# ---- MetroHash (C++) ----
$(BUILD)/metrohash128.o: third_party/metrohash/metrohash128.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@
$(BUILD)/metrohash_wrap.o: third_party/metrohash/metrohash_wrap.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@

# ---- Meow Hash (requires AES-NI + SSE4.1) ----
$(BUILD)/meow_wrap.o: third_party/meow_hash/meow_wrap.c | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -maes -mssse3 -msse4.1 -c $< -o $@

BENCH_OBJS = $(BUILD)/bench_main.o $(BUILD)/bench_hashes.o \
             $(BUILD)/bench_micro.o $(BUILD)/bench_file.o

$(BUILD)/bench_main.o: bench/main.c bench/hashes.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@
$(BUILD)/bench_hashes.o: bench/hashes.c bench/hashes.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@
$(BUILD)/bench_micro.o: bench/micro.c bench/hashes.h bench/timing.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@
$(BUILD)/bench_file.o: bench/file.c bench/hashes.h | $(BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INCLUDES) -c $< -o $@

# Link with $(CXX) so libstdc++ comes in automatically for MetroHash.
# -pthread for the multi-threaded `file --threads N` mode.
$(BUILD)/river5-bench: $(BENCH_OBJS) $(BUILD)/libriver5.a $(EXTRA_OBJS)
	$(CXX) $(BENCH_OBJS) $(EXTRA_OBJS) $(BUILD)/libriver5.a -pthread -o $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean quality
