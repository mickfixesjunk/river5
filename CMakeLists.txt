cmake_minimum_required(VERSION 3.16)
project(river5 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    add_compile_options(/O2 /W3)
else()
    add_compile_options(-O3 -Wall -Wextra -fno-strict-aliasing)
endif()

# --- libriver5: stable C ABI used by the bench AND by the Rust crate. ---
add_library(river5 STATIC
    csrc/river5.c
    third_party/xxhash/xxhash.c
)
target_include_directories(river5
    PUBLIC  include
    PRIVATE third_party/xxhash
)

# --- bench harness: links against libriver5 and re-includes xxhash inline. ---
add_executable(river5-bench
    bench/main.c
    bench/hashes.c
    bench/micro.c
    bench/file.c
)
target_include_directories(river5-bench PRIVATE
    bench
    include
    third_party/xxhash
)
target_link_libraries(river5-bench PRIVATE river5)

# Suggest a CSV-friendly invocation in the build log.
add_custom_target(bench_help
    COMMAND ${CMAKE_COMMAND} -E echo "Built river5-bench. Try:"
    COMMAND ${CMAKE_COMMAND} -E echo "  ./river5-bench micro"
    COMMAND ${CMAKE_COMMAND} -E echo "  ./river5-bench file /some/path"
    DEPENDS river5-bench
)
