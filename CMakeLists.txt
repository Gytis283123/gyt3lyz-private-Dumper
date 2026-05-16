cmake_minimum_required(VERSION 3.14)
project(elf_dumper VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_options(/utf-8 /Zc:__cplusplus)
    # /permissive- needs to be set via target_compile_options or escaped
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /permissive-")
endif()

add_executable(elf_dumper
    src/main.cpp
    src/elf_parser.cpp
    src/pe_parser.cpp
    src/search_helper.cpp
)

if(WIN32)
    target_sources(elf_dumper PRIVATE elf_dumper.rc)
endif()

target_include_directories(elf_dumper PRIVATE src)
