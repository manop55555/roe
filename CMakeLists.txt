cmake_minimum_required(VERSION 3.16)

project(
    roe
    VERSION 0.1.0
    DESCRIPTION "A disassembler fit for humans"
    LANGUAGES CXX
)

option(ROE_BUILD_TESTS "Build roe tests" ON)
option(ROE_BUILD_FUZZERS "Build roe fuzz targets" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(roe_options INTERFACE)
target_compile_features(roe_options INTERFACE cxx_std_17)
target_include_directories(
    roe_options
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_compile_options(
    roe_options
    INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Werror
        -Wconversion
        -Wshadow
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Release>:-DNDEBUG>
)
target_link_options(
    roe_options
    INTERFACE
        $<$<CONFIG:Debug>:-fsanitize=address,undefined>
)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CAPSTONE QUIET capstone)
endif()

file(
    GLOB_RECURSE
    ROE_LIBRARY_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/elf/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/disasm/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/resolver/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/format/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/*.cpp"
)

if(ROE_LIBRARY_SOURCES)
    add_library(roe_core STATIC ${ROE_LIBRARY_SOURCES})
    target_link_libraries(roe_core PUBLIC roe_options)
else()
    add_library(roe_core INTERFACE)
    target_link_libraries(roe_core INTERFACE roe_options)
endif()

if(CAPSTONE_FOUND)
    if(ROE_LIBRARY_SOURCES)
        target_include_directories(roe_core SYSTEM PUBLIC ${CAPSTONE_INCLUDE_DIRS})
        target_link_libraries(roe_core PUBLIC ${CAPSTONE_LIBRARIES})
        target_compile_options(roe_core PUBLIC ${CAPSTONE_CFLAGS_OTHER})
    else()
        target_include_directories(roe_core SYSTEM INTERFACE ${CAPSTONE_INCLUDE_DIRS})
        target_link_libraries(roe_core INTERFACE ${CAPSTONE_LIBRARIES})
        target_compile_options(roe_core INTERFACE ${CAPSTONE_CFLAGS_OTHER})
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
    add_executable(roe "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
    target_link_libraries(roe PRIVATE roe_core)
else()
    add_custom_target(
        roe
        COMMAND ${CMAKE_COMMAND} -E echo "roe executable placeholder: add src/main.cpp to build the CLI"
    )
endif()

include(CTest)
if(ROE_BUILD_TESTS)
    enable_testing()
    find_package(Catch2 3 QUIET)
    file(
        GLOB_RECURSE
        ROE_TEST_SOURCES
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp"
    )
    foreach(test_source IN LISTS ROE_TEST_SOURCES)
        get_filename_component(test_name "${test_source}" NAME_WE)
        add_executable("${test_name}" "${test_source}")
        target_link_libraries("${test_name}" PRIVATE roe_core)
        if(TARGET Catch2::Catch2WithMain)
            target_link_libraries("${test_name}" PRIVATE Catch2::Catch2WithMain)
        endif()
        add_test(NAME "${test_name}" COMMAND "${test_name}")
    endforeach()
endif()

if(ROE_BUILD_FUZZERS)
    file(
        GLOB_RECURSE
        ROE_FUZZ_SOURCES
        CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/fuzz/*.cpp"
    )
    foreach(fuzz_source IN LISTS ROE_FUZZ_SOURCES)
        get_filename_component(fuzz_name "${fuzz_source}" NAME_WE)
        add_executable("${fuzz_name}" "${fuzz_source}")
        target_link_libraries("${fuzz_name}" PRIVATE roe_core)
        target_compile_options("${fuzz_name}" PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options("${fuzz_name}" PRIVATE -fsanitize=fuzzer,address,undefined)
    endforeach()
endif()
