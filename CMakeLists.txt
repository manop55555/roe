cmake_minimum_required(VERSION 3.16)

project(
    roe
    VERSION 1.0.0
    DESCRIPTION "A disassembler fit for humans"
    HOMEPAGE_URL "https://github.com/USER/roe"
    LANGUAGES CXX
)

option(ROE_BUILD_TESTS "Build roe tests" ON)
option(ROE_BUILD_FUZZERS "Build roe fuzz targets" OFF)
option(ROE_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(ROE_PROJECT_LICENSE "Apache-2.0")

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
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Release>:-DNDEBUG>
)

if(ROE_SANITIZERS)
    target_compile_options(roe_options INTERFACE -fsanitize=address,undefined)
    target_link_options(roe_options INTERFACE -fsanitize=address,undefined)
endif()

find_package(Git QUIET)
if(Git_FOUND)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE ROE_BUILD_COMMIT_VALUE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()
if(NOT ROE_BUILD_COMMIT_VALUE)
    set(ROE_BUILD_COMMIT_VALUE "unknown")
endif()
string(TIMESTAMP ROE_BUILD_DATE_VALUE "%Y-%m-%d" UTC)

target_compile_definitions(
    roe_options
    INTERFACE
        ROE_BUILD_COMMIT="${ROE_BUILD_COMMIT_VALUE}"
        ROE_BUILD_DATE="${ROE_BUILD_DATE_VALUE}"
)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(CAPSTONE QUIET capstone)
endif()

if(CAPSTONE_FOUND AND CAPSTONE_VERSION)
    target_compile_definitions(roe_options INTERFACE ROE_CAPSTONE_VERSION="${CAPSTONE_VERSION}")
else()
    target_compile_definitions(roe_options INTERFACE ROE_CAPSTONE_VERSION="unknown")
endif()

file(
    GLOB_RECURSE
    ROE_LIBRARY_SOURCES
    CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/binary/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/elf/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/macho/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/pe/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/archive/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/disasm/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/disasm/arch/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/resolver/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/format/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/debug/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/features/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/watcher/*.cpp"
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
    install(TARGETS roe RUNTIME DESTINATION bin)
else()
    add_custom_target(
        roe
        COMMAND ${CMAKE_COMMAND} -E echo "roe executable placeholder: add src/main.cpp to build the CLI"
    )
endif()

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION include)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/docs/roe.1")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/docs/roe.1" DESTINATION share/man/man1)
endif()

foreach(legal_file LICENSE NOTICE)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${legal_file}")
        install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/${legal_file}" DESTINATION share/doc/roe)
    endif()
endforeach()

if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/completions")
    install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/completions/" DESTINATION share/roe/completions)
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
