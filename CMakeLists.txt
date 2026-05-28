cmake_minimum_required(VERSION 3.16)

project(
    roe
    VERSION 1.0.0
    DESCRIPTION "A disassembler fit for humans"
    HOMEPAGE_URL "https://github.com/manop55555/roe"
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
    if(NOT Catch2_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.7.1
        )
        FetchContent_MakeAvailable(Catch2)
    endif()
    # Test fixtures compiled from source at build time (never checked in as binaries).
    set(ROE_FIXTURE_BIN_DIR "${CMAKE_CURRENT_BINARY_DIR}/fixtures")
    file(MAKE_DIRECTORY "${ROE_FIXTURE_BIN_DIR}")
    set(ROE_FIXTURE_C_SRC "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/sample.c")
    set(ROE_FIXTURE_CPP_SRC "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/cpp_symbols.cc")
    set(ROE_FIXTURE_ELF "${ROE_FIXTURE_BIN_DIR}/sample.elf64")
    set(ROE_FIXTURE_CPP "${ROE_FIXTURE_BIN_DIR}/sample_cpp.elf64")
    add_custom_command(
        OUTPUT "${ROE_FIXTURE_ELF}"
        COMMAND "${CMAKE_CXX_COMPILER}" -x c -g -O1 -o "${ROE_FIXTURE_ELF}" "${ROE_FIXTURE_C_SRC}"
        DEPENDS "${ROE_FIXTURE_C_SRC}"
        COMMENT "Compiling x86-64 ELF test fixture"
        VERBATIM)
    set(ROE_FIXTURE_ELF_V4 "${ROE_FIXTURE_BIN_DIR}/sample.dwarf4.elf64")
    add_custom_command(
        OUTPUT "${ROE_FIXTURE_ELF_V4}"
        COMMAND "${CMAKE_CXX_COMPILER}" -x c -gdwarf-4 -O1 -o "${ROE_FIXTURE_ELF_V4}" "${ROE_FIXTURE_C_SRC}"
        DEPENDS "${ROE_FIXTURE_C_SRC}"
        COMMENT "Compiling DWARF 4 ELF test fixture"
        VERBATIM)
    set(ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_ELF}" "${ROE_FIXTURE_ELF_V4}")
    set(ROE_FIXTURE_DEFINES
        ROE_FIXTURE_ELF="${ROE_FIXTURE_ELF}"
        ROE_FIXTURE_ELF_V4="${ROE_FIXTURE_ELF_V4}"
        ROE_FIXTURE_SRC="${ROE_FIXTURE_C_SRC}")
    set(ROE_FIXTURE_NODEBUG "${ROE_FIXTURE_BIN_DIR}/sample.nodebug.elf64")
    add_custom_command(
        OUTPUT "${ROE_FIXTURE_NODEBUG}"
        COMMAND "${CMAKE_CXX_COMPILER}" -x c -O2 -g0 -o "${ROE_FIXTURE_NODEBUG}" "${ROE_FIXTURE_C_SRC}"
        DEPENDS "${ROE_FIXTURE_C_SRC}"
        COMMENT "Compiling no-debug ELF test fixture"
        VERBATIM)
    list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_NODEBUG}")
    list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_NODEBUG="${ROE_FIXTURE_NODEBUG}")

    # Diff fixtures (two versions with a changed function).
    set(ROE_FIXTURE_V1 "${ROE_FIXTURE_BIN_DIR}/v1.elf64")
    set(ROE_FIXTURE_V2 "${ROE_FIXTURE_BIN_DIR}/v2.elf64")
    add_custom_command(OUTPUT "${ROE_FIXTURE_V1}"
        COMMAND "${CMAKE_CXX_COMPILER}" -x c -O1 -g -o "${ROE_FIXTURE_V1}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/v1.c"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/v1.c" VERBATIM)
    add_custom_command(OUTPUT "${ROE_FIXTURE_V2}"
        COMMAND "${CMAKE_CXX_COMPILER}" -x c -O1 -g -o "${ROE_FIXTURE_V2}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/v2.c"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/v2.c" VERBATIM)
    list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_V1}" "${ROE_FIXTURE_V2}")
    list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_V1="${ROE_FIXTURE_V1}" ROE_FIXTURE_V2="${ROE_FIXTURE_V2}")

    # Mach-O object fixture (clang cross-target), if clang is available.
    find_program(ROE_CLANG NAMES clang)
    if(ROE_CLANG)
        set(ROE_FIXTURE_MACHO "${ROE_FIXTURE_BIN_DIR}/sample.macho_arm64")
        add_custom_command(OUTPUT "${ROE_FIXTURE_MACHO}"
            COMMAND "${ROE_CLANG}" --target=arm64-apple-macos11 -O1 -c -o "${ROE_FIXTURE_MACHO}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/macho_sample.c"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/macho_sample.c" VERBATIM)
        set(ROE_FIXTURE_MACHO_X64 "${ROE_FIXTURE_BIN_DIR}/sample.macho_x86_64")
        add_custom_command(OUTPUT "${ROE_FIXTURE_MACHO_X64}"
            COMMAND "${ROE_CLANG}" --target=x86_64-apple-macos11 -O1 -c -o "${ROE_FIXTURE_MACHO_X64}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/macho_sample.c"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/macho_sample.c" VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_MACHO}" "${ROE_FIXTURE_MACHO_X64}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_MACHO="${ROE_FIXTURE_MACHO}"
            ROE_FIXTURE_MACHO_X64="${ROE_FIXTURE_MACHO_X64}")
    else()
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_MACHO="" ROE_FIXTURE_MACHO_X64="")
    endif()

    # PE fixtures (mingw), if available.
    find_program(ROE_MINGW NAMES x86_64-w64-mingw32-gcc)
    if(ROE_MINGW)
        set(ROE_FIXTURE_PE "${ROE_FIXTURE_BIN_DIR}/sample.pe_x64")
        set(ROE_FIXTURE_PE_DLL "${ROE_FIXTURE_BIN_DIR}/sample.pe_dll")
        add_custom_command(OUTPUT "${ROE_FIXTURE_PE}"
            COMMAND "${ROE_MINGW}" -O1 -o "${ROE_FIXTURE_PE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/with_strings.c"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/with_strings.c" VERBATIM)
        add_custom_command(OUTPUT "${ROE_FIXTURE_PE_DLL}"
            COMMAND "${ROE_MINGW}" -O1 -shared -o "${ROE_FIXTURE_PE_DLL}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/pe_dll.c"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/pe_dll.c" VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_PE}" "${ROE_FIXTURE_PE_DLL}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_PE="${ROE_FIXTURE_PE}" ROE_FIXTURE_PE_DLL="${ROE_FIXTURE_PE_DLL}")
    else()
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_PE="" ROE_FIXTURE_PE_DLL="")
    endif()
    if(EXISTS "${ROE_FIXTURE_CPP_SRC}")
        add_custom_command(
            OUTPUT "${ROE_FIXTURE_CPP}"
            COMMAND "${CMAKE_CXX_COMPILER}" -g -O0 -o "${ROE_FIXTURE_CPP}" "${ROE_FIXTURE_CPP_SRC}"
            DEPENDS "${ROE_FIXTURE_CPP_SRC}"
            COMMENT "Compiling C++ ELF test fixture"
            VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_CPP}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_CPP="${ROE_FIXTURE_CPP}")
    endif()
    find_program(ROE_AARCH64_CC NAMES aarch64-linux-gnu-gcc)
    if(ROE_AARCH64_CC)
        set(ROE_FIXTURE_AARCH64 "${ROE_FIXTURE_BIN_DIR}/sample.aarch64")
        add_custom_command(
            OUTPUT "${ROE_FIXTURE_AARCH64}"
            COMMAND "${ROE_AARCH64_CC}" -x c -g -O1 -static -o "${ROE_FIXTURE_AARCH64}" "${ROE_FIXTURE_C_SRC}"
            DEPENDS "${ROE_FIXTURE_C_SRC}"
            COMMENT "Compiling aarch64 ELF test fixture"
            VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_AARCH64}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_AARCH64="${ROE_FIXTURE_AARCH64}")
    else()
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_AARCH64="")
    endif()

    # x86-32 ELF object fixture: native compiler with -m32, only when the 32-bit
    # headers (gcc-multilib) are present. Probe with the real source and flags.
    execute_process(
        COMMAND "${CMAKE_CXX_COMPILER}" -m32 -x c -c -o /dev/null "${ROE_FIXTURE_C_SRC}"
        RESULT_VARIABLE ROE_M32_RESULT
        OUTPUT_QUIET ERROR_QUIET)
    if(ROE_M32_RESULT EQUAL 0)
        set(ROE_FIXTURE_X86_32 "${ROE_FIXTURE_BIN_DIR}/sample.x86_32.o")
        add_custom_command(OUTPUT "${ROE_FIXTURE_X86_32}"
            COMMAND "${CMAKE_CXX_COMPILER}" -m32 -x c -g -O1 -c -o "${ROE_FIXTURE_X86_32}" "${ROE_FIXTURE_C_SRC}"
            DEPENDS "${ROE_FIXTURE_C_SRC}" VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_X86_32}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_X86_32="${ROE_FIXTURE_X86_32}")
    else()
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_X86_32="")
    endif()

    # MIPS / MIPSel ELF object fixtures (cross-gcc), if the toolchains are present.
    find_program(ROE_MIPS_CC NAMES mips-linux-gnu-gcc)
    if(ROE_MIPS_CC)
        set(ROE_FIXTURE_MIPS "${ROE_FIXTURE_BIN_DIR}/sample.mips.o")
        add_custom_command(OUTPUT "${ROE_FIXTURE_MIPS}"
            COMMAND "${ROE_MIPS_CC}" -x c -g -O1 -c -o "${ROE_FIXTURE_MIPS}" "${ROE_FIXTURE_C_SRC}"
            DEPENDS "${ROE_FIXTURE_C_SRC}" VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_MIPS}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_MIPS="${ROE_FIXTURE_MIPS}")
    else()
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_MIPS="")
    endif()
    find_program(ROE_MIPSEL_CC NAMES mipsel-linux-gnu-gcc)
    if(ROE_MIPSEL_CC)
        set(ROE_FIXTURE_MIPSEL "${ROE_FIXTURE_BIN_DIR}/sample.mipsel.o")
        add_custom_command(OUTPUT "${ROE_FIXTURE_MIPSEL}"
            COMMAND "${ROE_MIPSEL_CC}" -x c -g -O1 -c -o "${ROE_FIXTURE_MIPSEL}" "${ROE_FIXTURE_C_SRC}"
            DEPENDS "${ROE_FIXTURE_C_SRC}" VERBATIM)
        list(APPEND ROE_FIXTURE_OUTPUTS "${ROE_FIXTURE_MIPSEL}")
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_MIPSEL="${ROE_FIXTURE_MIPSEL}")
    else()
        list(APPEND ROE_FIXTURE_DEFINES ROE_FIXTURE_MIPSEL="")
    endif()

    add_custom_target(roe_fixtures ALL DEPENDS ${ROE_FIXTURE_OUTPUTS})

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
        add_dependencies("${test_name}" roe_fixtures)
        target_compile_definitions("${test_name}" PRIVATE ${ROE_FIXTURE_DEFINES})
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
