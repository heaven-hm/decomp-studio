cmake_minimum_required(VERSION 3.26)
project(recomp_studio VERSION 0.4.0 LANGUAGES CXX)

include(CTest)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Build the actual upstream Win32 provider tests when a pinned checkout is supplied.
# This does not yet connect the provider to generated Recomp Studio guests.
set(RECOMP_PCRECOMP_SOURCE "" CACHE PATH "PCRecomp checkout for upstream Win32 HLE tests")
if(RECOMP_PCRECOMP_SOURCE)
  enable_language(C)
  find_package(Git REQUIRED)
  execute_process(COMMAND ${GIT_EXECUTABLE} -C ${RECOMP_PCRECOMP_SOURCE} rev-parse HEAD
    OUTPUT_VARIABLE PCRECOMP_REVISION OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE PCRECOMP_GIT_RESULT)
  if(NOT PCRECOMP_GIT_RESULT EQUAL 0 OR NOT PCRECOMP_REVISION STREQUAL "a85ea970f9e0640ab6546d2ca7a01fccb132973d")
    message(FATAL_ERROR "PCRecomp checkout must be at a85ea970f9e0640ab6546d2ca7a01fccb132973d")
  endif()
  execute_process(COMMAND ${GIT_EXECUTABLE} -C ${RECOMP_PCRECOMP_SOURCE} status --porcelain --untracked-files=all -- tools runtime/win32hle runtime/recomp32
    OUTPUT_VARIABLE PCRECOMP_DIRTY OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE PCRECOMP_STATUS_RESULT)
  if(NOT PCRECOMP_STATUS_RESULT EQUAL 0 OR PCRECOMP_DIRTY)
    message(FATAL_ERROR "PCRecomp tools and runtime sources must be clean for a reproducible provider build")
  endif()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(PCRECOMP_SDL REQUIRED IMPORTED_TARGET sdl2 SDL2_ttf)
  find_package(Threads REQUIRED)
  set(PCRECOMP_HLE_DIR "${RECOMP_PCRECOMP_SOURCE}/runtime/win32hle")
  file(GLOB PCRECOMP_HLE_SOURCES CONFIGURE_DEPENDS "${PCRECOMP_HLE_DIR}/*.c")
  list(FILTER PCRECOMP_HLE_SOURCES EXCLUDE REGEX "_selftest\\.c$")
  foreach(test_name IN ITEMS win32hle gdi)
    add_executable(pcrecomp_${test_name}_selftest ${PCRECOMP_HLE_SOURCES}
      "${PCRECOMP_HLE_DIR}/${test_name}_selftest.c")
    target_include_directories(pcrecomp_${test_name}_selftest PRIVATE
      "${PCRECOMP_HLE_DIR}" "${RECOMP_PCRECOMP_SOURCE}/runtime/recomp32")
    target_link_libraries(pcrecomp_${test_name}_selftest PRIVATE PkgConfig::PCRECOMP_SDL Threads::Threads m)
    add_test(NAME pcrecomp_${test_name} COMMAND pcrecomp_${test_name}_selftest)
    set_tests_properties(pcrecomp_${test_name} PROPERTIES
      ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  endforeach()
  add_library(pcrecomp_stateless_crt_provider STATIC ${PCRECOMP_HLE_SOURCES}
    runtime/recomp_runtime.cpp runtime/pcrecomp_stateless_crt.cpp)
  target_compile_features(pcrecomp_stateless_crt_provider PRIVATE cxx_std_20)
  target_include_directories(pcrecomp_stateless_crt_provider PRIVATE runtime "${PCRECOMP_HLE_DIR}"
    "${RECOMP_PCRECOMP_SOURCE}/runtime/recomp32")
  target_link_libraries(pcrecomp_stateless_crt_provider PUBLIC PkgConfig::PCRECOMP_SDL Threads::Threads m)
  add_executable(pcrecomp_stateless_crt_test tests/compat/pcrecomp_stateless_crt_test.cpp)
  target_compile_features(pcrecomp_stateless_crt_test PRIVATE cxx_std_20)
  target_include_directories(pcrecomp_stateless_crt_test PRIVATE "${PCRECOMP_HLE_DIR}"
    "${RECOMP_PCRECOMP_SOURCE}/runtime/recomp32")
  target_link_libraries(pcrecomp_stateless_crt_test PRIVATE pcrecomp_stateless_crt_provider)
  add_test(NAME pcrecomp_stateless_crt COMMAND pcrecomp_stateless_crt_test)
  set_tests_properties(pcrecomp_stateless_crt PROPERTIES ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy")
  find_program(PCRECOMP_MINGW_CC i686-w64-mingw32-gcc)
  if(PCRECOMP_MINGW_CC)
    add_test(NAME pcrecomp_pe32_fixture COMMAND ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/end-to-end/pcrecomp_fixture_test.py
      ${RECOMP_PCRECOMP_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps/arith.c
      ${PCRECOMP_MINGW_CC} ${CMAKE_C_COMPILER} ${PKG_CONFIG_EXECUTABLE} ${CMAKE_OSX_SYSROOT})
    set_tests_properties(pcrecomp_pe32_fixture PROPERTIES
      ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy" TIMEOUT 120)
  endif()
endif()

# Unicorn (GPL-2.0) powers the differential verification backend. It is optional
# so the core recompiler and CLI can be built without it.
option(RECOMP_ENABLE_UNICORN "Build the Unicorn-based verification backend (GPL-2.0)" ON)

# Capstone (BSD-3-Clause) provides the x86-64 decoder used by function discovery.
find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h
  HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(CAPSTONE_LIBRARY NAMES capstone
  HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
if(NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
  message(FATAL_ERROR "Capstone not found. Install it (brew install capstone) or set CAPSTONE_INCLUDE_DIR/CAPSTONE_LIBRARY.")
endif()

set(RECOMP_SOURCES
  apps/cli/main.cpp
  core/binary/pe.cpp
  core/codegen/project_generator.cpp
  core/common/configuration.cpp
  core/common/diagnostic.cpp
  core/common/sha256.cpp
  core/discovery/function_discovery.cpp
  core/pipeline.cpp
  core/semantics/x86_64_lifter.cpp
  core/cli/capabilities.cpp
  core/cli/options.cpp
  core/detection/detection.cpp
  core/ir/ir.cpp
  core/ir/cpp_backend.cpp
  # The guest runtime is linked into the studio as well as into every generated
  # project. The differential reference dispatches through the same shim table,
  # so there is exactly one implementation of each Win32 call rather than two
  # that can drift apart.
  runtime/recomp_runtime.cpp
)
set(RECOMP_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/runtime ${CAPSTONE_INCLUDE_DIR})
set(RECOMP_LIBRARIES ${CAPSTONE_LIBRARY})

if(RECOMP_ENABLE_UNICORN)
  find_path(UNICORN_INCLUDE_DIR unicorn/unicorn.h
    HINTS /opt/homebrew/include /usr/local/include /usr/include)
  find_library(UNICORN_LIBRARY NAMES unicorn
    HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
  if(UNICORN_INCLUDE_DIR AND UNICORN_LIBRARY)
    list(APPEND RECOMP_SOURCES
      core/harness/repair_harness.cpp
      core/verification/differential_harness.cpp)
    list(APPEND RECOMP_INCLUDE_DIRS ${UNICORN_INCLUDE_DIR})
    list(APPEND RECOMP_LIBRARIES ${UNICORN_LIBRARY})
    add_compile_definitions(RECOMP_HAS_UNICORN=1)
  else()
    message(WARNING "Unicorn not found; building without the verification backend (brew install unicorn).")
  endif()
endif()

# The guest runtime is compiled with warnings disabled in every generated project,
# because it is copied into them verbatim and is not studio code. Compiling it with
# the studio's -Werror would fail on source that ships perfectly well, so the same
# flags are used in both places.
set_source_files_properties(runtime/recomp_runtime.cpp PROPERTIES COMPILE_OPTIONS "-w")

add_executable(recomp-studio ${RECOMP_SOURCES})
if(RECOMP_PCRECOMP_SOURCE AND PCRECOMP_MINGW_CC AND RECOMP_ENABLE_UNICORN AND UNICORN_INCLUDE_DIR AND UNICORN_LIBRARY)
  add_test(NAME pcrecomp_crt_bridge_pe32 COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/end-to-end/pcrecomp_crt_bridge_test.py
    ${RECOMP_PCRECOMP_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps/pcrecomp_crt_bridge.c
    ${PCRECOMP_MINGW_CC} ${CMAKE_C_COMPILER} ${CMAKE_CXX_COMPILER} ${PKG_CONFIG_EXECUTABLE}
    $<TARGET_FILE:pcrecomp_stateless_crt_provider> $<TARGET_FILE:recomp-studio> ${CMAKE_OSX_SYSROOT})
  set_tests_properties(pcrecomp_crt_bridge_pe32 PROPERTIES
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy" TIMEOUT 120)
  add_test(NAME pcrecomp_pe32_unicorn_reference COMMAND ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/end-to-end/pcrecomp_fixture_test.py
    ${RECOMP_PCRECOMP_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps/arith.c
    ${PCRECOMP_MINGW_CC} ${CMAKE_C_COMPILER} ${PKG_CONFIG_EXECUTABLE} ${CMAKE_OSX_SYSROOT}
    --reference-cli $<TARGET_FILE:recomp-studio>)
  set_tests_properties(pcrecomp_pe32_unicorn_reference PROPERTIES
    ENVIRONMENT "SDL_VIDEODRIVER=dummy;SDL_AUDIODRIVER=dummy" TIMEOUT 120)
endif()
add_executable(ghidra-import apps/cli/ghidra_import.cpp core/common/sha256.cpp)
add_executable(ghidra-run apps/cli/ghidra_run.cpp core/common/sha256.cpp)
add_executable(revng-run apps/cli/revng_run.cpp core/common/sha256.cpp)
target_compile_features(revng-run PRIVATE cxx_std_20)
target_include_directories(revng-run PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME revng_run COMMAND ${Python3_EXECUTABLE}
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/revng_run_test.py $<TARGET_FILE:revng-run>)
target_compile_features(ghidra-run PRIVATE cxx_std_20)
target_include_directories(ghidra-run PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME ghidra_run COMMAND ${Python3_EXECUTABLE}
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/ghidra_run_test.py $<TARGET_FILE:ghidra-run> ${RECOMP_PCRECOMP_SOURCE})
target_compile_features(ghidra-import PRIVATE cxx_std_20)
target_include_directories(ghidra-import PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME ghidra_import COMMAND ${Python3_EXECUTABLE}
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/ghidra_import_test.py $<TARGET_FILE:ghidra-import>)
# The reconciler needs the project's own discovery, so it links the same sources the studio
# does rather than reimplementing any of them.
add_executable(ghidra-reconcile apps/cli/ghidra_reconcile.cpp core/binary/pe.cpp
  core/discovery/function_discovery.cpp)
target_compile_features(ghidra-reconcile PRIVATE cxx_std_20)
target_include_directories(ghidra-reconcile PRIVATE ${RECOMP_INCLUDE_DIRS})
target_link_libraries(ghidra-reconcile PRIVATE ${RECOMP_LIBRARIES})
add_test(NAME ghidra_reconcile COMMAND ${Python3_EXECUTABLE}
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/ghidra_reconcile_test.py $<TARGET_FILE:ghidra-reconcile>
  ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps/arith.c)
target_compile_features(recomp-studio PRIVATE cxx_std_20)
target_include_directories(recomp-studio PRIVATE ${RECOMP_INCLUDE_DIRS})
target_link_libraries(recomp-studio PRIVATE ${RECOMP_LIBRARIES})
target_compile_options(recomp-studio PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(recomp-studio PRIVATE
  RECOMP_DEFAULT_RUNTIME_DIR="${CMAKE_CURRENT_SOURCE_DIR}/runtime")

add_executable(runtime_command_line_test tests/compat/runtime_command_line_test.cpp runtime/recomp_runtime.cpp)
target_compile_features(runtime_command_line_test PRIVATE cxx_std_20)
target_include_directories(runtime_command_line_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
add_test(NAME runtime_command_line COMMAND runtime_command_line_test)
add_executable(runtime_time_test tests/compat/runtime_time_test.cpp runtime/recomp_runtime.cpp)
target_compile_features(runtime_time_test PRIVATE cxx_std_20)
target_include_directories(runtime_time_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
add_test(NAME runtime_time COMMAND runtime_time_test)

# A hand-written numeric conversion needs a test that names the VALUES, not one that
# checks it runs. Every expectation below is the IEEE-754 encoding of that number.
add_executable(half_precision_test tests/compat/half_precision_test.cpp)
target_compile_features(half_precision_test PRIVATE cxx_std_20)
target_include_directories(half_precision_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
add_test(NAME half_precision COMMAND half_precision_test)

# Coverage is not detection. This injects a one-byte heap difference that does NOT change
# stdout and asserts the comparison catches it.
add_test(NAME heap_corruption
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/verification/heap_corruption_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps
          ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties(heap_corruption PROPERTIES TIMEOUT 900 SKIP_RETURN_CODE 77)

add_executable(runtime_crt_test tests/compat/runtime_crt_test.cpp runtime/recomp_runtime.cpp)
target_compile_features(runtime_crt_test PRIVATE cxx_std_20)
target_include_directories(runtime_crt_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
add_test(NAME runtime_crt COMMAND runtime_crt_test)

add_executable(diagnostic_test tests/compat/diagnostic_test.cpp core/common/diagnostic.cpp)
target_compile_features(diagnostic_test PRIVATE cxx_std_20)
target_include_directories(diagnostic_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME diagnostic_json COMMAND diagnostic_test)

# The app-directory policy, checked without a guest in the way. Every file-facing
# shim resolves through it, so the escape that matters is the quiet one: a path
# above the app directory that is served anyway.
add_executable(guest_file_system_test tests/compat/guest_file_system_test.cpp)
target_compile_features(guest_file_system_test PRIVATE cxx_std_20)
target_include_directories(guest_file_system_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
add_test(NAME guest_file_system COMMAND guest_file_system_test)

# File APIs cross the same shared shim boundary as real guest imports. Keep the
# CRT stream and kernel32 handle paths covered for both PE32 and PE32+ guests.
add_executable(runtime_file_streams_test tests/compat/runtime_file_streams_test.cpp runtime/recomp_runtime.cpp)
target_compile_features(runtime_file_streams_test PRIVATE cxx_std_20)
target_include_directories(runtime_file_streams_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
add_test(NAME runtime_file_streams COMMAND runtime_file_streams_test)

add_test(NAME preflight_prerequisites
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/preflight/prerequisites_test.py
          $<TARGET_FILE:recomp-studio>)

add_test(NAME cli_version_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/version_test.py
          $<TARGET_FILE:recomp-studio>)

add_test(NAME fixture_reproducibility
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/reproducibility/fixtures_test.py
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME fixture_recompile_end_to_end
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/end-to-end/recompile_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME negative_inputs
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/negative/negative_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME coverage_census
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/coverage/coverage_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME import_compatibility
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/compat/imports_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps
          ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME autorecomp_pipeline
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/autorecomp/autorecomp_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME cli_options
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/options_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME stdin_path_handling
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/stdin_path_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME input_detection
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/detection/detection_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME guest_state_checkpoints
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/verification/guest_state_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME atexit_handlers
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/verification/atexit_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME golden_generated_code
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/golden/golden_code_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/golden/generated_code.sha256)

add_test(NAME cxx_runtime
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cxx/cxx_runtime_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME guest_heap
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/heap/heap_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

add_test(NAME vex_encoding_values
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/vex/vex_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps)

# The corpus lives outside the repository and is not redistributable, so the
# directory comes from RECOMP_APPS_DIR; the test prints SKIP when it is unset.
add_test(NAME real_application_corpus
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/apps/real_apps_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/apps/baseline.json)

# A test that exits 0 when its corpus is absent is green without ever running. 77 is
# ctest's convention for "not run", so this reports SKIPPED rather than PASSED and the
# absence is visible in the summary instead of hidden behind a pass.
set_tests_properties(real_application_corpus PROPERTIES SKIP_RETURN_CODE 77)

set_tests_properties(fixture_recompile_end_to_end PROPERTIES TIMEOUT 1800)
set_tests_properties(negative_inputs PROPERTIES TIMEOUT 900)
set_tests_properties(coverage_census PROPERTIES TIMEOUT 900)
set_tests_properties(import_compatibility PROPERTIES TIMEOUT 900)
set_tests_properties(autorecomp_pipeline PROPERTIES TIMEOUT 1800)
set_tests_properties(vex_encoding_values PROPERTIES TIMEOUT 900)
set_tests_properties(guest_heap PROPERTIES TIMEOUT 900)
set_tests_properties(real_application_corpus PROPERTIES TIMEOUT 5400)

add_test(NAME real_application_required_policy
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/apps/required_corpus_policy_test.py)
