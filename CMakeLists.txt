cmake_minimum_required(VERSION 3.26)
project(recomp_studio VERSION 0.4.0 LANGUAGES CXX)

include(CTest)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

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

set_tests_properties(fixture_recompile_end_to_end PROPERTIES TIMEOUT 1800)
set_tests_properties(negative_inputs PROPERTIES TIMEOUT 900)
set_tests_properties(coverage_census PROPERTIES TIMEOUT 900)
set_tests_properties(import_compatibility PROPERTIES TIMEOUT 900)
set_tests_properties(autorecomp_pipeline PROPERTIES TIMEOUT 1800)
set_tests_properties(vex_encoding_values PROPERTIES TIMEOUT 900)
set_tests_properties(guest_heap PROPERTIES TIMEOUT 900)
set_tests_properties(real_application_corpus PROPERTIES TIMEOUT 5400)
