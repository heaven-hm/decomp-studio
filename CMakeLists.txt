cmake_minimum_required(VERSION 3.26)
project(recomp_studio VERSION 0.2.0 LANGUAGES CXX)

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
)
set(RECOMP_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CAPSTONE_INCLUDE_DIR})
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

add_executable(recomp-studio ${RECOMP_SOURCES})
target_compile_features(recomp-studio PRIVATE cxx_std_20)
target_include_directories(recomp-studio PRIVATE ${RECOMP_INCLUDE_DIRS})
target_link_libraries(recomp-studio PRIVATE ${RECOMP_LIBRARIES})
target_compile_options(recomp-studio PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(recomp-studio PRIVATE
  RECOMP_DEFAULT_RUNTIME_DIR="${CMAKE_CURRENT_SOURCE_DIR}/runtime")

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

set_tests_properties(fixture_recompile_end_to_end PROPERTIES TIMEOUT 1800)
set_tests_properties(negative_inputs PROPERTIES TIMEOUT 900)
