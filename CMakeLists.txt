cmake_minimum_required(VERSION 3.26)
project(recomp_studio VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_executable(recomp-studio
  apps/cli/main.cpp
  core/binary/pe.cpp
  core/codegen/generate.cpp
  core/discovery/analyze.cpp
  core/ir/ir.cpp
  core/common/diagnostic.cpp
  core/common/sha256.cpp
)
target_compile_features(recomp-studio PRIVATE cxx_std_20)
target_include_directories(recomp-studio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(recomp-studio PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_test(NAME cli_version_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/version_test.py
          $<TARGET_FILE:recomp-studio>)
add_test(NAME pe_inspect_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/pe32/inspect_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/build_pe.py)
add_test(NAME pe_analyze_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/instruction-semantics/analyze_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/build_pe.py)
add_test(NAME pe_lift_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/instruction-semantics/lift_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/build_pe.py)
add_test(NAME pe_translate_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/end-to-end/translate_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/build_pe.py)
add_test(NAME pe_verify_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/differential/verify_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/build_pe.py)
add_test(NAME cli_examples_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/examples_test.py
          $<TARGET_FILE:recomp-studio>)
