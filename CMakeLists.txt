cmake_minimum_required(VERSION 3.26)
project(recomp_studio VERSION 0.2.0 LANGUAGES CXX)

include(CTest)
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Capstone provides the x86-64 decoder used by function discovery.
find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h
  HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(CAPSTONE_LIBRARY NAMES capstone
  HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
find_path(UNICORN_INCLUDE_DIR unicorn/unicorn.h
  HINTS /opt/homebrew/include /usr/local/include /usr/include)
find_library(UNICORN_LIBRARY NAMES unicorn
  HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
if(NOT CAPSTONE_INCLUDE_DIR OR NOT CAPSTONE_LIBRARY)
  message(FATAL_ERROR "Capstone not found. Install it (brew install capstone) or set CAPSTONE_INCLUDE_DIR/CAPSTONE_LIBRARY.")
endif()
if(NOT UNICORN_INCLUDE_DIR OR NOT UNICORN_LIBRARY)
  message(FATAL_ERROR "Unicorn not found. Install it (brew install unicorn) or set UNICORN_INCLUDE_DIR/UNICORN_LIBRARY.")
endif()

add_executable(recomp-studio
  apps/cli/main.cpp
  core/binary/pe.cpp
  core/codegen/project_generator.cpp
  core/common/configuration.cpp
  core/common/diagnostic.cpp
  core/common/sha256.cpp
  core/discovery/function_discovery.cpp
  core/harness/repair_harness.cpp
  core/pipeline.cpp
  core/semantics/x86_64_lifter.cpp
  core/verification/differential_harness.cpp
)
target_compile_features(recomp-studio PRIVATE cxx_std_20)
target_include_directories(recomp-studio PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CAPSTONE_INCLUDE_DIR} ${UNICORN_INCLUDE_DIR})
target_link_libraries(recomp-studio PRIVATE ${CAPSTONE_LIBRARY} ${UNICORN_LIBRARY})
target_compile_options(recomp-studio PRIVATE -Wall -Wextra -Wpedantic -Werror)
target_compile_definitions(recomp-studio PRIVATE
  RECOMP_DEFAULT_RUNTIME_DIR="${CMAKE_CURRENT_SOURCE_DIR}/runtime")

add_test(NAME cli_version_contract
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli/version_test.py
          $<TARGET_FILE:recomp-studio>)
add_test(NAME fixture_recompile_end_to_end
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/end-to-end/recompile_test.py
          $<TARGET_FILE:recomp-studio>
          ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/apps
          ${CMAKE_CURRENT_SOURCE_DIR}/runtime)
