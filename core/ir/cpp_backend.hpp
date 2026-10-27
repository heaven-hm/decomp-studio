#pragma once

// The C++ backend: turns the architecture-neutral representation into the C++
// the project has always generated.
//
// This is the only place in the compiler that decides what C++ text a statement
// becomes. The lifter decides *what happens*; this decides *how it is written*.
// While the migration is in progress every statement still arrives as Verbatim,
// which this backend emits unchanged, so the generated code is byte-identical to
// what the lifter produced when it wrote C++ itself.

#include "core/ir/ir.hpp"

#include <string>

namespace recomp::ir {

struct CppBackendOptions {
  std::string indent{"  "};
};

std::string render_function(const Function& function, const CppBackendOptions& options = {});
std::string render_module(const Module& module, const CppBackendOptions& options = {});

}  // namespace recomp::ir
