#pragma once

// The architecture-neutral semantic representation.
//
// The lifter used to write C++ text directly, which meant the only description of
// what a guest instruction *does* was a line of C++ and the only way to consume it
// was to compile that line. Nothing else could read it: not a second backend, not
// an LLVM IR emitter, not an analysis pass, and not a checker that compares two
// translations.
//
// This is the boundary. A statement describes an effect on the guest machine --
// assign a value, store to memory, call something, branch, trap -- and names no
// architecture, no register index and no source language. A backend turns
// statements into whatever the target needs.
//
// Migration is deliberately incremental and byte-verified. `Verbatim` carries text
// that has not been given a structured form yet, and the C++ backend emits it
// unchanged, so a statement that has not been migrated cannot alter the output.
// The golden test in tests/golden pins that: the generated C++ must stay
// byte-identical while the lifter is moved onto this representation.

#include <cstdint>
#include <string>
#include <vector>

namespace recomp::ir {

// What a statement does to the guest machine.
enum class StatementKind {
  Comment,       // provenance: the guest instruction this came from
  Assign,        // destination = expression
  StoreMemory,   // memory[address] = expression, width bytes wide
  CallGuest,     // invoke a recovered guest function at a known address
  CallImport,    // invoke a Win32 import
  CallIndirect,  // invoke through a computed address
  JumpIf,        // conditional branch to a label
  Jump,          // unconditional branch to a label
  Label,         // a branch target
  Return,        // return from the guest function
  Trap,          // the guest reached something that cannot be executed
  Verbatim,      // not yet migrated: emitted unchanged by the backend
};

const char* statement_kind_name(StatementKind kind);

struct Statement {
  StatementKind kind{StatementKind::Verbatim};

  std::string destination;  // Assign: what is written
  std::string expression;   // Assign, StoreMemory, JumpIf: the value or condition
  std::string address;      // StoreMemory: where
  int width{};              // StoreMemory: bytes
  std::string symbol;       // CallGuest, CallImport: the callee
  std::string library;      // CallImport: the library
  std::string label;        // Jump, JumpIf, Label
  std::string text;         // Comment, Verbatim
  std::uint64_t address_of_instruction{};  // provenance for every statement

  static Statement verbatim(std::string line, std::uint64_t instruction_address) {
    Statement statement;
    statement.kind = StatementKind::Verbatim;
    statement.text = std::move(line);
    statement.address_of_instruction = instruction_address;
    return statement;
  }
  static Statement comment(std::string line, std::uint64_t instruction_address) {
    Statement statement;
    statement.kind = StatementKind::Comment;
    statement.text = std::move(line);
    statement.address_of_instruction = instruction_address;
    return statement;
  }
};

// A recovered guest function, in statement form.
struct Function {
  std::uint64_t address{};
  std::string name;
  std::vector<Statement> statements;
};

// Everything recovered from one image.
struct Module {
  std::vector<Function> functions;
};

// Counts statements by kind, so a migration can be reported as a fraction rather
// than as an impression.
struct StatementCensus {
  std::uint64_t total{};
  std::uint64_t verbatim{};
  std::uint64_t structured{};
  double structured_percent() const {
    return total == 0 ? 100.0 : 100.0 * static_cast<double>(structured) / static_cast<double>(total);
  }
};

StatementCensus census(const Module& module);

}  // namespace recomp::ir
