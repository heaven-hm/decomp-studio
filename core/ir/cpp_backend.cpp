#include "core/ir/cpp_backend.hpp"

namespace recomp::ir {
namespace {

void render_statement(const Statement& statement, const CppBackendOptions& options, std::string& output) {
  switch (statement.kind) {
    case StatementKind::Comment:
      output += options.indent + "// " + statement.text + "\n";
      return;
    case StatementKind::Assign:
      output += options.indent + statement.destination + " = " + statement.expression + ";\n";
      return;
    case StatementKind::StoreMemory:
      output += options.indent + "store_guest_memory(context, " + statement.address + ", " +
                statement.expression + ", " + std::to_string(statement.width) + ");\n";
      return;
    case StatementKind::CallGuest:
      output += options.indent + statement.symbol + "(context);\n";
      return;
    case StatementKind::CallImport:
      output += options.indent + "invoke_win32_import(context, \"" + statement.library + "\", \"" +
                statement.symbol + "\");\n";
      return;
    case StatementKind::CallIndirect:
      output += options.indent + "invoke_guest_indirect(context, " + statement.expression + ");\n";
      return;
    case StatementKind::JumpIf:
      output += options.indent + "if (" + statement.expression + ") goto " + statement.label + ";\n";
      return;
    case StatementKind::Jump:
      output += options.indent + "goto " + statement.label + ";\n";
      return;
    case StatementKind::Label:
      output += statement.label + ":;\n";
      return;
    case StatementKind::Return:
      output += options.indent + "return;\n";
      return;
    case StatementKind::Trap:
      output += options.indent + "recomp_trap(context, \"" + statement.text + "\");\n";
      return;
    case StatementKind::Verbatim:
      // Not yet migrated. Emitted exactly as the lifter produced it, which is
      // what keeps the generated code byte-identical during the migration.
      output += options.indent + statement.text + "\n";
      return;
  }
}

}  // namespace

std::string render_function(const Function& function, const CppBackendOptions& options) {
  std::string output;
  for (const auto& statement : function.statements) render_statement(statement, options, output);
  return output;
}

std::string render_module(const Module& module, const CppBackendOptions& options) {
  std::string output;
  for (const auto& function : module.functions) output += render_function(function, options);
  return output;
}

}  // namespace recomp::ir
