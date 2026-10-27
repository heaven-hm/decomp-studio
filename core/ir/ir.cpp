#include "core/ir/ir.hpp"

namespace recomp::ir {

const char* statement_kind_name(StatementKind kind) {
  switch (kind) {
    case StatementKind::Comment: return "comment";
    case StatementKind::Assign: return "assign";
    case StatementKind::StoreMemory: return "store";
    case StatementKind::CallGuest: return "call-guest";
    case StatementKind::CallImport: return "call-import";
    case StatementKind::CallIndirect: return "call-indirect";
    case StatementKind::JumpIf: return "jump-if";
    case StatementKind::Jump: return "jump";
    case StatementKind::Label: return "label";
    case StatementKind::Return: return "return";
    case StatementKind::Trap: return "trap";
    case StatementKind::Verbatim: return "verbatim";
    case StatementKind::Trace: return "trace";
  }
  return "unknown";
}

StatementCensus census(const Module& module) {
  StatementCensus result;
  for (const auto& function : module.functions) {
    for (const auto& statement : function.statements) {
      ++result.total;
      if (statement.kind == StatementKind::Verbatim) ++result.verbatim;
      else if (statement.kind != StatementKind::Comment) ++result.structured;
    }
  }
  return result;
}

}  // namespace recomp::ir
