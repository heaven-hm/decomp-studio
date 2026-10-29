# Canonical semantic IR (MVP)

Each IR operation carries its guest instruction source RVA and an explicit bit
width. The initial operations are `write_register`, `arithmetic_with_eflags`,
`compare_with_eflags`, `direct_call`, `branch`, `return`, and `no_operation`.

The current decoder supports only proven byte encodings. Unsupported opcodes
stop the pipeline with an error; they never become arbitrary host code.

This first representation establishes deterministic instruction provenance and
widths. Operand values, full EFLAGS semantics, memory operations, partial
registers, and indirect control flow are follow-up semantics slices.
