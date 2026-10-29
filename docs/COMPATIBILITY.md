# Compatibility status

| Capability | State | Evidence |
| --- | --- | --- |
| PE32 x86 structure inspection | Implemented | `pe_inspect_contract` |
| PE32+ x64 structure inspection | Implemented | `pe_inspect_contract` |
| SHA-256 identity | Implemented | Python `hashlib` cross-check |
| PE import-DLL enumeration | Implemented | Bounds-checked parser; fixture import coverage pending |
| x86 instruction lifting | Planned | Not yet claimed |
| x64 instruction lifting | Planned | Not yet claimed |
| macOS ARM64 native execution | Planned | Not yet claimed |
| Linux/WASM host execution | Unavailable | No execution backend |
| TicTacToe .NET profile | Blocked | Requires a .NET backend |
| Plink PE32+ profile | Blocked | Requires x64 lifting and required Win32 imports |
