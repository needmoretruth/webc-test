# WEBC source documentation template

Every new or materially changed source file starts with a module-level comment
that answers the following questions. The wording should describe the actual
module; do not paste the checklist verbatim into source code.

```text
Purpose: why the module exists.
Responsibilities: state and behavior owned by the module.
Non-responsibilities: adjacent behavior owned elsewhere.
Data flow: trusted inputs, validation, mutation, and outputs.
Security boundary: hostile inputs, invariants, limits, and rollback behavior.
```

Every public protocol interface documents:

- input and output types, units, ranges, and size limits;
- authorization and domain-separation requirements;
- consensus-critical state changes and deterministic ordering;
- typed failure cases and whether failure rolls back;
- whether it is stable, experimental, devnet-only, or disabled for real funds.

Consensus structs keep their invariants next to the definition. Complex code
comments explain why ordering and checks prevent an attack; they do not narrate
obvious syntax. Tests and examples use deterministic values and avoid
`unwrap`, `expect`, or panic handling outside test-only code.
