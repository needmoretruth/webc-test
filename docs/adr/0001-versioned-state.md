# ADR-0001: versioned state and atomic execution

Status: accepted for implementation

WEBC uses a versioned `StateKey` space for accounts, balances, objects,
application namespaces, and protocol state. Transactions declare exact reads
and writes. The execution layer records actual access and rejects undeclared
keys.

Protocol version 1 uses fixed, typed variants for accounts, owner-scoped asset
balances, validators, delegation positions, payer-scoped fee deltas, replay
markers, protocol fields, objects, modules, and application-local keys. Runtime
validation rejects unsupported versions, duplicate/overlapping declarations,
more than 256 keys, undeclared reads/writes, read-only writes, and declared keys
that a successful transaction did not actually use. The last rule prevents
artificial contention through over-declaration.

A transaction executes in an overlay and a block executes in a parent overlay.
Only a completely valid block commits. Scheduler concurrency may change work
ordering but never the deterministic commit order or resulting root.

This boundary prevents hidden global contention, undeclared-state attacks, and
partial blocks. State versions must include an explicit migration path.
