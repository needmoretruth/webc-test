# ADR-0002: signed delegated-PoS BFT consensus

Status: accepted direction; timing and committee parameters remain technical gates

Consensus uses stake snapshots, a deterministic proposer schedule, and signed
prevote/precommit rounds. Votes commit to protocol version, chain ID, height,
round, step, proposal hash, and validator-set snapshot. More than two thirds of
selected voting power is required for finality.

PoH and zero-collateral voting are excluded. Objective signed conflicts are the
only severe slashing input. Networking, storage, and execution remain separate
from the consensus state machine.
