//! The typed, name-resolved intermediate representation.
//!
//! [`Module`] is the **stable hand-off between the front end and any backend**.
//! [`crate::sema`] produces it (fields keyed and slotted, entries effect-checked,
//! bodies type-checked); the WAT backend and the interface manifest both consume
//! it. A future production backend (lowering via the audited Rust framework) or a
//! monomorphization pass slots in at exactly this boundary — consuming the same
//! `Module` — so the whole front end is reused verbatim. Keeping the IR distinct
//! from the surface AST is what makes that swap non-breaking.

use crate::ast::{EventDecl, Param, Stmt, Ty};
use webc_crypto::Hash256;

/// A fully resolved component ready for code generation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// The component name.
    pub name: String,
    /// The `vN` version / edition.
    pub version: u32,
    /// Leading documentation.
    pub docs: Vec<String>,
    /// The persistent state fields, in declaration order (which fixes their
    /// memory slots — see the backend's memory layout).
    pub state: Vec<Field>,
    /// The entrypoints.
    pub entries: Vec<EntryIr>,
    /// Declared events (carried to the manifest; codegen-deferred in edition 1).
    pub events: Vec<EventDecl>,
}

impl Module {
    /// The contract's declared footprint: the union of every entry's read and
    /// write keys, **sorted ascending and de-duplicated** — the exact shape the
    /// chain's `WasmContractManifest` requires.
    ///
    /// Note the deliberate split from memory slots: footprint order is *sorted*
    /// (a chain invariant), while a field's memory slot is its *declaration*
    /// index (backend layout). The two mappings are kept separate on purpose.
    pub fn footprint(&self) -> Vec<Hash256> {
        let mut keys: Vec<Hash256> = self.state.iter().map(|field| field.key).collect();
        keys.sort();
        keys.dedup();
        keys
    }

    /// Looks up a state field by name, returning its slot index.
    pub fn field_slot(&self, name: &str) -> Option<usize> {
        self.state.iter().position(|field| field.name == name)
    }
}

/// One resolved state field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    /// The field name.
    pub name: String,
    /// The field type.
    pub ty: Ty,
    /// The derived 32-byte state key (baked into the guest + listed in the manifest).
    pub key: Hash256,
    /// The field's slot index (its declaration order), fixing its memory offset.
    pub slot: usize,
}

/// One resolved entrypoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryIr {
    /// The entrypoint name.
    pub name: String,
    /// Parameters (the skeleton wires at most one `bytes` param).
    pub params: Vec<Param>,
    /// The optional return type.
    pub ret: Option<Ty>,
    /// State field slots this entry reads (declaration-order indices).
    pub reads: Vec<usize>,
    /// State field slots this entry writes (declaration-order indices).
    pub writes: Vec<usize>,
    /// The type-checked statement body.
    pub body: Vec<Stmt>,
    /// Leading documentation.
    pub docs: Vec<String>,
}

impl EntryIr {
    /// The slots this entry touches (reads ∪ writes), sorted and de-duplicated —
    /// the fields the backend must load in the prologue and may flush after.
    pub fn touched_slots(&self) -> Vec<usize> {
        let mut slots: Vec<usize> = self.reads.iter().chain(&self.writes).copied().collect();
        slots.sort_unstable();
        slots.dedup();
        slots
    }
}
