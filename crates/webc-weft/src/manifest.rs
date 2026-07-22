//! The machine-readable interface manifest (`weft.interface/v1`).
//!
//! Emitted alongside the wasm artifact, this is the decided design's compiler
//! output that the component catalog and AI agents consume: the component's
//! entrypoints, state, events, errors, and — crucially — the resolved effect keys
//! and the sorted `footprint` a deployer feeds straight into the chain's
//! `WasmContractManifest`. Serialized as canonical JSON with a fixed field order
//! and sorted footprint, so it participates in reproducible builds.
//!
//! Edition-1 scope: `events` is populated from declarations; `errors` and `types`
//! are present-but-empty reserved arrays (typed `Result` errors and struct/enum
//! definitions land later) — the schema shape is already the full one, so growth
//! adds data, not fields.

use serde::{Deserialize, Serialize};
use webc_crypto::Hash256;

use crate::ast::Ty;
use crate::ir::Module;

/// ABI/manifest edition this compiler emits. Mirrors the chain's
/// `WASM_CONTRACT_ABI_VERSION` for edition 1.
pub const WEFT_ABI_VERSION: u32 = 1;
/// Gas-schedule version the emitted contract is priced against.
pub const WEFT_GAS_SCHEDULE_VERSION: u32 = 1;
/// The manifest schema identifier.
pub const WEFT_INTERFACE_SCHEMA: &str = "weft.interface/v1";

/// The full interface manifest for one compiled component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceManifest {
    /// Schema identifier (`weft.interface/v1`).
    pub schema: String,
    /// Language edition the source was compiled under.
    pub edition: u32,
    /// Contract ABI version (matches the chain's wasm ABI).
    pub abi_version: u32,
    /// Gas-schedule version priced against.
    pub gas_schedule_version: u32,
    /// The compiler name+version, for reproducible-build provenance.
    pub compiler: String,
    /// Raw SHA-256 of the emitted wasm module — a reproducible-build fingerprint
    /// (distinct from the chain's domain-separated `code_hash`, which the chain
    /// computes at registration).
    pub wasm_sha256: Hash256,
    /// The component name.
    pub component: String,
    /// The component version (`vN`).
    pub version: u32,
    /// The component's doc comment (joined lines), or empty.
    pub doc: String,
    /// Declared persistent state.
    pub state: Vec<StateEntry>,
    /// Callable entrypoints.
    pub entrypoints: Vec<EntrypointEntry>,
    /// Declared event types.
    pub events: Vec<EventEntry>,
    /// Reserved: typed `Result` error enums (empty in edition 1).
    pub errors: Vec<TypeEntry>,
    /// Reserved: struct/enum type definitions (empty in edition 1).
    pub types: Vec<TypeEntry>,
    /// The contract's declared footprint — sorted ascending state keys, exactly
    /// what the chain's `WasmContractManifest.footprint` requires.
    pub footprint: Vec<Hash256>,
}

/// One state field in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateEntry {
    /// The field name.
    pub name: String,
    /// The field type as a string (`u64` / `bytes`).
    #[serde(rename = "type")]
    pub ty: String,
    /// The derived 32-byte state key.
    pub key_hash: Hash256,
    /// The field's doc comment (joined), or empty.
    pub doc: String,
}

/// One entrypoint in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrypointEntry {
    /// The entrypoint name.
    pub name: String,
    /// The entrypoint's doc comment (joined), or empty.
    pub doc: String,
    /// Declared parameters.
    pub params: Vec<ParamEntry>,
    /// The return type as a string, or `null` if it returns nothing.
    pub returns: Option<String>,
    /// State field names in the `reads` clause (source-level effect).
    pub reads: Vec<String>,
    /// State field names in the `writes` clause (source-level effect).
    pub writes: Vec<String>,
    /// The resolved physical effect keys — the on-chain declared access.
    pub effects: EffectKeys,
}

/// A named+typed manifest parameter or event/struct field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamEntry {
    /// The name.
    pub name: String,
    /// The type as a string.
    #[serde(rename = "type")]
    pub ty: String,
}

/// The resolved read/write keys of an entrypoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectKeys {
    /// Physical keys read.
    pub reads: Vec<Hash256>,
    /// Physical keys written.
    pub writes: Vec<Hash256>,
}

/// One event type in the manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEntry {
    /// The event name.
    pub name: String,
    /// The event's doc comment (joined), or empty.
    pub doc: String,
    /// The event's payload fields.
    pub fields: Vec<ParamEntry>,
}

/// A reserved named type (errors/types), carried for forward-compatible shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeEntry {
    /// The type name.
    pub name: String,
}

/// Renders a [`Ty`] as its manifest string.
fn ty_str(ty: Ty) -> String {
    match ty {
        Ty::U64 => "u64".to_string(),
        Ty::Bytes => "bytes".to_string(),
    }
}

/// Builds the interface manifest for a checked `module` and its emitted `wasm`.
pub fn build(module: &Module, wasm: &[u8]) -> InterfaceManifest {
    let state = module
        .state
        .iter()
        .map(|field| StateEntry {
            name: field.name.clone(),
            ty: ty_str(field.ty),
            key_hash: field.key,
            doc: String::new(),
        })
        .collect();

    let entrypoints = module
        .entries
        .iter()
        .map(|entry| {
            let reads_keys = entry.reads.iter().map(|s| module.state[*s].key).collect();
            let writes_keys = entry.writes.iter().map(|s| module.state[*s].key).collect();
            EntrypointEntry {
                name: entry.name.clone(),
                doc: entry.docs.join(" "),
                params: entry
                    .params
                    .iter()
                    .map(|p| ParamEntry {
                        name: p.name.value.clone(),
                        ty: ty_str(p.ty),
                    })
                    .collect(),
                returns: entry.ret.map(ty_str),
                reads: entry
                    .reads
                    .iter()
                    .map(|s| module.state[*s].name.clone())
                    .collect(),
                writes: entry
                    .writes
                    .iter()
                    .map(|s| module.state[*s].name.clone())
                    .collect(),
                effects: EffectKeys {
                    reads: reads_keys,
                    writes: writes_keys,
                },
            }
        })
        .collect();

    let events = module
        .events
        .iter()
        .map(|event| EventEntry {
            name: event.name.value.clone(),
            doc: event.docs.join(" "),
            fields: event
                .fields
                .iter()
                .map(|p| ParamEntry {
                    name: p.name.value.clone(),
                    ty: ty_str(p.ty),
                })
                .collect(),
        })
        .collect();

    InterfaceManifest {
        schema: WEFT_INTERFACE_SCHEMA.to_string(),
        edition: module.version,
        abi_version: WEFT_ABI_VERSION,
        gas_schedule_version: WEFT_GAS_SCHEDULE_VERSION,
        compiler: concat!("webc-weft ", env!("CARGO_PKG_VERSION")).to_string(),
        wasm_sha256: Hash256::digest(wasm),
        component: module.name.clone(),
        version: module.version,
        doc: module.docs.join(" "),
        state,
        entrypoints,
        events,
        errors: Vec::new(),
        types: Vec::new(),
        footprint: module.footprint(),
    }
}

impl InterfaceManifest {
    /// Serializes to canonical pretty JSON.
    pub fn to_json(&self) -> String {
        // Field order is fixed by the struct; serialization cannot fail for these
        // plain data types, but fall back rather than panic if it somehow does.
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}
