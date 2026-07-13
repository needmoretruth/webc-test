use crate::{Amount, ChainConfig};
use serde::{Deserialize, Serialize};
use webc_crypto::{Address, PublicKeyBytes};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: Address,
    pub balance: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub operator: Address,
    pub consensus_key: PublicKeyBytes,
    pub self_stake: Amount,
    pub commission_bps: u16,
    pub bootstrap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain: ChainConfig,
    pub accounts: Vec<GenesisAccount>,
    pub validators: Vec<GenesisValidator>,
}
