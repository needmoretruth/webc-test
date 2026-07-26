//! Protocol-2 finality-authority set commitments.
//!
//! Purpose: turn the validator snapshot that certifies a V4 header into one
//! versioned, deterministic commitment usable by storage, checkpoints, and light
//! clients. Responsibilities: bind protocol/chain/epoch, sorted validator IDs,
//! consensus keys, individual voting power, and checked total power; convert to
//! the existing certificate verifier's [`ValidatorSet`]. Non-responsibilities:
//! select committees, mutate staking, fetch checkpoints, or verify blocks.
//!
//! Data flow: consensus snapshots produce [`FinalityAuthoritySetV1`] at an epoch
//! boundary. Its domain-separated commitment enters both current/next authority
//! fields of a V4 header. A verifier validates the bounded set, checks the header
//! root, converts it to [`ValidatorSet`], and only then verifies a certificate.
//!
//! Security boundary: decoded sets are hostile. Outer bytes and authority count
//! are bounded before retaining attacker-controlled collections. Validation
//! rejects empty/unsorted/duplicate identities, reused consensus keys, zero
//! power, overflow, inconsistent totals, wrong version, and wrong protocol.

use std::collections::{BTreeMap, BTreeSet};

use serde::{de::SeqAccess, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use webc_crypto::{Hash256, PublicKeyBytes};

use crate::{
    canonical::canonical_json_bytes, Amount, ChainId, Epoch, ProtocolVersion, ValidatorId,
    ValidatorPower, ValidatorSet, TRANSACTION_V5_PROTOCOL_VERSION,
};

/// Schema version carried by every finality-authority set.
pub const FINALITY_AUTHORITY_SET_V1: u16 = 1;

/// Domain separating authority-set commitments from state and block roots.
pub const FINALITY_AUTHORITY_SET_V1_DOMAIN: &str = "WEBC_FINALITY_AUTHORITY_SET_V1";

/// Absolute authority-entry count accepted from network or storage.
pub const MAX_FINALITY_AUTHORITIES_V1: usize = 16_384;

/// Absolute JSON byte bound for one checkpoint authority set.
pub const MAX_FINALITY_AUTHORITY_SET_V1_JSON_BYTES: usize = 8 * 1024 * 1024;

/// One immutable finality authority and its snapshot voting power.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityAuthorityV1 {
    /// Stable validator identity derived from the operator account.
    pub validator_id: ValidatorId,
    /// Ed25519 key authenticating protocol-2 consensus votes.
    pub consensus_key: PublicKeyBytes,
    /// Non-zero snapshot voting power in native base units.
    pub voting_power: Amount,
}

/// Versioned authority set committed by a protocol-2 V4 header.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityAuthoritySetV1 {
    /// Must equal [`FINALITY_AUTHORITY_SET_V1`].
    pub version: u16,
    /// Must equal protocol version 2.
    pub protocol_version: ProtocolVersion,
    /// Genesis-fixed network replay domain.
    pub chain_id: ChainId,
    /// Snapshot epoch encoded as a decimal string in JSON.
    #[serde(with = "epoch_decimal")]
    pub epoch: Epoch,
    /// Strictly validator-ID-sorted unique authority entries.
    #[serde(deserialize_with = "bounded_authorities::deserialize")]
    pub authorities: Vec<FinalityAuthorityV1>,
    /// Checked sum of every authority's power.
    pub total_power: Amount,
}

impl FinalityAuthoritySetV1 {
    /// Converts an existing immutable validator snapshot into the V1 commitment.
    pub fn from_validator_set(
        protocol_version: ProtocolVersion,
        chain_id: ChainId,
        epoch: Epoch,
        validator_set: &ValidatorSet,
    ) -> Result<Self, FinalityAuthoritySetErrorV1> {
        let authorities = validator_set
            .validators
            .iter()
            .map(|(operator, authority)| {
                if operator != &authority.validator {
                    return Err(FinalityAuthoritySetErrorV1::ValidatorMapKeyMismatch);
                }
                Ok(FinalityAuthorityV1 {
                    validator_id: ValidatorId::from_operator(*operator),
                    consensus_key: authority.consensus_key,
                    voting_power: authority.power,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let authority_set = Self {
            version: FINALITY_AUTHORITY_SET_V1,
            protocol_version,
            chain_id,
            epoch,
            authorities,
            total_power: validator_set.total_power,
        };
        authority_set.validate()?;
        Ok(authority_set)
    }

    /// Decodes and validates hostile JSON after enforcing the outer byte cap.
    pub fn decode_json(bytes: &[u8]) -> Result<Self, FinalityAuthoritySetErrorV1> {
        if bytes.len() > MAX_FINALITY_AUTHORITY_SET_V1_JSON_BYTES {
            return Err(FinalityAuthoritySetErrorV1::SetTooLarge {
                actual: bytes.len(),
                maximum: MAX_FINALITY_AUTHORITY_SET_V1_JSON_BYTES,
            });
        }
        let authority_set = serde_json::from_slice::<Self>(bytes)
            .map_err(|_| FinalityAuthoritySetErrorV1::Malformed)?;
        authority_set.validate()?;
        Ok(authority_set)
    }

    /// Validates schema, ordering, keys, power, and exact checked total.
    pub fn validate(&self) -> Result<(), FinalityAuthoritySetErrorV1> {
        if self.version != FINALITY_AUTHORITY_SET_V1 {
            return Err(FinalityAuthoritySetErrorV1::UnsupportedVersion {
                actual: self.version,
            });
        }
        if self.protocol_version != TRANSACTION_V5_PROTOCOL_VERSION {
            return Err(FinalityAuthoritySetErrorV1::UnsupportedProtocolVersion);
        }
        if self.authorities.is_empty() {
            return Err(FinalityAuthoritySetErrorV1::Empty);
        }
        if self.authorities.len() > MAX_FINALITY_AUTHORITIES_V1 {
            return Err(FinalityAuthoritySetErrorV1::TooManyAuthorities {
                actual: self.authorities.len(),
                maximum: MAX_FINALITY_AUTHORITIES_V1,
            });
        }
        let mut prior = None;
        let mut keys = BTreeSet::new();
        let mut total = Amount::ZERO;
        for authority in &self.authorities {
            if prior.is_some_and(|previous| previous >= authority.validator_id) {
                return Err(FinalityAuthoritySetErrorV1::NotStrictlySorted);
            }
            prior = Some(authority.validator_id);
            if !keys.insert(authority.consensus_key) {
                return Err(FinalityAuthoritySetErrorV1::DuplicateConsensusKey);
            }
            if authority.voting_power.is_zero() {
                return Err(FinalityAuthoritySetErrorV1::ZeroPower);
            }
            total = total
                .checked_add(authority.voting_power)
                .ok_or(FinalityAuthoritySetErrorV1::PowerOverflow)?;
        }
        if total != self.total_power {
            return Err(FinalityAuthoritySetErrorV1::TotalPowerMismatch);
        }
        Ok(())
    }

    /// Returns the domain-separated commitment placed in V4 headers.
    pub fn commitment(&self) -> Result<Hash256, FinalityAuthoritySetErrorV1> {
        self.validate()?;
        #[derive(Serialize)]
        struct Commitment<'a> {
            domain: &'static str,
            authority_set: &'a FinalityAuthoritySetV1,
        }
        canonical_json_bytes(&Commitment {
            domain: FINALITY_AUTHORITY_SET_V1_DOMAIN,
            authority_set: self,
        })
        .map(Hash256::digest)
        .map_err(|_| FinalityAuthoritySetErrorV1::CanonicalEncoding)
    }

    /// Reconstructs the existing immutable verifier input after full validation.
    pub fn to_validator_set(&self) -> Result<ValidatorSet, FinalityAuthoritySetErrorV1> {
        self.validate()?;
        let validators = self
            .authorities
            .iter()
            .map(|authority| {
                let operator = authority.validator_id.operator();
                (
                    operator,
                    ValidatorPower {
                        validator: operator,
                        power: authority.voting_power,
                        consensus_key: authority.consensus_key,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        Ok(ValidatorSet {
            validators,
            total_power: self.total_power,
        })
    }
}

/// Fail-closed authority-set construction and validation failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FinalityAuthoritySetErrorV1 {
    /// JSON bytes are not the strict V1 schema.
    #[error("finality authority set JSON is malformed")]
    Malformed,
    /// Outer bytes exceed the hard checkpoint/proof safety cap.
    #[error("finality authority set size {actual} exceeds maximum {maximum}")]
    SetTooLarge {
        /// Observed JSON byte length.
        actual: usize,
        /// Hard maximum JSON byte length.
        maximum: usize,
    },
    /// Record schema is not V1.
    #[error("unsupported finality authority set version {actual}")]
    UnsupportedVersion {
        /// Rejected schema version.
        actual: u16,
    },
    /// Authority commitments are only active under protocol version 2.
    #[error("finality authority set requires protocol version 2")]
    UnsupportedProtocolVersion,
    /// No authority can certify a block.
    #[error("finality authority set must not be empty")]
    Empty,
    /// Authority count exceeds the hard proof safety cap.
    #[error("authority count {actual} exceeds maximum {maximum}")]
    TooManyAuthorities {
        /// Observed authority count.
        actual: usize,
        /// Hard maximum authority count.
        maximum: usize,
    },
    /// Validator IDs are duplicated or out of canonical order.
    #[error("finality authorities must be strictly sorted by validator ID")]
    NotStrictlySorted,
    /// Two validator identities reuse one consensus key.
    #[error("finality authorities must use distinct consensus keys")]
    DuplicateConsensusKey,
    /// Voting power must be positive.
    #[error("finality authority voting power must be non-zero")]
    ZeroPower,
    /// Summing authority power overflowed the native amount range.
    #[error("finality authority total power overflowed")]
    PowerOverflow,
    /// Declared total does not equal the checked entry sum.
    #[error("finality authority total power does not match entries")]
    TotalPowerMismatch,
    /// Existing validator map key disagrees with its embedded identity.
    #[error("validator-set map key does not match its authority identity")]
    ValidatorMapKeyMismatch,
    /// Canonical commitment bytes could not be produced.
    #[error("finality authority set cannot be canonically encoded")]
    CanonicalEncoding,
}

fn deserialize_decimal_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(serde::de::Error::custom(
            "expected canonical unsigned decimal string",
        ));
    }
    value.parse::<u64>().map_err(serde::de::Error::custom)
}

mod epoch_decimal {
    use super::*;

    pub fn serialize<S>(value: &Epoch, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.get().to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Epoch, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_decimal_u64(deserializer).map(Epoch::new)
    }
}

mod bounded_authorities {
    use super::*;
    use std::fmt;
    use std::marker::PhantomData;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<FinalityAuthorityV1>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AuthoritiesVisitor(PhantomData<FinalityAuthorityV1>);

        impl<'de> Visitor<'de> for AuthoritiesVisitor {
            type Value = Vec<FinalityAuthorityV1>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded finality authority array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence
                    .size_hint()
                    .is_some_and(|hint| hint > MAX_FINALITY_AUTHORITIES_V1)
                {
                    return Err(serde::de::Error::custom("too many finality authorities"));
                }
                let mut authorities = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(MAX_FINALITY_AUTHORITIES_V1),
                );
                while let Some(authority) = sequence.next_element()? {
                    if authorities.len() == MAX_FINALITY_AUTHORITIES_V1 {
                        return Err(serde::de::Error::custom("too many finality authorities"));
                    }
                    authorities.push(authority);
                }
                Ok(authorities)
            }
        }

        deserializer.deserialize_seq(AuthoritiesVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webc_crypto::Keypair;

    fn fixture() -> FinalityAuthoritySetV1 {
        let validator = Keypair::from_seed([1; 32]);
        FinalityAuthoritySetV1 {
            version: FINALITY_AUTHORITY_SET_V1,
            protocol_version: TRANSACTION_V5_PROTOCOL_VERSION,
            chain_id: ChainId::devnet(),
            epoch: Epoch::new(3),
            authorities: vec![FinalityAuthorityV1 {
                validator_id: ValidatorId::from_operator(validator.address()),
                consensus_key: validator.public_key(),
                voting_power: Amount::from_units(100),
            }],
            total_power: Amount::from_units(100),
        }
    }

    #[test]
    fn authority_commitment_matches_browser_fixture_and_validator_set() {
        let authority_set = fixture();
        assert_eq!(
            authority_set.commitment().unwrap().to_hex(),
            "4361528bc72a2ea4e098119168f5eec6c5087d2958d48c2bccd26d0de2651899"
        );
        let verifier = authority_set.to_validator_set().unwrap();
        let rebuilt = FinalityAuthoritySetV1::from_validator_set(
            TRANSACTION_V5_PROTOCOL_VERSION,
            ChainId::devnet(),
            Epoch::new(3),
            &verifier,
        )
        .unwrap();
        assert_eq!(rebuilt, authority_set);
    }

    #[test]
    fn rejects_order_duplicates_zero_power_and_bad_total() {
        let first = Keypair::from_seed([1; 32]);
        let second = Keypair::from_seed([2; 32]);
        let mut authority_set = fixture();
        authority_set.authorities = vec![
            FinalityAuthorityV1 {
                validator_id: ValidatorId::from_operator(second.address()),
                consensus_key: second.public_key(),
                voting_power: Amount::from_units(1),
            },
            FinalityAuthorityV1 {
                validator_id: ValidatorId::from_operator(first.address()),
                consensus_key: first.public_key(),
                voting_power: Amount::from_units(1),
            },
        ];
        authority_set.total_power = Amount::from_units(2);
        authority_set
            .authorities
            .sort_by_key(|item| item.validator_id);
        authority_set.authorities.reverse();
        assert_eq!(
            authority_set.validate(),
            Err(FinalityAuthoritySetErrorV1::NotStrictlySorted)
        );

        let mut duplicate_key = fixture();
        let mut other = duplicate_key.authorities[0];
        other.validator_id = ValidatorId::from_operator(second.address());
        duplicate_key.authorities.push(other);
        duplicate_key
            .authorities
            .sort_by_key(|item| item.validator_id);
        duplicate_key.total_power = Amount::from_units(200);
        assert_eq!(
            duplicate_key.validate(),
            Err(FinalityAuthoritySetErrorV1::DuplicateConsensusKey)
        );

        let mut zero = fixture();
        zero.authorities[0].voting_power = Amount::ZERO;
        zero.total_power = Amount::ZERO;
        assert_eq!(zero.validate(), Err(FinalityAuthoritySetErrorV1::ZeroPower));

        let mut total = fixture();
        total.total_power = Amount::from_units(101);
        assert_eq!(
            total.validate(),
            Err(FinalityAuthoritySetErrorV1::TotalPowerMismatch)
        );
    }

    #[test]
    fn hostile_json_is_bounded_and_wide_epoch_is_a_string() {
        let json = serde_json::to_vec(&fixture()).unwrap();
        let decoded = FinalityAuthoritySetV1::decode_json(&json).unwrap();
        assert_eq!(decoded, fixture());
        let mut value = serde_json::to_value(fixture()).unwrap();
        assert_eq!(value["epoch"], "3");
        value["epoch"] = serde_json::Value::Number(3.into());
        assert!(serde_json::from_value::<FinalityAuthoritySetV1>(value).is_err());
        assert!(matches!(
            FinalityAuthoritySetV1::decode_json(&vec![
                b' ';
                MAX_FINALITY_AUTHORITY_SET_V1_JSON_BYTES + 1
            ]),
            Err(FinalityAuthoritySetErrorV1::SetTooLarge { .. })
        ));
    }
}
