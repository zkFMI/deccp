//! Deterministic clearing and risk state for a Decentralized Central
//! Counterparty.
//!
//! DeCCP centralizes the *logical* novation, margin, netting, guarantee, and
//! default-waterfall rules while decentralizing their control through a
//! threshold authority set. DeCCP never updates authoritative cash or asset
//! title: it records DeFMI lock/settlement receipts and emits exact contexts for
//! zkPI construction.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zkfmi_crypto::{
    hybrid::signature::{HybridSignature, HybridSigner, HybridVerifier},
    key::{KeyId, KeyPurpose, KeyRecord},
    suite::{Suite, SuiteId, Version},
    traits::Signer as _,
};

pub type Digest32 = [u8; 32];
pub type Identifier = [u8; 32];
pub const ZERO: [u8; 32] = [0; 32];

/// Both components are mandatory. Legacy 64-byte-only approvals are not accepted.
pub type SignatureBytes = HybridSignature;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityMember {
    pub member_id: Identifier,
    pub key: KeyRecord,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySet {
    pub epoch: u64,
    pub threshold: u16,
    pub members: Vec<AuthorityMember>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySignature {
    pub member_id: Identifier,
    pub key_id: KeyId,
    pub key_version: u32,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuorumApproval {
    pub version: Version,
    pub suite: Suite,
    pub authority_epoch: u64,
    pub authority_digest: Digest32,
    pub statement_digest: Digest32,
    pub signatures: Vec<AuthoritySignature>,
}

impl AuthoritySet {
    pub fn validate(&self) -> Result<(), DeCcpError> {
        if self.epoch == 0
            || self.threshold == 0
            || self.threshold as usize > self.members.len()
            || self.members.is_empty()
            || self.members.len() > 64
        {
            return Err(DeCcpError::InvalidAuthoritySet);
        }
        let mut ids = BTreeSet::new();
        let mut participants = BTreeSet::new();
        let mut key_ids = BTreeSet::new();
        let mut classical = BTreeSet::new();
        let mut pq = BTreeSet::new();
        for member in &self.members {
            let key = &member.key;
            if member.member_id == ZERO
                || key.validate().is_err()
                || key.suite != Suite::new(SuiteId::Ed25519MlDsa65)
                || key.purpose != KeyPurpose::Governance
                || !ids.insert(member.member_id)
                || !participants.insert(key.participant_id.clone())
                || !key_ids.insert(key.key_id.clone())
            {
                return Err(DeCcpError::InvalidAuthoritySet);
            }
            let public: [u8; 32] = key.public_key[..32]
                .try_into()
                .map_err(|_| DeCcpError::InvalidAuthoritySet)?;
            if public == ZERO
                || VerifyingKey::from_bytes(&public).is_err()
                || key.public_key[32..].iter().all(|byte| *byte == 0)
                || !classical.insert(public)
                || !pq.insert(key.public_key[32..].to_vec())
            {
                return Err(DeCcpError::InvalidAuthoritySet);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<Digest32, DeCcpError> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|_| DeCcpError::InvalidAuthoritySet)?;
        Ok(digest_fields(b"DECCP:HYBRID-AUTHORITY:v2", &[&encoded]))
    }

    fn signing_message(
        &self,
        statement: &Digest32,
        member: &Identifier,
    ) -> Result<Digest32, DeCcpError> {
        Ok(digest_fields(
            b"DECCP:HYBRID-APPROVAL:v2",
            &[&self.digest()?, member, statement],
        ))
    }

    /// The caller supplies the authoritative execution time, never a request timestamp.
    pub fn verify(
        &self,
        statement: &Digest32,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), DeCcpError> {
        self.verify_at(statement, approval, Some(now))
    }

    /// Integrity-only verification for explicitly requested snapshot restoration.
    /// Every subsequent operation still uses the current execution-time key checks.
    fn verify_archived(
        &self,
        statement: &Digest32,
        approval: &QuorumApproval,
    ) -> Result<(), DeCcpError> {
        self.verify_at(statement, approval, None)
    }

    fn verify_at(
        &self,
        statement: &Digest32,
        approval: &QuorumApproval,
        now: Option<u64>,
    ) -> Result<(), DeCcpError> {
        self.validate()?;
        if approval.suite != Suite::new(SuiteId::Ed25519MlDsa65)
            || approval.authority_epoch != self.epoch
            || approval.authority_digest != self.digest()?
            || &approval.statement_digest != statement
            || approval.signatures.len() > self.members.len()
        {
            return Err(DeCcpError::InvalidQuorumApproval);
        }
        let mut signers = BTreeSet::new();
        for signed in &approval.signatures {
            if !signers.insert(signed.member_id) {
                return Err(DeCcpError::InvalidQuorumApproval);
            }
            let member = self
                .members
                .iter()
                .find(|member| member.member_id == signed.member_id)
                .ok_or(DeCcpError::InvalidQuorumApproval)?;
            let key = &member.key;
            if signed.key_id != key.key_id
                || signed.key_version != key.key_version
                || now.is_some_and(|at| key.valid_at(at).is_err())
            {
                return Err(DeCcpError::InvalidQuorumApproval);
            }
            HybridVerifier
                .verify_hybrid(
                    KeyPurpose::Governance,
                    &key.public_key,
                    &self.signing_message(statement, &signed.member_id)?,
                    &signed.signature,
                )
                .map_err(|_| DeCcpError::InvalidQuorumApproval)?;
        }
        if signers.len() < self.threshold as usize {
            return Err(DeCcpError::InsufficientQuorum);
        }
        Ok(())
    }
}

impl QuorumApproval {
    pub fn sign(
        authorities: &AuthoritySet,
        statement_digest: Digest32,
        signers: &[(Identifier, &HybridSigner)],
    ) -> Result<Self, DeCcpError> {
        authorities.validate()?;
        let mut seen = BTreeSet::new();
        let mut signatures = Vec::new();
        for (member_id, signer) in signers {
            let member = authorities
                .members
                .iter()
                .find(|member| member.member_id == *member_id)
                .ok_or(DeCcpError::InvalidQuorumApproval)?;
            if !seen.insert(*member_id) || signer.public_key() != member.key.public_key {
                return Err(DeCcpError::InvalidQuorumApproval);
            }
            let signature = signer
                .sign_hybrid(
                    KeyPurpose::Governance,
                    &authorities.signing_message(&statement_digest, member_id)?,
                )
                .map_err(|_| DeCcpError::InvalidQuorumApproval)?;
            signatures.push(AuthoritySignature {
                member_id: *member_id,
                key_id: member.key.key_id.clone(),
                key_version: member.key.key_version,
                signature,
            });
        }
        Ok(Self {
            version: Version::V1,
            suite: Suite::new(SuiteId::Ed25519MlDsa65),
            authority_epoch: authorities.epoch,
            authority_digest: authorities.digest()?,
            statement_digest,
            signatures,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus {
    Active,
    Suspended,
    Defaulted,
    Exited,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EligibilityAttestation {
    pub provider_id: Identifier,
    pub subject_line_id: Digest32,
    pub policy_digest: Digest32,
    pub evidence_digest: Digest32,
    pub valid_until: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAdmission {
    pub provider_id: Identifier,
    pub subject_line_id: Digest32,
    pub policy_digest: Digest32,
    pub evidence_digest: Digest32,
    pub valid_until: u64,
}

pub trait EligibilityPort {
    fn verify(
        &self,
        evidence: &EligibilityAttestation,
        now: u64,
    ) -> Result<VerifiedAdmission, String>;
}

/// Boundary to zkPI or another authenticated settlement-instruction source.
/// The implementation must verify that the digest names a valid instruction
/// whose parties, asset, amount, and lifecycle permit clearing admission.
pub trait InstructionPort {
    fn verify_obligation(&self, obligation: &ClearingObligation, now: u64) -> Result<(), String>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefmiSettlementReceipt {
    pub receipt_digest: Digest32,
    pub context_digest: Digest32,
    pub finalized_at: u64,
}

/// Explicit boundary to authoritative DeFMI state. Implementations must query
/// or verify the target deployment; a non-zero identifier is not evidence that
/// collateral or guarantee value was actually locked or settled.
pub trait DeFmiPort {
    fn verify_ccp_capital(
        &self,
        capitalization: &CcpCapitalization,
        now: u64,
    ) -> Result<(), String>;

    fn verify_default_fund(&self, admission: &ParticipantAdmission, now: u64)
        -> Result<(), String>;

    fn verify_collateral_lock(&self, lot: &CollateralLot, now: u64) -> Result<(), String>;

    fn verify_guarantee_facility(
        &self,
        facility: &GuaranteeFacility,
        now: u64,
    ) -> Result<(), String>;

    fn verify_guarantee_hold(
        &self,
        reservation: &GuaranteeReservation,
        now: u64,
    ) -> Result<(), String>;

    fn verify_confidential_guarantee_facility(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        now: u64,
    ) -> Result<(), String>;

    fn verify_confidential_guarantee_hold(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        reservation: &ConfidentialGuaranteeReservation,
        now: u64,
    ) -> Result<(), String>;

    fn verify_confidential_guarantee_release(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeReleaseRequest,
        now: u64,
    ) -> Result<(), String>;

    fn verify_confidential_guarantee_claim(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeClaimRequest,
        now: u64,
    ) -> Result<(), String>;

    fn verify_guarantee_release(
        &self,
        expected_context: &Digest32,
        receipt: &DefmiSettlementReceipt,
        now: u64,
    ) -> Result<(), String>;

    fn verify_settlement(
        &self,
        expected_context: &Digest32,
        receipt: &DefmiSettlementReceipt,
        now: u64,
    ) -> Result<(), String>;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParticipantAdmission {
    pub operation_id: Identifier,
    pub participant_id: Identifier,
    pub settlement_participant_id: Identifier,
    pub eligibility: EligibilityAttestation,
    pub default_fund_contribution: u128,
    pub default_fund_defmi_lock_id: Identifier,
    pub default_fund_proof_digest: Digest32,
    pub admitted_at: u64,
}

impl ParticipantAdmission {
    pub fn statement_digest(&self) -> Result<Digest32, DeCcpError> {
        if [
            self.operation_id,
            self.participant_id,
            self.settlement_participant_id,
            self.eligibility.provider_id,
            self.eligibility.subject_line_id,
            self.eligibility.policy_digest,
            self.eligibility.evidence_digest,
            self.default_fund_defmi_lock_id,
            self.default_fund_proof_digest,
        ]
        .contains(&ZERO)
            || self.default_fund_contribution == 0
            || self.admitted_at == 0
            || self.eligibility.valid_until < self.admitted_at
        {
            return Err(DeCcpError::InvalidParticipant);
        }
        Ok(digest_fields(
            b"DECCP:PARTICIPANT-ADMISSION:v1",
            &[
                &self.operation_id,
                &self.participant_id,
                &self.settlement_participant_id,
                &self.eligibility.provider_id,
                &self.eligibility.subject_line_id,
                &self.eligibility.policy_digest,
                &self.eligibility.evidence_digest,
                &self.eligibility.valid_until.to_be_bytes(),
                &self.default_fund_contribution.to_be_bytes(),
                &self.default_fund_defmi_lock_id,
                &self.default_fund_proof_digest,
                &self.admitted_at.to_be_bytes(),
            ],
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Participant {
    pub participant_id: Identifier,
    pub settlement_participant_id: Identifier,
    pub eligibility: EligibilityAttestation,
    pub default_fund_remaining: u128,
    pub default_fund_defmi_lock_id: Identifier,
    pub default_fund_proof_digest: Digest32,
    pub status: ParticipantStatus,
    pub admitted_at: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralStatus {
    Available,
    Released,
    Seized,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CollateralLot {
    pub operation_id: Identifier,
    pub lot_id: Identifier,
    pub owner_id: Identifier,
    pub asset_id: Identifier,
    pub defmi_lock_id: Identifier,
    pub market_value: u128,
    pub haircut_basis_points: u16,
    pub valuation_policy_digest: Digest32,
    pub valuation_proof_digest: Digest32,
    pub valid_until: u64,
    pub status: CollateralStatus,
}

impl CollateralLot {
    pub fn eligible_value(&self) -> Result<u128, DeCcpError> {
        if self.haircut_basis_points >= 10_000 {
            return Err(DeCcpError::InvalidCollateral);
        }
        self.market_value
            .checked_mul((10_000 - self.haircut_basis_points) as u128)
            .and_then(|value| value.checked_div(10_000))
            .ok_or(DeCcpError::ArithmeticOverflow)
    }

    fn validate(&self) -> Result<(), DeCcpError> {
        if [
            self.operation_id,
            self.lot_id,
            self.owner_id,
            self.asset_id,
            self.defmi_lock_id,
            self.valuation_policy_digest,
            self.valuation_proof_digest,
        ]
        .contains(&ZERO)
            || self.market_value == 0
            || self.valid_until == 0
            || self.status != CollateralStatus::Available
        {
            return Err(DeCcpError::InvalidCollateral);
        }
        self.eligible_value()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarginAccount {
    pub initial_margin: u128,
    pub variation_margin: u128,
    pub encumbered_collateral: u128,
    pub sequence: u64,
}

impl MarginAccount {
    pub fn required(&self) -> Result<u128, DeCcpError> {
        self.initial_margin
            .checked_add(self.variation_margin)
            .ok_or(DeCcpError::ArithmeticOverflow)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MarginUpdate {
    pub operation_id: Identifier,
    pub participant_id: Identifier,
    pub initial_margin: u128,
    pub variation_margin: u128,
    pub expected_sequence: u64,
}

impl MarginUpdate {
    pub fn statement_digest(&self) -> Digest32 {
        margin_approval_digest(
            &self.operation_id,
            &self.participant_id,
            self.initial_margin,
            self.variation_margin,
            self.expected_sequence,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingMode {
    GrossGross,
    GrossNet,
    NetNet,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleStatus {
    Open,
    Closed,
    Settled,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenCycleRequest {
    pub operation_id: Identifier,
    pub cycle_id: Identifier,
    pub mode: NettingMode,
    pub settlement_asset_id: Identifier,
    pub policy_digest: Digest32,
    pub opened_at: u64,
}

impl OpenCycleRequest {
    pub fn statement_digest(&self) -> Digest32 {
        open_cycle_approval_digest(
            &self.operation_id,
            &self.cycle_id,
            self.mode,
            &self.settlement_asset_id,
            &self.policy_digest,
            self.opened_at,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingObligation {
    pub operation_id: Identifier,
    pub obligation_id: Identifier,
    pub cycle_id: Identifier,
    pub payer_id: Identifier,
    pub payee_id: Identifier,
    pub asset_id: Identifier,
    pub amount: u128,
    pub risk_value: u128,
    pub zkpi_digest: Digest32,
}

impl ClearingObligation {
    fn validate(&self) -> Result<(), DeCcpError> {
        if [
            self.operation_id,
            self.obligation_id,
            self.cycle_id,
            self.payer_id,
            self.payee_id,
            self.asset_id,
            self.zkpi_digest,
        ]
        .contains(&ZERO)
            || self.payer_id == self.payee_id
            || self.amount == 0
            || self.risk_value == 0
        {
            return Err(DeCcpError::InvalidObligation);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingLeg {
    pub payer_id: Identifier,
    pub payee_id: Identifier,
    pub asset_id: Identifier,
    pub amount: u128,
    /// Exact public context a zkPI builder must bind.
    pub instruction_context_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NettingProposal {
    pub cycle_id: Identifier,
    pub mode: NettingMode,
    pub obligation_root: Digest32,
    pub legs: Vec<ClearingLeg>,
    pub risk_debits: BTreeMap<String, u128>,
    pub proposal_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NettingCycle {
    pub cycle_id: Identifier,
    pub mode: NettingMode,
    pub settlement_asset_id: Identifier,
    pub policy_digest: Digest32,
    pub status: CycleStatus,
    pub opened_at: u64,
    pub obligations: Vec<Identifier>,
    pub closed_proposal: Option<NettingProposal>,
    pub defmi_settlement_receipt: Option<Digest32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeFacilityStatus {
    Active,
    Suspended,
    Exhausted,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuaranteeHoldStatus {
    Reserved,
    Bound,
    Consumed,
    Released,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeFacility {
    pub facility_id: Identifier,
    pub guarantor_id: Identifier,
    pub beneficiary_subject_line_id: Digest32,
    pub settlement_asset_id: Identifier,
    pub capacity: u128,
    pub reserved: u128,
    pub consumed: u128,
    pub defmi_facility_id: Identifier,
    pub policy_digest: Digest32,
    pub valid_until: u64,
    pub sequence: u64,
    pub status: GuaranteeFacilityStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeReservation {
    pub operation_id: Identifier,
    pub hold_id: Identifier,
    pub facility_id: Identifier,
    pub purpose_digest: Digest32,
    pub amount: u128,
    pub defmi_hold_id: Identifier,
    pub relation_proof_digest: Digest32,
    pub expected_facility_sequence: u64,
    pub valid_until: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeHold {
    pub hold_id: Identifier,
    pub facility_id: Identifier,
    pub purpose_digest: Digest32,
    pub amount: u128,
    pub defmi_hold_id: Identifier,
    pub relation_proof_digest: Digest32,
    pub valid_until: u64,
    pub status: GuaranteeHoldStatus,
    pub bound_exposure_id: Option<Identifier>,
    pub defmi_settlement_receipt: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuaranteeClaimRequest {
    pub operation_id: Identifier,
    pub hold_id: Identifier,
    pub exposure_id: Identifier,
    pub default_event_digest: Digest32,
    pub receipt: DefmiSettlementReceipt,
}

/// A guarantee facility whose monetary capacity and aggregate usage remain
/// committed in DeFMI. DeCCP serializes changes with both a public sequence and
/// a commitment-state compare-and-swap; it never needs the hidden amount.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidentialGuaranteeFacility {
    pub facility_id: Identifier,
    pub guarantor_id: Identifier,
    pub beneficiary_subject_line_id: Digest32,
    pub settlement_asset_id: Identifier,
    pub capacity_commitment: Digest32,
    pub latest_facility_state_digest: Digest32,
    pub defmi_facility_id: Identifier,
    pub policy_digest: Digest32,
    pub valid_until: u64,
    pub sequence: u64,
    pub status: GuaranteeFacilityStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidentialGuaranteeReservation {
    pub operation_id: Identifier,
    pub hold_id: Identifier,
    pub facility_id: Identifier,
    pub purpose_digest: Digest32,
    pub coverage_commitment: Digest32,
    pub defmi_hold_id: Identifier,
    /// Proof that the hidden hold amount is positive, is the amount committed
    /// by `coverage_commitment`, and leaves the facility within capacity.
    pub relation_proof_digest: Digest32,
    pub expected_facility_state_digest: Digest32,
    pub after_facility_state_digest: Digest32,
    pub expected_facility_sequence: u64,
    pub valid_until: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidentialGuaranteeHold {
    pub hold_id: Identifier,
    pub facility_id: Identifier,
    pub purpose_digest: Digest32,
    pub coverage_commitment: Digest32,
    pub defmi_hold_id: Identifier,
    pub relation_proof_digest: Digest32,
    pub reserved_state_digest: Digest32,
    pub valid_until: u64,
    pub status: GuaranteeHoldStatus,
    pub bound_exposure_id: Option<Identifier>,
    pub defmi_settlement_receipt: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidentialGuaranteeReleaseRequest {
    pub operation_id: Identifier,
    pub hold_id: Identifier,
    pub expected_facility_state_digest: Digest32,
    pub after_facility_state_digest: Digest32,
    pub expected_facility_sequence: u64,
    pub transition_proof_digest: Digest32,
    pub receipt: DefmiSettlementReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfidentialGuaranteeClaimRequest {
    pub operation_id: Identifier,
    pub hold_id: Identifier,
    pub exposure_id: Identifier,
    pub default_event_digest: Digest32,
    pub expected_facility_state_digest: Digest32,
    pub after_facility_state_digest: Digest32,
    pub expected_facility_sequence: u64,
    pub transition_proof_digest: Digest32,
    pub receipt: DefmiSettlementReceipt,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultEvidence {
    pub event_id: Identifier,
    pub source_id: Identifier,
    pub participant_id: Identifier,
    pub event_digest: Digest32,
    pub observed_at: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultSourceKind {
    DefaulterMargin,
    DefaulterFund,
    MutualizedFund,
    CcpCapital,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WaterfallDraw {
    pub source_kind: DefaultSourceKind,
    pub participant_id: Option<Identifier>,
    pub amount: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultResolution {
    pub case_id: Identifier,
    pub participant_id: Identifier,
    pub shortfall: u128,
    pub draws: Vec<WaterfallDraw>,
    pub settlement_context_digest: Digest32,
    pub resolution_digest: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DefaultCase {
    pub case_id: Identifier,
    pub evidence: DefaultEvidence,
    pub declared_at: u64,
    pub resolution: Option<DefaultResolution>,
    pub defmi_settlement_receipt: Option<Digest32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CcpCapitalization {
    pub amount: u128,
    pub defmi_lock_id: Identifier,
    pub proof_digest: Digest32,
    pub valid_until: u64,
}

/// Persisted form of [`ClearingBook`]. It is plain data; only
/// [`ClearingBook::restore`] turns it back into a book, and that requires a
/// quorum approval of the snapshot digest by a trusted authority set plus a
/// full invariant check.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingSnapshot {
    pub authorities: AuthoritySet,
    pub participants: BTreeMap<String, Participant>,
    pub collateral: BTreeMap<String, CollateralLot>,
    pub margins: BTreeMap<String, MarginAccount>,
    pub cycles: BTreeMap<String, NettingCycle>,
    pub obligations: BTreeMap<String, ClearingObligation>,
    pub guarantee_facilities: BTreeMap<String, GuaranteeFacility>,
    pub guarantee_holds: BTreeMap<String, GuaranteeHold>,
    pub confidential_guarantee_facilities: BTreeMap<String, ConfidentialGuaranteeFacility>,
    pub confidential_guarantee_holds: BTreeMap<String, ConfidentialGuaranteeHold>,
    pub defaults: BTreeMap<String, DefaultCase>,
    pub ccp_capital_remaining: u128,
    pub ccp_capital_defmi_lock_id: Identifier,
    pub ccp_capital_proof_digest: Digest32,
    pub ccp_capital_valid_until: u64,
    pub used_operations: BTreeSet<String>,
}

impl ClearingSnapshot {
    /// Digest over the canonical JSON encoding (all maps are ordered).
    pub fn digest(&self) -> Result<Digest32, DeCcpError> {
        let encoded = serde_json::to_vec(self).map_err(|_| DeCcpError::InvalidState)?;
        let mut hash = Sha256::new();
        hash.update(b"DECCP:SNAPSHOT:v1");
        hash.update((encoded.len() as u64).to_be_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
}

/// Runtime aggregate. It is intentionally serialization-only: deserializing a
/// struct directly would bypass quorum, DeKYX, and DeFMI verification. Restore
/// implementations must replay verified operations or add a separately
/// authenticated snapshot format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingBook {
    authorities: AuthoritySet,
    participants: BTreeMap<String, Participant>,
    collateral: BTreeMap<String, CollateralLot>,
    margins: BTreeMap<String, MarginAccount>,
    cycles: BTreeMap<String, NettingCycle>,
    obligations: BTreeMap<String, ClearingObligation>,
    guarantee_facilities: BTreeMap<String, GuaranteeFacility>,
    guarantee_holds: BTreeMap<String, GuaranteeHold>,
    confidential_guarantee_facilities: BTreeMap<String, ConfidentialGuaranteeFacility>,
    confidential_guarantee_holds: BTreeMap<String, ConfidentialGuaranteeHold>,
    defaults: BTreeMap<String, DefaultCase>,
    ccp_capital_remaining: u128,
    ccp_capital_defmi_lock_id: Identifier,
    ccp_capital_proof_digest: Digest32,
    ccp_capital_valid_until: u64,
    used_operations: BTreeSet<String>,
}

impl ClearingBook {
    pub fn new<P: DeFmiPort>(
        authorities: AuthoritySet,
        capitalization: CcpCapitalization,
        defmi: &P,
        now: u64,
    ) -> Result<Self, DeCcpError> {
        authorities.validate()?;
        if capitalization.amount == 0
            || capitalization.defmi_lock_id == ZERO
            || capitalization.proof_digest == ZERO
            || capitalization.valid_until < now
        {
            return Err(DeCcpError::InvalidCapital);
        }
        defmi
            .verify_ccp_capital(&capitalization, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        Ok(Self {
            authorities,
            participants: BTreeMap::new(),
            collateral: BTreeMap::new(),
            margins: BTreeMap::new(),
            cycles: BTreeMap::new(),
            obligations: BTreeMap::new(),
            guarantee_facilities: BTreeMap::new(),
            guarantee_holds: BTreeMap::new(),
            confidential_guarantee_facilities: BTreeMap::new(),
            confidential_guarantee_holds: BTreeMap::new(),
            defaults: BTreeMap::new(),
            ccp_capital_remaining: capitalization.amount,
            ccp_capital_defmi_lock_id: capitalization.defmi_lock_id,
            ccp_capital_proof_digest: capitalization.proof_digest,
            ccp_capital_valid_until: capitalization.valid_until,
            used_operations: BTreeSet::new(),
        })
    }

    pub fn authority_set(&self) -> &AuthoritySet {
        &self.authorities
    }

    pub fn participant(&self, participant_id: &Identifier) -> Option<&Participant> {
        self.participants.get(&id_key(participant_id))
    }

    pub fn margin(&self, participant_id: &Identifier) -> Option<&MarginAccount> {
        self.margins.get(&id_key(participant_id))
    }

    pub fn cycle(&self, cycle_id: &Identifier) -> Option<&NettingCycle> {
        self.cycles.get(&id_key(cycle_id))
    }

    pub fn guarantee_facility(&self, facility_id: &Identifier) -> Option<&GuaranteeFacility> {
        self.guarantee_facilities.get(&id_key(facility_id))
    }

    pub fn guarantee_hold(&self, hold_id: &Identifier) -> Option<&GuaranteeHold> {
        self.guarantee_holds.get(&id_key(hold_id))
    }

    pub fn confidential_guarantee_facility(
        &self,
        facility_id: &Identifier,
    ) -> Option<&ConfidentialGuaranteeFacility> {
        self.confidential_guarantee_facilities
            .get(&id_key(facility_id))
    }

    pub fn confidential_guarantee_hold(
        &self,
        hold_id: &Identifier,
    ) -> Option<&ConfidentialGuaranteeHold> {
        self.confidential_guarantee_holds.get(&id_key(hold_id))
    }

    pub fn default_case(&self, case_id: &Identifier) -> Option<&DefaultCase> {
        self.defaults.get(&id_key(case_id))
    }

    pub fn ccp_capital_remaining(&self) -> u128 {
        self.ccp_capital_remaining
    }

    pub fn ccp_capital_lock(&self) -> (Identifier, Digest32, u64) {
        (
            self.ccp_capital_defmi_lock_id,
            self.ccp_capital_proof_digest,
            self.ccp_capital_valid_until,
        )
    }

    pub fn snapshot(&self) -> ClearingSnapshot {
        ClearingSnapshot {
            authorities: self.authorities.clone(),
            participants: self.participants.clone(),
            collateral: self.collateral.clone(),
            margins: self.margins.clone(),
            cycles: self.cycles.clone(),
            obligations: self.obligations.clone(),
            guarantee_facilities: self.guarantee_facilities.clone(),
            guarantee_holds: self.guarantee_holds.clone(),
            confidential_guarantee_facilities: self.confidential_guarantee_facilities.clone(),
            confidential_guarantee_holds: self.confidential_guarantee_holds.clone(),
            defaults: self.defaults.clone(),
            ccp_capital_remaining: self.ccp_capital_remaining,
            ccp_capital_defmi_lock_id: self.ccp_capital_defmi_lock_id,
            ccp_capital_proof_digest: self.ccp_capital_proof_digest,
            ccp_capital_valid_until: self.ccp_capital_valid_until,
            used_operations: self.used_operations.clone(),
        }
    }

    /// Rebuilds a book from a snapshot. `trusted` is the authority set the
    /// operator already trusts; the snapshot must name the same set, the
    /// approval must be that set's quorum over the snapshot digest, and every
    /// internal invariant must hold. Without all three, restore fails closed.
    pub fn restore(
        trusted: &AuthoritySet,
        snapshot: ClearingSnapshot,
        approval: &QuorumApproval,
    ) -> Result<Self, DeCcpError> {
        trusted.validate()?;
        if &snapshot.authorities != trusted {
            return Err(DeCcpError::InvalidAuthoritySet);
        }
        trusted.verify_archived(&snapshot.digest()?, approval)?;
        Self::restore_authenticated(snapshot)
    }

    /// Rebuilds a book from a snapshot whose authenticity the host has already
    /// established outside DeCCP: a consensus-committed VM state whose root
    /// commits to the snapshot bytes, or a store the host authenticates by
    /// other means. DeCCP still re-runs every structural invariant, so a
    /// tampered or truncated snapshot fails closed; what this route does not
    /// do is demand a separate quorum signature over the snapshot digest.
    /// Storage the host does not authenticate must go through [`Self::restore`].
    pub fn restore_authenticated(snapshot: ClearingSnapshot) -> Result<Self, DeCcpError> {
        let book = Self {
            authorities: snapshot.authorities,
            participants: snapshot.participants,
            collateral: snapshot.collateral,
            margins: snapshot.margins,
            cycles: snapshot.cycles,
            obligations: snapshot.obligations,
            guarantee_facilities: snapshot.guarantee_facilities,
            guarantee_holds: snapshot.guarantee_holds,
            confidential_guarantee_facilities: snapshot.confidential_guarantee_facilities,
            confidential_guarantee_holds: snapshot.confidential_guarantee_holds,
            defaults: snapshot.defaults,
            ccp_capital_remaining: snapshot.ccp_capital_remaining,
            ccp_capital_defmi_lock_id: snapshot.ccp_capital_defmi_lock_id,
            ccp_capital_proof_digest: snapshot.ccp_capital_proof_digest,
            ccp_capital_valid_until: snapshot.ccp_capital_valid_until,
            used_operations: snapshot.used_operations,
        };
        book.validate()?;
        Ok(book)
    }

    /// Structural invariants that every reachable book satisfies. They are
    /// re-checked on restore so persisted input cannot bypass the operations.
    pub fn validate(&self) -> Result<(), DeCcpError> {
        self.authorities.validate()?;
        if self.ccp_capital_defmi_lock_id == ZERO
            || self.ccp_capital_proof_digest == ZERO
            || self.ccp_capital_valid_until == 0
        {
            return Err(DeCcpError::InvalidCapital);
        }
        let mut subject_lines = BTreeSet::new();
        let mut defmi_locks = BTreeSet::from([self.ccp_capital_defmi_lock_id]);
        for (key, participant) in &self.participants {
            if key != &id_key(&participant.participant_id)
                || !self.margins.contains_key(key)
                || !subject_lines.insert(participant.eligibility.subject_line_id)
                || !defmi_locks.insert(participant.default_fund_defmi_lock_id)
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        for key in self.margins.keys() {
            if !self.participants.contains_key(key) {
                return Err(DeCcpError::InvalidState);
            }
        }
        for (key, lot) in &self.collateral {
            if key != &id_key(&lot.lot_id)
                || !self.participants.contains_key(&id_key(&lot.owner_id))
                || !defmi_locks.insert(lot.defmi_lock_id)
            {
                return Err(DeCcpError::InvalidState);
            }
            lot.eligible_value()?;
        }
        for (key, cycle) in &self.cycles {
            let consistent = match cycle.status {
                CycleStatus::Open => {
                    cycle.closed_proposal.is_none() && cycle.defmi_settlement_receipt.is_none()
                }
                CycleStatus::Closed => {
                    cycle.closed_proposal.is_some() && cycle.defmi_settlement_receipt.is_none()
                }
                CycleStatus::Settled => {
                    cycle.closed_proposal.is_some() && cycle.defmi_settlement_receipt.is_some()
                }
            };
            if key != &id_key(&cycle.cycle_id)
                || !consistent
                || cycle.obligations.iter().any(|obligation| {
                    self.obligations
                        .get(&id_key(obligation))
                        .is_none_or(|found| found.cycle_id != cycle.cycle_id)
                })
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        for (key, obligation) in &self.obligations {
            obligation.validate()?;
            if key != &id_key(&obligation.obligation_id)
                || self
                    .cycles
                    .get(&id_key(&obligation.cycle_id))
                    .is_none_or(|cycle| !cycle.obligations.contains(&obligation.obligation_id))
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        let mut facility_ids = BTreeSet::new();
        let mut defmi_holds = BTreeSet::new();
        let mut reserved: BTreeMap<String, u128> = BTreeMap::new();
        let mut consumed: BTreeMap<String, u128> = BTreeMap::new();
        for (key, hold) in &self.guarantee_holds {
            if key != &id_key(&hold.hold_id)
                || !hold_shape_is_consistent(
                    hold.status,
                    hold.bound_exposure_id.is_some(),
                    hold.defmi_settlement_receipt.is_some(),
                )
                || !self
                    .guarantee_facilities
                    .contains_key(&id_key(&hold.facility_id))
                || !defmi_holds.insert(hold.defmi_hold_id)
                || hold.amount == 0
            {
                return Err(DeCcpError::InvalidState);
            }
            let bucket = match hold.status {
                GuaranteeHoldStatus::Reserved | GuaranteeHoldStatus::Bound => &mut reserved,
                GuaranteeHoldStatus::Consumed => &mut consumed,
                GuaranteeHoldStatus::Released => continue,
            };
            let total = bucket.entry(id_key(&hold.facility_id)).or_insert(0);
            *total = total
                .checked_add(hold.amount)
                .ok_or(DeCcpError::ArithmeticOverflow)?;
        }
        for (key, facility) in &self.guarantee_facilities {
            let allocated = facility
                .reserved
                .checked_add(facility.consumed)
                .ok_or(DeCcpError::ArithmeticOverflow)?;
            if key != &id_key(&facility.facility_id)
                || !facility_ids.insert(facility.facility_id)
                || facility.capacity == 0
                || allocated > facility.capacity
                || reserved.get(key).copied().unwrap_or(0) != facility.reserved
                || consumed.get(key).copied().unwrap_or(0) != facility.consumed
                || !self
                    .participants
                    .contains_key(&id_key(&facility.guarantor_id))
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        for (key, facility) in &self.confidential_guarantee_facilities {
            if key != &id_key(&facility.facility_id)
                || !facility_ids.insert(facility.facility_id)
                || facility.capacity_commitment == ZERO
                || facility.latest_facility_state_digest == ZERO
                || !self
                    .participants
                    .contains_key(&id_key(&facility.guarantor_id))
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        for (key, hold) in &self.confidential_guarantee_holds {
            if key != &id_key(&hold.hold_id)
                || !hold_shape_is_consistent(
                    hold.status,
                    hold.bound_exposure_id.is_some(),
                    hold.defmi_settlement_receipt.is_some(),
                )
                || !self
                    .confidential_guarantee_facilities
                    .contains_key(&id_key(&hold.facility_id))
                || !defmi_holds.insert(hold.defmi_hold_id)
                || hold.coverage_commitment == ZERO
                || hold.reserved_state_digest == ZERO
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        for (key, case) in &self.defaults {
            let participant = self
                .participants
                .get(&id_key(&case.evidence.participant_id))
                .ok_or(DeCcpError::InvalidState)?;
            if key != &id_key(&case.case_id)
                || participant.status != ParticipantStatus::Defaulted
                || case.resolution.is_some() != case.defmi_settlement_receipt.is_some()
                || case.resolution.as_ref().is_some_and(|resolution| {
                    resolution.case_id != case.case_id
                        || resolution.participant_id != case.evidence.participant_id
                })
            {
                return Err(DeCcpError::InvalidState);
            }
        }
        if self.used_operations.iter().any(|key| !valid_hex_id(key)) {
            return Err(DeCcpError::InvalidState);
        }
        Ok(())
    }

    pub fn admit_participant<V: EligibilityPort, P: DeFmiPort>(
        &mut self,
        request: ParticipantAdmission,
        verifier: &V,
        approval: &QuorumApproval,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        let statement = request.statement_digest()?;
        self.authorities.verify(&statement, approval, now)?;
        if request.admitted_at != now || self.operation_used(&request.operation_id) {
            return Err(DeCcpError::ReplayOrStaleOperation);
        }
        let verified = verifier
            .verify(&request.eligibility, now)
            .map_err(DeCcpError::EligibilityRejected)?;
        defmi
            .verify_default_fund(&request, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        if verified
            != (VerifiedAdmission {
                provider_id: request.eligibility.provider_id,
                subject_line_id: request.eligibility.subject_line_id,
                policy_digest: request.eligibility.policy_digest,
                evidence_digest: request.eligibility.evidence_digest,
                valid_until: request.eligibility.valid_until,
            })
            || self.participants.values().any(|participant| {
                participant.eligibility.subject_line_id == verified.subject_line_id
            })
        {
            return Err(DeCcpError::EligibilityRejected(
                "verified eligibility does not match or is already admitted".into(),
            ));
        }
        if request.default_fund_defmi_lock_id == self.ccp_capital_defmi_lock_id
            || self.participants.values().any(|participant| {
                participant.default_fund_defmi_lock_id == request.default_fund_defmi_lock_id
            })
            || self
                .collateral
                .values()
                .any(|lot| lot.defmi_lock_id == request.default_fund_defmi_lock_id)
        {
            return Err(DeCcpError::DuplicateDeFmiReference);
        }
        let key = id_key(&request.participant_id);
        if self.participants.contains_key(&key) {
            return Err(DeCcpError::DuplicateParticipant);
        }
        self.participants.insert(
            key.clone(),
            Participant {
                participant_id: request.participant_id,
                settlement_participant_id: request.settlement_participant_id,
                eligibility: request.eligibility,
                default_fund_remaining: request.default_fund_contribution,
                default_fund_defmi_lock_id: request.default_fund_defmi_lock_id,
                default_fund_proof_digest: request.default_fund_proof_digest,
                status: ParticipantStatus::Active,
                admitted_at: now,
            },
        );
        self.margins.insert(key, MarginAccount::default());
        self.consume_operation(&request.operation_id)
    }

    pub fn post_collateral<P: DeFmiPort>(
        &mut self,
        lot: CollateralLot,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        lot.validate()?;
        self.active_participant(&lot.owner_id, now)?;
        defmi
            .verify_collateral_lock(&lot, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        if self.operation_used(&lot.operation_id) {
            return Err(DeCcpError::ReplayOrStaleOperation);
        }
        if lot.valid_until < now {
            return Err(DeCcpError::InvalidCollateral);
        }
        if lot.defmi_lock_id == self.ccp_capital_defmi_lock_id
            || self
                .participants
                .values()
                .any(|participant| participant.default_fund_defmi_lock_id == lot.defmi_lock_id)
            || self
                .collateral
                .values()
                .any(|existing| existing.defmi_lock_id == lot.defmi_lock_id)
            || self.collateral.contains_key(&id_key(&lot.lot_id))
        {
            return Err(DeCcpError::DuplicateDeFmiReference);
        }
        let operation = lot.operation_id;
        self.collateral.insert(id_key(&lot.lot_id), lot);
        self.consume_operation(&operation)
    }

    pub fn set_margin(
        &mut self,
        request: MarginUpdate,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), DeCcpError> {
        self.active_participant(&request.participant_id, now)?;
        if request.operation_id == ZERO
            || request.initial_margin == 0
            || self.operation_used(&request.operation_id)
        {
            return Err(DeCcpError::InvalidMargin);
        }
        let statement = request.statement_digest();
        self.authorities.verify(&statement, approval, now)?;
        let required = request
            .initial_margin
            .checked_add(request.variation_margin)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        if self.eligible_collateral(&request.participant_id, now)? < required {
            return Err(DeCcpError::InsufficientCollateral);
        }
        let account = self
            .margins
            .get_mut(&id_key(&request.participant_id))
            .ok_or(DeCcpError::UnknownParticipant)?;
        if account.sequence != request.expected_sequence {
            return Err(DeCcpError::StaleSequence);
        }
        account.initial_margin = request.initial_margin;
        account.variation_margin = request.variation_margin;
        account.encumbered_collateral = required;
        account.sequence = account
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        self.consume_operation(&request.operation_id)
    }

    pub fn open_cycle(
        &mut self,
        request: OpenCycleRequest,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            request.operation_id,
            request.cycle_id,
            request.settlement_asset_id,
            request.policy_digest,
        ]
        .contains(&ZERO)
            || request.opened_at == 0
            || request.opened_at != now
            || self.operation_used(&request.operation_id)
            || self.cycles.contains_key(&id_key(&request.cycle_id))
        {
            return Err(DeCcpError::InvalidCycle);
        }
        let statement = request.statement_digest();
        self.authorities.verify(&statement, approval, now)?;
        self.cycles.insert(
            id_key(&request.cycle_id),
            NettingCycle {
                cycle_id: request.cycle_id,
                mode: request.mode,
                settlement_asset_id: request.settlement_asset_id,
                policy_digest: request.policy_digest,
                status: CycleStatus::Open,
                opened_at: request.opened_at,
                obligations: Vec::new(),
                closed_proposal: None,
                defmi_settlement_receipt: None,
            },
        );
        self.consume_operation(&request.operation_id)
    }

    pub fn submit_obligation<P: InstructionPort>(
        &mut self,
        obligation: ClearingObligation,
        instructions: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        obligation.validate()?;
        self.active_participant(&obligation.payer_id, now)?;
        self.active_participant(&obligation.payee_id, now)?;
        instructions
            .verify_obligation(&obligation, now)
            .map_err(DeCcpError::InstructionRejected)?;
        if self.operation_used(&obligation.operation_id)
            || self
                .obligations
                .contains_key(&id_key(&obligation.obligation_id))
        {
            return Err(DeCcpError::DuplicateObligation);
        }
        let cycle = self
            .cycles
            .get_mut(&id_key(&obligation.cycle_id))
            .ok_or(DeCcpError::UnknownCycle)?;
        if cycle.status != CycleStatus::Open {
            return Err(DeCcpError::CycleNotOpen);
        }
        cycle.obligations.push(obligation.obligation_id);
        let operation = obligation.operation_id;
        self.obligations
            .insert(id_key(&obligation.obligation_id), obligation);
        self.consume_operation(&operation)
    }

    pub fn prepare_close(&self, cycle_id: &Identifier) -> Result<NettingProposal, DeCcpError> {
        let cycle = self
            .cycles
            .get(&id_key(cycle_id))
            .ok_or(DeCcpError::UnknownCycle)?;
        if cycle.status != CycleStatus::Open || cycle.obligations.is_empty() {
            return Err(DeCcpError::CycleNotOpen);
        }
        let mut obligations = cycle
            .obligations
            .iter()
            .map(|id| {
                self.obligations
                    .get(&id_key(id))
                    .ok_or(DeCcpError::InvalidState)
            })
            .collect::<Result<Vec<_>, _>>()?;
        obligations.sort_by_key(|obligation| obligation.obligation_id);
        let obligation_root = obligation_root(&obligations)?;
        let mut positions: BTreeMap<(Identifier, Identifier), i128> = BTreeMap::new();
        let mut risks: BTreeMap<Identifier, i128> = BTreeMap::new();
        let mut gross_risk_debits: BTreeMap<Identifier, u128> = BTreeMap::new();
        let mut legs = Vec::new();
        for obligation in &obligations {
            let amount =
                i128::try_from(obligation.amount).map_err(|_| DeCcpError::ArithmeticOverflow)?;
            let risk = i128::try_from(obligation.risk_value)
                .map_err(|_| DeCcpError::ArithmeticOverflow)?;
            let asset_is_net = match cycle.mode {
                NettingMode::GrossGross => false,
                NettingMode::GrossNet => obligation.asset_id == cycle.settlement_asset_id,
                NettingMode::NetNet => true,
            };
            if asset_is_net {
                checked_position_add(
                    &mut positions,
                    (obligation.asset_id, obligation.payer_id),
                    -amount,
                )?;
                checked_position_add(
                    &mut positions,
                    (obligation.asset_id, obligation.payee_id),
                    amount,
                )?;
            } else {
                legs.push(ClearingLeg {
                    payer_id: obligation.payer_id,
                    payee_id: obligation.payee_id,
                    asset_id: obligation.asset_id,
                    amount: obligation.amount,
                    instruction_context_digest: clearing_leg_context(
                        cycle_id,
                        &obligation.payer_id,
                        &obligation.payee_id,
                        &obligation.asset_id,
                        obligation.amount,
                        &obligation_root,
                    ),
                });
            }
            if cycle.mode == NettingMode::GrossGross {
                let entry = gross_risk_debits.entry(obligation.payer_id).or_insert(0);
                *entry = entry
                    .checked_add(obligation.risk_value)
                    .ok_or(DeCcpError::ArithmeticOverflow)?;
            } else {
                checked_risk_add(&mut risks, obligation.payer_id, -risk)?;
                checked_risk_add(&mut risks, obligation.payee_id, risk)?;
            }
        }
        let assets: BTreeSet<Identifier> = positions.keys().map(|(asset, _)| *asset).collect();
        for asset in assets {
            let mut debtors: Vec<(Identifier, u128)> = positions
                .iter()
                .filter(|((candidate, _), value)| *candidate == asset && **value < 0)
                .map(|((_, participant), value)| Ok((*participant, value.unsigned_abs())))
                .collect::<Result<Vec<_>, DeCcpError>>()?;
            let mut creditors: Vec<(Identifier, u128)> = positions
                .iter()
                .filter(|((candidate, _), value)| *candidate == asset && **value > 0)
                .map(|((_, participant), value)| {
                    u128::try_from(*value)
                        .map(|amount| (*participant, amount))
                        .map_err(|_| DeCcpError::ArithmeticOverflow)
                })
                .collect::<Result<Vec<_>, DeCcpError>>()?;
            let total_debit = debtors.iter().try_fold(0_u128, |sum, (_, amount)| {
                sum.checked_add(*amount)
                    .ok_or(DeCcpError::ArithmeticOverflow)
            })?;
            let total_credit = creditors.iter().try_fold(0_u128, |sum, (_, amount)| {
                sum.checked_add(*amount)
                    .ok_or(DeCcpError::ArithmeticOverflow)
            })?;
            if total_debit != total_credit {
                return Err(DeCcpError::ConservationFailure);
            }
            let (mut debit_at, mut credit_at) = (0usize, 0usize);
            while debit_at < debtors.len() && credit_at < creditors.len() {
                let amount = debtors[debit_at].1.min(creditors[credit_at].1);
                let payer = debtors[debit_at].0;
                let payee = creditors[credit_at].0;
                legs.push(ClearingLeg {
                    payer_id: payer,
                    payee_id: payee,
                    asset_id: asset,
                    amount,
                    instruction_context_digest: clearing_leg_context(
                        cycle_id,
                        &payer,
                        &payee,
                        &asset,
                        amount,
                        &obligation_root,
                    ),
                });
                debtors[debit_at].1 -= amount;
                creditors[credit_at].1 -= amount;
                if debtors[debit_at].1 == 0 {
                    debit_at += 1;
                }
                if creditors[credit_at].1 == 0 {
                    credit_at += 1;
                }
            }
        }
        let risk_debits_by_id = if cycle.mode == NettingMode::GrossGross {
            gross_risk_debits
        } else {
            risks
                .into_iter()
                .filter_map(|(participant, risk)| {
                    (risk < 0).then_some((participant, risk.unsigned_abs()))
                })
                .collect()
        };
        let mut risk_debits = BTreeMap::new();
        for (participant, debit) in risk_debits_by_id {
            let margin = self
                .margins
                .get(&id_key(&participant))
                .ok_or(DeCcpError::UnknownParticipant)?;
            if margin.encumbered_collateral < debit {
                return Err(DeCcpError::InsufficientMargin);
            }
            risk_debits.insert(id_key(&participant), debit);
        }
        let proposal_digest =
            netting_proposal_digest(cycle_id, cycle.mode, &obligation_root, &legs, &risk_debits);
        Ok(NettingProposal {
            cycle_id: *cycle_id,
            mode: cycle.mode,
            obligation_root,
            legs,
            risk_debits,
            proposal_digest,
        })
    }

    pub fn commit_close(
        &mut self,
        proposal: NettingProposal,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), DeCcpError> {
        self.authorities
            .verify(&proposal.proposal_digest, approval, now)?;
        if self.prepare_close(&proposal.cycle_id)? != proposal {
            return Err(DeCcpError::InvalidNettingProposal);
        }
        let cycle = self
            .cycles
            .get_mut(&id_key(&proposal.cycle_id))
            .ok_or(DeCcpError::UnknownCycle)?;
        cycle.status = CycleStatus::Closed;
        cycle.closed_proposal = Some(proposal);
        Ok(())
    }

    pub fn record_cycle_settlement<P: DeFmiPort>(
        &mut self,
        cycle_id: &Identifier,
        proposal_digest: Digest32,
        receipt: DefmiSettlementReceipt,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if receipt.receipt_digest == ZERO || receipt.context_digest != proposal_digest {
            return Err(DeCcpError::InvalidSettlementReceipt);
        }
        defmi
            .verify_settlement(&proposal_digest, &receipt, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let cycle = self
            .cycles
            .get_mut(&id_key(cycle_id))
            .ok_or(DeCcpError::UnknownCycle)?;
        if cycle.status != CycleStatus::Closed
            || cycle
                .closed_proposal
                .as_ref()
                .map(|proposal| proposal.proposal_digest)
                != Some(proposal_digest)
        {
            return Err(DeCcpError::InvalidSettlementReceipt);
        }
        cycle.status = CycleStatus::Settled;
        cycle.defmi_settlement_receipt = Some(receipt.receipt_digest);
        Ok(())
    }

    pub fn register_guarantee_facility<P: DeFmiPort>(
        &mut self,
        operation_id: Identifier,
        facility: GuaranteeFacility,
        approval: &QuorumApproval,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            operation_id,
            facility.facility_id,
            facility.guarantor_id,
            facility.beneficiary_subject_line_id,
            facility.settlement_asset_id,
            facility.defmi_facility_id,
            facility.policy_digest,
        ]
        .contains(&ZERO)
            || facility.capacity == 0
            || facility.reserved != 0
            || facility.consumed != 0
            || facility.sequence != 0
            || facility.valid_until < now
            || facility.status != GuaranteeFacilityStatus::Active
            || self.operation_used(&operation_id)
            || self
                .guarantee_facilities
                .contains_key(&id_key(&facility.facility_id))
            || self
                .confidential_guarantee_facilities
                .contains_key(&id_key(&facility.facility_id))
        {
            return Err(DeCcpError::InvalidGuaranteeFacility);
        }
        self.active_participant(&facility.guarantor_id, now)?;
        defmi
            .verify_guarantee_facility(&facility, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let statement = guarantee_facility_statement(&operation_id, &facility);
        self.authorities.verify(&statement, approval, now)?;
        self.guarantee_facilities
            .insert(id_key(&facility.facility_id), facility);
        self.consume_operation(&operation_id)
    }

    pub fn reserve_guarantee<P: DeFmiPort>(
        &mut self,
        request: GuaranteeReservation,
        defmi: &P,
        now: u64,
    ) -> Result<GuaranteeHold, DeCcpError> {
        if [
            request.operation_id,
            request.hold_id,
            request.facility_id,
            request.purpose_digest,
            request.defmi_hold_id,
            request.relation_proof_digest,
        ]
        .contains(&ZERO)
            || request.amount == 0
            || request.valid_until < now
            || self.operation_used(&request.operation_id)
            || self.guarantee_holds.contains_key(&id_key(&request.hold_id))
            || self
                .confidential_guarantee_holds
                .contains_key(&id_key(&request.hold_id))
            || self
                .guarantee_holds
                .values()
                .any(|hold| hold.defmi_hold_id == request.defmi_hold_id)
            || self
                .confidential_guarantee_holds
                .values()
                .any(|hold| hold.defmi_hold_id == request.defmi_hold_id)
        {
            return Err(DeCcpError::InvalidGuaranteeReservation);
        }
        let guarantor_id = self
            .guarantee_facilities
            .get(&id_key(&request.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?
            .guarantor_id;
        self.active_participant(&guarantor_id, now)?;
        defmi
            .verify_guarantee_hold(&request, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let facility = self
            .guarantee_facilities
            .get_mut(&id_key(&request.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        if facility.status != GuaranteeFacilityStatus::Active
            || facility.valid_until < request.valid_until
            || facility.sequence != request.expected_facility_sequence
        {
            return Err(DeCcpError::StaleSequence);
        }
        let allocated = facility
            .reserved
            .checked_add(facility.consumed)
            .and_then(|value| value.checked_add(request.amount))
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        if allocated > facility.capacity {
            return Err(DeCcpError::GuaranteeCapacityExceeded);
        }
        facility.reserved = facility
            .reserved
            .checked_add(request.amount)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        let hold = GuaranteeHold {
            hold_id: request.hold_id,
            facility_id: request.facility_id,
            purpose_digest: request.purpose_digest,
            amount: request.amount,
            defmi_hold_id: request.defmi_hold_id,
            relation_proof_digest: request.relation_proof_digest,
            valid_until: request.valid_until,
            status: GuaranteeHoldStatus::Reserved,
            bound_exposure_id: None,
            defmi_settlement_receipt: None,
        };
        self.guarantee_holds
            .insert(id_key(&hold.hold_id), hold.clone());
        self.consume_operation(&request.operation_id)?;
        Ok(hold)
    }

    pub fn bind_guarantee(
        &mut self,
        operation_id: Identifier,
        hold_id: Identifier,
        exposure_id: Identifier,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [operation_id, hold_id, exposure_id].contains(&ZERO)
            || self.operation_used(&operation_id)
        {
            return Err(DeCcpError::InvalidGuaranteeReservation);
        }
        let hold = self
            .guarantee_holds
            .get_mut(&id_key(&hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        if hold.status != GuaranteeHoldStatus::Reserved || hold.valid_until < now {
            return Err(DeCcpError::GuaranteeHoldUnavailable);
        }
        hold.status = GuaranteeHoldStatus::Bound;
        hold.bound_exposure_id = Some(exposure_id);
        self.consume_operation(&operation_id)
    }

    pub fn release_guarantee<P: DeFmiPort>(
        &mut self,
        operation_id: Identifier,
        hold_id: Identifier,
        receipt: DefmiSettlementReceipt,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        let expected_context = guarantee_release_context(&hold_id);
        if operation_id == ZERO
            || receipt.receipt_digest == ZERO
            || receipt.context_digest != expected_context
            || self.operation_used(&operation_id)
        {
            return Err(DeCcpError::ReplayOrStaleOperation);
        }
        defmi
            .verify_guarantee_release(&expected_context, &receipt, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let hold = self
            .guarantee_holds
            .get_mut(&id_key(&hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        if !matches!(
            hold.status,
            GuaranteeHoldStatus::Reserved | GuaranteeHoldStatus::Bound
        ) {
            return Err(DeCcpError::GuaranteeHoldUnavailable);
        }
        let facility = self
            .guarantee_facilities
            .get_mut(&id_key(&hold.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        facility.reserved = facility
            .reserved
            .checked_sub(hold.amount)
            .ok_or(DeCcpError::InvalidState)?;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        hold.status = GuaranteeHoldStatus::Released;
        hold.defmi_settlement_receipt = Some(receipt.receipt_digest);
        self.consume_operation(&operation_id)
    }

    pub fn consume_guarantee<P: DeFmiPort>(
        &mut self,
        request: GuaranteeClaimRequest,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            request.operation_id,
            request.hold_id,
            request.exposure_id,
            request.default_event_digest,
            request.receipt.receipt_digest,
        ]
        .contains(&ZERO)
            || self.operation_used(&request.operation_id)
        {
            return Err(DeCcpError::InvalidGuaranteeClaim);
        }
        let expected_context = guarantee_claim_context(
            &request.hold_id,
            &request.exposure_id,
            &request.default_event_digest,
        );
        if request.receipt.context_digest != expected_context {
            return Err(DeCcpError::InvalidGuaranteeClaim);
        }
        defmi
            .verify_settlement(&expected_context, &request.receipt, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let hold = self
            .guarantee_holds
            .get_mut(&id_key(&request.hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        if hold.status != GuaranteeHoldStatus::Bound
            || hold.bound_exposure_id != Some(request.exposure_id)
            || hold.valid_until < now
        {
            return Err(DeCcpError::GuaranteeHoldUnavailable);
        }
        let facility = self
            .guarantee_facilities
            .get_mut(&id_key(&hold.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        facility.reserved = facility
            .reserved
            .checked_sub(hold.amount)
            .ok_or(DeCcpError::InvalidState)?;
        facility.consumed = facility
            .consumed
            .checked_add(hold.amount)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        if facility.consumed == facility.capacity {
            facility.status = GuaranteeFacilityStatus::Exhausted;
        }
        hold.status = GuaranteeHoldStatus::Consumed;
        hold.defmi_settlement_receipt = Some(request.receipt.receipt_digest);
        self.consume_operation(&request.operation_id)
    }

    pub fn register_confidential_guarantee_facility<P: DeFmiPort>(
        &mut self,
        operation_id: Identifier,
        facility: ConfidentialGuaranteeFacility,
        approval: &QuorumApproval,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            operation_id,
            facility.facility_id,
            facility.guarantor_id,
            facility.beneficiary_subject_line_id,
            facility.settlement_asset_id,
            facility.capacity_commitment,
            facility.latest_facility_state_digest,
            facility.defmi_facility_id,
            facility.policy_digest,
        ]
        .contains(&ZERO)
            || facility.sequence != 0
            || facility.valid_until < now
            || facility.status != GuaranteeFacilityStatus::Active
            || self.operation_used(&operation_id)
            || self
                .guarantee_facilities
                .contains_key(&id_key(&facility.facility_id))
            || self
                .confidential_guarantee_facilities
                .contains_key(&id_key(&facility.facility_id))
        {
            return Err(DeCcpError::InvalidGuaranteeFacility);
        }
        self.active_participant(&facility.guarantor_id, now)?;
        defmi
            .verify_confidential_guarantee_facility(&facility, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let statement = confidential_guarantee_facility_statement(&operation_id, &facility);
        self.authorities.verify(&statement, approval, now)?;
        self.confidential_guarantee_facilities
            .insert(id_key(&facility.facility_id), facility);
        self.consume_operation(&operation_id)
    }

    /// Reserves hidden guarantee capacity using a DeFMI-verified commitment
    /// transition. The sequence and state digest form a compare-and-swap, so
    /// concurrent reservations cannot both consume the same capacity state.
    pub fn reserve_confidential_guarantee<P: DeFmiPort>(
        &mut self,
        request: ConfidentialGuaranteeReservation,
        defmi: &P,
        now: u64,
    ) -> Result<ConfidentialGuaranteeHold, DeCcpError> {
        if [
            request.operation_id,
            request.hold_id,
            request.facility_id,
            request.purpose_digest,
            request.coverage_commitment,
            request.defmi_hold_id,
            request.relation_proof_digest,
            request.expected_facility_state_digest,
            request.after_facility_state_digest,
        ]
        .contains(&ZERO)
            || request.expected_facility_state_digest == request.after_facility_state_digest
            || request.valid_until < now
            || self.operation_used(&request.operation_id)
            || self.guarantee_holds.contains_key(&id_key(&request.hold_id))
            || self
                .confidential_guarantee_holds
                .contains_key(&id_key(&request.hold_id))
            || self
                .guarantee_holds
                .values()
                .any(|hold| hold.defmi_hold_id == request.defmi_hold_id)
            || self
                .confidential_guarantee_holds
                .values()
                .any(|hold| hold.defmi_hold_id == request.defmi_hold_id)
        {
            return Err(DeCcpError::InvalidGuaranteeReservation);
        }
        let facility = self
            .confidential_guarantee_facilities
            .get(&id_key(&request.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        if facility.status != GuaranteeFacilityStatus::Active
            || facility.valid_until < request.valid_until
            || facility.sequence != request.expected_facility_sequence
            || facility.latest_facility_state_digest != request.expected_facility_state_digest
        {
            return Err(DeCcpError::StaleSequence);
        }
        self.active_participant(&facility.guarantor_id, now)?;
        defmi
            .verify_confidential_guarantee_hold(facility, &request, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let facility = self
            .confidential_guarantee_facilities
            .get_mut(&id_key(&request.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        facility.latest_facility_state_digest = request.after_facility_state_digest;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        let hold = ConfidentialGuaranteeHold {
            hold_id: request.hold_id,
            facility_id: request.facility_id,
            purpose_digest: request.purpose_digest,
            coverage_commitment: request.coverage_commitment,
            defmi_hold_id: request.defmi_hold_id,
            relation_proof_digest: request.relation_proof_digest,
            reserved_state_digest: request.after_facility_state_digest,
            valid_until: request.valid_until,
            status: GuaranteeHoldStatus::Reserved,
            bound_exposure_id: None,
            defmi_settlement_receipt: None,
        };
        self.confidential_guarantee_holds
            .insert(id_key(&hold.hold_id), hold.clone());
        self.consume_operation(&request.operation_id)?;
        Ok(hold)
    }

    pub fn bind_confidential_guarantee(
        &mut self,
        operation_id: Identifier,
        hold_id: Identifier,
        exposure_id: Identifier,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [operation_id, hold_id, exposure_id].contains(&ZERO)
            || self.operation_used(&operation_id)
        {
            return Err(DeCcpError::InvalidGuaranteeReservation);
        }
        let hold = self
            .confidential_guarantee_holds
            .get_mut(&id_key(&hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        if hold.status != GuaranteeHoldStatus::Reserved || hold.valid_until < now {
            return Err(DeCcpError::GuaranteeHoldUnavailable);
        }
        hold.status = GuaranteeHoldStatus::Bound;
        hold.bound_exposure_id = Some(exposure_id);
        self.consume_operation(&operation_id)
    }

    pub fn release_confidential_guarantee<P: DeFmiPort>(
        &mut self,
        request: ConfidentialGuaranteeReleaseRequest,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            request.operation_id,
            request.hold_id,
            request.expected_facility_state_digest,
            request.after_facility_state_digest,
            request.transition_proof_digest,
            request.receipt.receipt_digest,
        ]
        .contains(&ZERO)
            || request.expected_facility_state_digest == request.after_facility_state_digest
            || self.operation_used(&request.operation_id)
            || request.receipt.context_digest != confidential_guarantee_release_context(&request)
        {
            return Err(DeCcpError::ReplayOrStaleOperation);
        }
        let hold = self
            .confidential_guarantee_holds
            .get(&id_key(&request.hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        if !matches!(
            hold.status,
            GuaranteeHoldStatus::Reserved | GuaranteeHoldStatus::Bound
        ) {
            return Err(DeCcpError::GuaranteeHoldUnavailable);
        }
        let facility = self
            .confidential_guarantee_facilities
            .get(&id_key(&hold.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        if facility.sequence != request.expected_facility_sequence
            || facility.latest_facility_state_digest != request.expected_facility_state_digest
        {
            return Err(DeCcpError::StaleSequence);
        }
        defmi
            .verify_confidential_guarantee_release(facility, hold, &request, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let facility = self
            .confidential_guarantee_facilities
            .get_mut(&id_key(&hold.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        facility.latest_facility_state_digest = request.after_facility_state_digest;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        let hold = self
            .confidential_guarantee_holds
            .get_mut(&id_key(&request.hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        hold.status = GuaranteeHoldStatus::Released;
        hold.defmi_settlement_receipt = Some(request.receipt.receipt_digest);
        self.consume_operation(&request.operation_id)
    }

    pub fn consume_confidential_guarantee<P: DeFmiPort>(
        &mut self,
        request: ConfidentialGuaranteeClaimRequest,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            request.operation_id,
            request.hold_id,
            request.exposure_id,
            request.default_event_digest,
            request.expected_facility_state_digest,
            request.after_facility_state_digest,
            request.transition_proof_digest,
            request.receipt.receipt_digest,
        ]
        .contains(&ZERO)
            || request.expected_facility_state_digest == request.after_facility_state_digest
            || self.operation_used(&request.operation_id)
            || request.receipt.context_digest != confidential_guarantee_claim_context(&request)
        {
            return Err(DeCcpError::InvalidGuaranteeClaim);
        }
        let hold = self
            .confidential_guarantee_holds
            .get(&id_key(&request.hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        if hold.status != GuaranteeHoldStatus::Bound
            || hold.bound_exposure_id != Some(request.exposure_id)
            || hold.valid_until < now
        {
            return Err(DeCcpError::GuaranteeHoldUnavailable);
        }
        let facility = self
            .confidential_guarantee_facilities
            .get(&id_key(&hold.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        if facility.sequence != request.expected_facility_sequence
            || facility.latest_facility_state_digest != request.expected_facility_state_digest
        {
            return Err(DeCcpError::StaleSequence);
        }
        defmi
            .verify_confidential_guarantee_claim(facility, hold, &request, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        let facility = self
            .confidential_guarantee_facilities
            .get_mut(&id_key(&hold.facility_id))
            .ok_or(DeCcpError::UnknownGuaranteeFacility)?;
        facility.latest_facility_state_digest = request.after_facility_state_digest;
        facility.sequence = facility
            .sequence
            .checked_add(1)
            .ok_or(DeCcpError::ArithmeticOverflow)?;
        let hold = self
            .confidential_guarantee_holds
            .get_mut(&id_key(&request.hold_id))
            .ok_or(DeCcpError::UnknownGuaranteeHold)?;
        hold.status = GuaranteeHoldStatus::Consumed;
        hold.defmi_settlement_receipt = Some(request.receipt.receipt_digest);
        self.consume_operation(&request.operation_id)
    }

    pub fn declare_default(
        &mut self,
        operation_id: Identifier,
        case_id: Identifier,
        evidence: DefaultEvidence,
        approval: &QuorumApproval,
        now: u64,
    ) -> Result<(), DeCcpError> {
        if [
            operation_id,
            case_id,
            evidence.event_id,
            evidence.source_id,
            evidence.participant_id,
            evidence.event_digest,
        ]
        .contains(&ZERO)
            || evidence.observed_at > now
            || self.operation_used(&operation_id)
            || self.defaults.contains_key(&id_key(&case_id))
        {
            return Err(DeCcpError::InvalidDefault);
        }
        self.active_participant(&evidence.participant_id, now)?;
        let statement = digest_fields(
            b"DECCP:DECLARE-DEFAULT:v1",
            &[
                &operation_id,
                &case_id,
                &evidence.event_id,
                &evidence.source_id,
                &evidence.participant_id,
                &evidence.event_digest,
                &evidence.observed_at.to_be_bytes(),
                &now.to_be_bytes(),
            ],
        );
        self.authorities.verify(&statement, approval, now)?;
        self.participants
            .get_mut(&id_key(&evidence.participant_id))
            .ok_or(DeCcpError::UnknownParticipant)?
            .status = ParticipantStatus::Defaulted;
        self.defaults.insert(
            id_key(&case_id),
            DefaultCase {
                case_id,
                evidence,
                declared_at: now,
                resolution: None,
                defmi_settlement_receipt: None,
            },
        );
        self.consume_operation(&operation_id)
    }

    pub fn prepare_default_resolution(
        &self,
        case_id: &Identifier,
        shortfall: u128,
    ) -> Result<DefaultResolution, DeCcpError> {
        if shortfall == 0 {
            return Err(DeCcpError::InvalidDefault);
        }
        let case = self
            .defaults
            .get(&id_key(case_id))
            .ok_or(DeCcpError::UnknownDefault)?;
        if case.resolution.is_some() {
            return Err(DeCcpError::DefaultAlreadyResolved);
        }
        if self.ccp_capital_valid_until < case.declared_at {
            return Err(DeCcpError::InvalidCapital);
        }
        let participant = case.evidence.participant_id;
        let mut remaining = shortfall;
        let mut draws = Vec::new();
        let margin = self
            .margins
            .get(&id_key(&participant))
            .ok_or(DeCcpError::UnknownParticipant)?
            .encumbered_collateral;
        draw_layer(
            &mut draws,
            DefaultSourceKind::DefaulterMargin,
            Some(participant),
            margin,
            &mut remaining,
        );
        let own_fund = self
            .participants
            .get(&id_key(&participant))
            .ok_or(DeCcpError::UnknownParticipant)?
            .default_fund_remaining;
        draw_layer(
            &mut draws,
            DefaultSourceKind::DefaulterFund,
            Some(participant),
            own_fund,
            &mut remaining,
        );
        for member in self.participants.values() {
            if member.participant_id != participant && member.status == ParticipantStatus::Active {
                draw_layer(
                    &mut draws,
                    DefaultSourceKind::MutualizedFund,
                    Some(member.participant_id),
                    member.default_fund_remaining,
                    &mut remaining,
                );
            }
        }
        draw_layer(
            &mut draws,
            DefaultSourceKind::CcpCapital,
            None,
            self.ccp_capital_remaining,
            &mut remaining,
        );
        if remaining != 0 {
            return Err(DeCcpError::WaterfallExhausted);
        }
        let settlement_context_digest = default_settlement_context(case_id, &draws);
        let resolution_digest = default_resolution_digest(
            case_id,
            &participant,
            shortfall,
            &draws,
            &settlement_context_digest,
        );
        Ok(DefaultResolution {
            case_id: *case_id,
            participant_id: participant,
            shortfall,
            draws,
            settlement_context_digest,
            resolution_digest,
        })
    }

    pub fn commit_default_resolution<P: DeFmiPort>(
        &mut self,
        resolution: DefaultResolution,
        approval: &QuorumApproval,
        receipt: DefmiSettlementReceipt,
        defmi: &P,
        now: u64,
    ) -> Result<(), DeCcpError> {
        self.authorities
            .verify(&resolution.resolution_digest, approval, now)?;
        if self.prepare_default_resolution(&resolution.case_id, resolution.shortfall)? != resolution
            || receipt.receipt_digest == ZERO
            || receipt.context_digest != resolution.settlement_context_digest
            || self.ccp_capital_valid_until < now
        {
            return Err(DeCcpError::InvalidDefaultResolution);
        }
        defmi
            .verify_settlement(&resolution.settlement_context_digest, &receipt, now)
            .map_err(DeCcpError::DeFmiEvidenceRejected)?;
        for draw in &resolution.draws {
            match draw.source_kind {
                DefaultSourceKind::DefaulterMargin => {
                    let participant = draw.participant_id.ok_or(DeCcpError::InvalidState)?;
                    let margin = self
                        .margins
                        .get_mut(&id_key(&participant))
                        .ok_or(DeCcpError::UnknownParticipant)?;
                    margin.encumbered_collateral = margin
                        .encumbered_collateral
                        .checked_sub(draw.amount)
                        .ok_or(DeCcpError::InvalidState)?;
                }
                DefaultSourceKind::DefaulterFund | DefaultSourceKind::MutualizedFund => {
                    let participant = draw.participant_id.ok_or(DeCcpError::InvalidState)?;
                    let member = self
                        .participants
                        .get_mut(&id_key(&participant))
                        .ok_or(DeCcpError::UnknownParticipant)?;
                    member.default_fund_remaining = member
                        .default_fund_remaining
                        .checked_sub(draw.amount)
                        .ok_or(DeCcpError::InvalidState)?;
                }
                DefaultSourceKind::CcpCapital => {
                    self.ccp_capital_remaining = self
                        .ccp_capital_remaining
                        .checked_sub(draw.amount)
                        .ok_or(DeCcpError::InvalidState)?;
                }
            }
        }
        let case_id = resolution.case_id;
        let case = self
            .defaults
            .get_mut(&id_key(&case_id))
            .ok_or(DeCcpError::UnknownDefault)?;
        case.resolution = Some(resolution);
        case.defmi_settlement_receipt = Some(receipt.receipt_digest);
        Ok(())
    }

    fn active_participant(
        &self,
        participant_id: &Identifier,
        now: u64,
    ) -> Result<&Participant, DeCcpError> {
        let participant = self
            .participants
            .get(&id_key(participant_id))
            .ok_or(DeCcpError::UnknownParticipant)?;
        if participant.status != ParticipantStatus::Active
            || participant.eligibility.valid_until < now
        {
            return Err(DeCcpError::ParticipantNotActive);
        }
        Ok(participant)
    }

    fn eligible_collateral(
        &self,
        participant_id: &Identifier,
        now: u64,
    ) -> Result<u128, DeCcpError> {
        self.collateral
            .values()
            .filter(|lot| {
                lot.owner_id == *participant_id
                    && lot.status == CollateralStatus::Available
                    && lot.valid_until >= now
            })
            .try_fold(0_u128, |sum, lot| {
                sum.checked_add(lot.eligible_value()?)
                    .ok_or(DeCcpError::ArithmeticOverflow)
            })
    }

    fn operation_used(&self, operation: &Identifier) -> bool {
        self.used_operations.contains(&id_key(operation))
    }

    fn consume_operation(&mut self, operation: &Identifier) -> Result<(), DeCcpError> {
        if *operation == ZERO || !self.used_operations.insert(id_key(operation)) {
            return Err(DeCcpError::ReplayOrStaleOperation);
        }
        Ok(())
    }
}

fn hold_shape_is_consistent(status: GuaranteeHoldStatus, bound: bool, receipted: bool) -> bool {
    match status {
        GuaranteeHoldStatus::Reserved => !bound && !receipted,
        GuaranteeHoldStatus::Bound => bound && !receipted,
        GuaranteeHoldStatus::Consumed => bound && receipted,
        GuaranteeHoldStatus::Released => receipted,
    }
}

fn valid_hex_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checked_position_add(
    positions: &mut BTreeMap<(Identifier, Identifier), i128>,
    key: (Identifier, Identifier),
    delta: i128,
) -> Result<(), DeCcpError> {
    let next = positions
        .get(&key)
        .copied()
        .unwrap_or(0)
        .checked_add(delta)
        .ok_or(DeCcpError::ArithmeticOverflow)?;
    positions.insert(key, next);
    Ok(())
}

fn checked_risk_add(
    risks: &mut BTreeMap<Identifier, i128>,
    participant: Identifier,
    delta: i128,
) -> Result<(), DeCcpError> {
    let next = risks
        .get(&participant)
        .copied()
        .unwrap_or(0)
        .checked_add(delta)
        .ok_or(DeCcpError::ArithmeticOverflow)?;
    risks.insert(participant, next);
    Ok(())
}

fn obligation_root(obligations: &[&ClearingObligation]) -> Result<Digest32, DeCcpError> {
    let mut leaves = obligations
        .iter()
        .map(|obligation| {
            obligation.validate()?;
            Ok(digest_fields(
                b"DECCP:OBLIGATION:v1",
                &[
                    &obligation.operation_id,
                    &obligation.obligation_id,
                    &obligation.cycle_id,
                    &obligation.payer_id,
                    &obligation.payee_id,
                    &obligation.asset_id,
                    &obligation.amount.to_be_bytes(),
                    &obligation.risk_value.to_be_bytes(),
                    &obligation.zkpi_digest,
                ],
            ))
        })
        .collect::<Result<Vec<_>, DeCcpError>>()?;
    leaves.sort_unstable();
    let mut hash = Sha256::new();
    hash.update(b"DECCP:OBLIGATION-ROOT:v1");
    hash.update((leaves.len() as u32).to_be_bytes());
    for leaf in leaves {
        hash.update(leaf);
    }
    Ok(hash.finalize().into())
}

fn clearing_leg_context(
    cycle_id: &Identifier,
    payer_id: &Identifier,
    payee_id: &Identifier,
    asset_id: &Identifier,
    amount: u128,
    obligation_root: &Digest32,
) -> Digest32 {
    digest_fields(
        b"DECCP:ZKPI-CONTEXT:v1",
        &[
            cycle_id,
            payer_id,
            payee_id,
            asset_id,
            &amount.to_be_bytes(),
            obligation_root,
        ],
    )
}

pub fn guarantee_claim_context(
    hold_id: &Identifier,
    exposure_id: &Identifier,
    default_event_digest: &Digest32,
) -> Digest32 {
    digest_fields(
        b"DECCP:GUARANTEE-CLAIM-CONTEXT:v1",
        &[hold_id, exposure_id, default_event_digest],
    )
}

pub fn guarantee_release_context(hold_id: &Identifier) -> Digest32 {
    digest_fields(b"DECCP:GUARANTEE-RELEASE-CONTEXT:v1", &[hold_id])
}

pub fn confidential_guarantee_release_context(
    request: &ConfidentialGuaranteeReleaseRequest,
) -> Digest32 {
    digest_fields(
        b"DECCP:CONFIDENTIAL-GUARANTEE-RELEASE-CONTEXT:v1",
        &[
            &request.operation_id,
            &request.hold_id,
            &request.expected_facility_state_digest,
            &request.after_facility_state_digest,
            &request.expected_facility_sequence.to_be_bytes(),
            &request.transition_proof_digest,
        ],
    )
}

pub fn confidential_guarantee_claim_context(
    request: &ConfidentialGuaranteeClaimRequest,
) -> Digest32 {
    digest_fields(
        b"DECCP:CONFIDENTIAL-GUARANTEE-CLAIM-CONTEXT:v1",
        &[
            &request.operation_id,
            &request.hold_id,
            &request.exposure_id,
            &request.default_event_digest,
            &request.expected_facility_state_digest,
            &request.after_facility_state_digest,
            &request.expected_facility_sequence.to_be_bytes(),
            &request.transition_proof_digest,
        ],
    )
}

fn netting_proposal_digest(
    cycle_id: &Identifier,
    mode: NettingMode,
    obligation_root: &Digest32,
    legs: &[ClearingLeg],
    risk_debits: &BTreeMap<String, u128>,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"DECCP:NETTING-PROPOSAL:v1");
    hash.update(cycle_id);
    hash.update([mode_tag(mode)]);
    hash.update(obligation_root);
    hash.update((legs.len() as u32).to_be_bytes());
    for leg in legs {
        hash.update(leg.payer_id);
        hash.update(leg.payee_id);
        hash.update(leg.asset_id);
        hash.update(leg.amount.to_be_bytes());
        hash.update(leg.instruction_context_digest);
    }
    for (participant, debit) in risk_debits {
        hash.update((participant.len() as u32).to_be_bytes());
        hash.update(participant.as_bytes());
        hash.update(debit.to_be_bytes());
    }
    hash.finalize().into()
}

fn guarantee_facility_statement(
    operation_id: &Identifier,
    facility: &GuaranteeFacility,
) -> Digest32 {
    digest_fields(
        b"DECCP:GUARANTEE-FACILITY:v1",
        &[
            operation_id,
            &facility.facility_id,
            &facility.guarantor_id,
            &facility.beneficiary_subject_line_id,
            &facility.settlement_asset_id,
            &facility.capacity.to_be_bytes(),
            &facility.defmi_facility_id,
            &facility.policy_digest,
            &facility.valid_until.to_be_bytes(),
        ],
    )
}

pub fn guarantee_facility_approval_digest(
    operation_id: &Identifier,
    facility: &GuaranteeFacility,
) -> Digest32 {
    guarantee_facility_statement(operation_id, facility)
}

fn confidential_guarantee_facility_statement(
    operation_id: &Identifier,
    facility: &ConfidentialGuaranteeFacility,
) -> Digest32 {
    digest_fields(
        b"DECCP:CONFIDENTIAL-GUARANTEE-FACILITY:v1",
        &[
            operation_id,
            &facility.facility_id,
            &facility.guarantor_id,
            &facility.beneficiary_subject_line_id,
            &facility.settlement_asset_id,
            &facility.capacity_commitment,
            &facility.latest_facility_state_digest,
            &facility.defmi_facility_id,
            &facility.policy_digest,
            &facility.valid_until.to_be_bytes(),
            &facility.sequence.to_be_bytes(),
        ],
    )
}

pub fn confidential_guarantee_facility_approval_digest(
    operation_id: &Identifier,
    facility: &ConfidentialGuaranteeFacility,
) -> Digest32 {
    confidential_guarantee_facility_statement(operation_id, facility)
}

pub fn margin_approval_digest(
    operation_id: &Identifier,
    participant_id: &Identifier,
    initial_margin: u128,
    variation_margin: u128,
    expected_sequence: u64,
) -> Digest32 {
    digest_fields(
        b"DECCP:MARGIN:v1",
        &[
            operation_id,
            participant_id,
            &initial_margin.to_be_bytes(),
            &variation_margin.to_be_bytes(),
            &expected_sequence.to_be_bytes(),
        ],
    )
}

pub fn open_cycle_approval_digest(
    operation_id: &Identifier,
    cycle_id: &Identifier,
    mode: NettingMode,
    settlement_asset_id: &Identifier,
    policy_digest: &Digest32,
    opened_at: u64,
) -> Digest32 {
    digest_fields(
        b"DECCP:OPEN-CYCLE:v1",
        &[
            operation_id,
            cycle_id,
            &[mode_tag(mode)],
            settlement_asset_id,
            policy_digest,
            &opened_at.to_be_bytes(),
        ],
    )
}

pub fn default_declaration_approval_digest(
    operation_id: &Identifier,
    case_id: &Identifier,
    evidence: &DefaultEvidence,
    now: u64,
) -> Digest32 {
    digest_fields(
        b"DECCP:DECLARE-DEFAULT:v1",
        &[
            operation_id,
            case_id,
            &evidence.event_id,
            &evidence.source_id,
            &evidence.participant_id,
            &evidence.event_digest,
            &evidence.observed_at.to_be_bytes(),
            &now.to_be_bytes(),
        ],
    )
}

fn draw_layer(
    draws: &mut Vec<WaterfallDraw>,
    source_kind: DefaultSourceKind,
    participant_id: Option<Identifier>,
    available: u128,
    remaining: &mut u128,
) {
    let amount = available.min(*remaining);
    if amount > 0 {
        draws.push(WaterfallDraw {
            source_kind,
            participant_id,
            amount,
        });
        *remaining -= amount;
    }
}

fn default_settlement_context(case_id: &Identifier, draws: &[WaterfallDraw]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"DECCP:DEFAULT-SETTLEMENT-CONTEXT:v1");
    hash.update(case_id);
    for draw in draws {
        hash.update([default_source_tag(draw.source_kind)]);
        hash.update(draw.participant_id.unwrap_or(ZERO));
        hash.update(draw.amount.to_be_bytes());
    }
    hash.finalize().into()
}

fn default_resolution_digest(
    case_id: &Identifier,
    participant_id: &Identifier,
    shortfall: u128,
    draws: &[WaterfallDraw],
    settlement_context: &Digest32,
) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(b"DECCP:DEFAULT-RESOLUTION:v1");
    hash.update(case_id);
    hash.update(participant_id);
    hash.update(shortfall.to_be_bytes());
    hash.update(settlement_context);
    for draw in draws {
        hash.update([default_source_tag(draw.source_kind)]);
        hash.update(draw.participant_id.unwrap_or(ZERO));
        hash.update(draw.amount.to_be_bytes());
    }
    hash.finalize().into()
}

fn mode_tag(mode: NettingMode) -> u8 {
    match mode {
        NettingMode::GrossGross => 1,
        NettingMode::GrossNet => 2,
        NettingMode::NetNet => 3,
    }
}

fn default_source_tag(kind: DefaultSourceKind) -> u8 {
    match kind {
        DefaultSourceKind::DefaulterMargin => 1,
        DefaultSourceKind::DefaulterFund => 2,
        DefaultSourceKind::MutualizedFund => 3,
        DefaultSourceKind::CcpCapital => 4,
    }
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Digest32 {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

fn id_key(id: &Identifier) -> String {
    let mut out = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DeCcpError {
    #[error("authority set is invalid")]
    InvalidAuthoritySet,
    #[error("quorum approval is invalid")]
    InvalidQuorumApproval,
    #[error("quorum threshold is not met")]
    InsufficientQuorum,
    #[error("CCP capital must be positive")]
    InvalidCapital,
    #[error("participant admission is invalid")]
    InvalidParticipant,
    #[error("participant is already registered")]
    DuplicateParticipant,
    #[error("participant is unknown")]
    UnknownParticipant,
    #[error("participant is not active or its eligibility expired")]
    ParticipantNotActive,
    #[error("eligibility rejected: {0}")]
    EligibilityRejected(String),
    #[error("DeFMI evidence rejected: {0}")]
    DeFmiEvidenceRejected(String),
    #[error("settlement instruction rejected: {0}")]
    InstructionRejected(String),
    #[error("collateral is invalid")]
    InvalidCollateral,
    #[error("DeFMI lock or hold reference is already assigned to another resource")]
    DuplicateDeFmiReference,
    #[error("margin request is invalid")]
    InvalidMargin,
    #[error("eligible collateral is insufficient")]
    InsufficientCollateral,
    #[error("net exposure exceeds encumbered margin")]
    InsufficientMargin,
    #[error("state sequence is stale")]
    StaleSequence,
    #[error("cycle is invalid")]
    InvalidCycle,
    #[error("cycle is unknown")]
    UnknownCycle,
    #[error("cycle is not open")]
    CycleNotOpen,
    #[error("obligation is invalid")]
    InvalidObligation,
    #[error("obligation is duplicate")]
    DuplicateObligation,
    #[error("netting proposal is invalid")]
    InvalidNettingProposal,
    #[error("netting conservation failed")]
    ConservationFailure,
    #[error("DeFMI settlement receipt is invalid")]
    InvalidSettlementReceipt,
    #[error("guarantee facility is invalid")]
    InvalidGuaranteeFacility,
    #[error("guarantee facility is unknown")]
    UnknownGuaranteeFacility,
    #[error("guarantee reservation is invalid")]
    InvalidGuaranteeReservation,
    #[error("guarantee capacity is exceeded")]
    GuaranteeCapacityExceeded,
    #[error("guarantee hold is unknown")]
    UnknownGuaranteeHold,
    #[error("guarantee hold is unavailable")]
    GuaranteeHoldUnavailable,
    #[error("guarantee claim is invalid")]
    InvalidGuaranteeClaim,
    #[error("default declaration is invalid")]
    InvalidDefault,
    #[error("default case is unknown")]
    UnknownDefault,
    #[error("default case is already resolved")]
    DefaultAlreadyResolved,
    #[error("default resolution is invalid")]
    InvalidDefaultResolution,
    #[error("loss exceeds all waterfall resources")]
    WaterfallExhausted,
    #[error("operation was replayed or stale")]
    ReplayOrStaleOperation,
    #[error("arithmetic overflow")]
    ArithmeticOverflow,
    #[error("stored clearing state is inconsistent")]
    InvalidState,
}
