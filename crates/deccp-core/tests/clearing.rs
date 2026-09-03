use deccp_core::{
    confidential_guarantee_claim_context, confidential_guarantee_facility_approval_digest,
    confidential_guarantee_release_context, default_declaration_approval_digest,
    guarantee_claim_context, guarantee_facility_approval_digest, guarantee_release_context,
    margin_approval_digest, open_cycle_approval_digest, AuthorityMember, AuthoritySet,
    CcpCapitalization, ClearingBook, ClearingObligation, CollateralLot, CollateralStatus,
    ConfidentialGuaranteeClaimRequest, ConfidentialGuaranteeFacility, ConfidentialGuaranteeHold,
    ConfidentialGuaranteeReleaseRequest, ConfidentialGuaranteeReservation, DeCcpError, DeFmiPort,
    DefaultEvidence, DefaultSourceKind, DefmiSettlementReceipt, EligibilityAttestation,
    EligibilityPort, GuaranteeClaimRequest, GuaranteeFacility, GuaranteeFacilityStatus,
    GuaranteeHoldStatus, GuaranteeReservation, InstructionPort, MarginUpdate, NettingMode,
    OpenCycleRequest, ParticipantAdmission, QuorumApproval, VerifiedAdmission,
};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

struct Fixture {
    authorities: AuthoritySet,
    keys: Vec<([u8; 32], SigningKey)>,
}

impl Fixture {
    fn new() -> Self {
        let keys: Vec<_> = (1..=3)
            .map(|index| (id(index), SigningKey::generate(&mut OsRng)))
            .collect();
        let authorities = AuthoritySet {
            epoch: 1,
            threshold: 2,
            members: keys
                .iter()
                .map(|(member_id, key)| AuthorityMember {
                    member_id: *member_id,
                    public_key: key.verifying_key().to_bytes(),
                })
                .collect(),
        };
        Self { authorities, keys }
    }

    fn approval(&self, statement: [u8; 32]) -> QuorumApproval {
        QuorumApproval::sign(
            self.authorities.epoch,
            statement,
            &[
                (self.keys[0].0, &self.keys[0].1),
                (self.keys[1].0, &self.keys[1].1),
            ],
        )
    }
}

struct Eligibility;

struct Instructions;
struct RejectInstructions;

impl InstructionPort for Instructions {
    fn verify_obligation(&self, obligation: &ClearingObligation, _now: u64) -> Result<(), String> {
        (obligation.zkpi_digest != [0; 32])
            .then_some(())
            .ok_or_else(|| "zkPI was not verified".into())
    }
}

impl InstructionPort for RejectInstructions {
    fn verify_obligation(&self, _obligation: &ClearingObligation, _now: u64) -> Result<(), String> {
        Err("zkPI proof rejected".into())
    }
}

impl EligibilityPort for Eligibility {
    fn verify(
        &self,
        evidence: &EligibilityAttestation,
        now: u64,
    ) -> Result<VerifiedAdmission, String> {
        if evidence.valid_until < now {
            return Err("expired".into());
        }
        Ok(VerifiedAdmission {
            provider_id: evidence.provider_id,
            subject_line_id: evidence.subject_line_id,
            policy_digest: evidence.policy_digest,
            evidence_digest: evidence.evidence_digest,
            valid_until: evidence.valid_until,
        })
    }
}

struct Defmi;

impl DeFmiPort for Defmi {
    fn verify_ccp_capital(
        &self,
        capitalization: &CcpCapitalization,
        now: u64,
    ) -> Result<(), String> {
        (capitalization.valid_until >= now)
            .then_some(())
            .ok_or_else(|| "expired CCP capital".into())
    }

    fn verify_default_fund(
        &self,
        admission: &ParticipantAdmission,
        _now: u64,
    ) -> Result<(), String> {
        (admission.default_fund_contribution > 0)
            .then_some(())
            .ok_or_else(|| "empty default fund".into())
    }

    fn verify_collateral_lock(&self, lot: &CollateralLot, now: u64) -> Result<(), String> {
        (lot.valid_until >= now)
            .then_some(())
            .ok_or_else(|| "expired collateral lock".into())
    }

    fn verify_guarantee_facility(
        &self,
        facility: &GuaranteeFacility,
        now: u64,
    ) -> Result<(), String> {
        (facility.valid_until >= now)
            .then_some(())
            .ok_or_else(|| "expired facility".into())
    }

    fn verify_guarantee_hold(
        &self,
        reservation: &GuaranteeReservation,
        now: u64,
    ) -> Result<(), String> {
        (reservation.valid_until >= now)
            .then_some(())
            .ok_or_else(|| "expired hold".into())
    }

    fn verify_confidential_guarantee_facility(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        now: u64,
    ) -> Result<(), String> {
        (facility.valid_until >= now && facility.latest_facility_state_digest != [0; 32])
            .then_some(())
            .ok_or_else(|| "invalid confidential facility".into())
    }

    fn verify_confidential_guarantee_hold(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        reservation: &ConfidentialGuaranteeReservation,
        now: u64,
    ) -> Result<(), String> {
        (reservation.valid_until >= now
            && reservation.expected_facility_state_digest == facility.latest_facility_state_digest
            && reservation.after_facility_state_digest
                != reservation.expected_facility_state_digest)
            .then_some(())
            .ok_or_else(|| "invalid confidential hold transition".into())
    }

    fn verify_confidential_guarantee_release(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeReleaseRequest,
        now: u64,
    ) -> Result<(), String> {
        (hold.facility_id == facility.facility_id
            && request.expected_facility_state_digest == facility.latest_facility_state_digest
            && request.receipt.context_digest == confidential_guarantee_release_context(request)
            && request.receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "invalid confidential release transition".into())
    }

    fn verify_confidential_guarantee_claim(
        &self,
        facility: &ConfidentialGuaranteeFacility,
        hold: &ConfidentialGuaranteeHold,
        request: &ConfidentialGuaranteeClaimRequest,
        now: u64,
    ) -> Result<(), String> {
        (hold.facility_id == facility.facility_id
            && request.expected_facility_state_digest == facility.latest_facility_state_digest
            && request.receipt.context_digest == confidential_guarantee_claim_context(request)
            && request.receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "invalid confidential claim transition".into())
    }

    fn verify_guarantee_release(
        &self,
        expected_context: &[u8; 32],
        receipt: &DefmiSettlementReceipt,
        now: u64,
    ) -> Result<(), String> {
        (&receipt.context_digest == expected_context && receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "wrong release".into())
    }

    fn verify_settlement(
        &self,
        expected_context: &[u8; 32],
        receipt: &DefmiSettlementReceipt,
        now: u64,
    ) -> Result<(), String> {
        (&receipt.context_digest == expected_context && receipt.finalized_at <= now)
            .then_some(())
            .ok_or_else(|| "wrong or non-final receipt".into())
    }
}

fn admission(operation: u8, participant: u8, subject: u8, fund: u128) -> ParticipantAdmission {
    ParticipantAdmission {
        operation_id: id(operation),
        participant_id: id(participant),
        settlement_participant_id: id(participant + 40),
        eligibility: EligibilityAttestation {
            provider_id: id(90),
            subject_line_id: id(subject),
            policy_digest: id(91),
            evidence_digest: id(operation + 1),
            valid_until: 1_000,
        },
        default_fund_contribution: fund,
        default_fund_defmi_lock_id: id(operation + 20),
        default_fund_proof_digest: id(operation + 30),
        admitted_at: 100,
    }
}

fn admit(book: &mut ClearingBook, fixture: &Fixture, request: ParticipantAdmission) {
    let approval = fixture.approval(request.statement_digest().unwrap());
    book.admit_participant(request, &Eligibility, &approval, &Defmi, 100)
        .unwrap();
}

fn new_book(fixture: &Fixture, capital: u128) -> ClearingBook {
    ClearingBook::new(
        fixture.authorities.clone(),
        CcpCapitalization {
            amount: capital,
            defmi_lock_id: id(80),
            proof_digest: id(81),
            valid_until: 1_000,
        },
        &Defmi,
        100,
    )
    .unwrap()
}

fn collateral(operation: u8, lot: u8, owner: u8, value: u128) -> CollateralLot {
    CollateralLot {
        operation_id: id(operation),
        lot_id: id(lot),
        owner_id: id(owner),
        asset_id: id(70),
        defmi_lock_id: id(lot + 20),
        market_value: value,
        haircut_basis_points: 0,
        valuation_policy_digest: id(71),
        valuation_proof_digest: id(lot + 30),
        valid_until: 900,
        status: CollateralStatus::Available,
    }
}

#[test]
fn netting_is_conserving_quorum_approved_and_margin_bounded() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 500);
    admit(&mut book, &fixture, admission(10, 20, 30, 50));
    admit(&mut book, &fixture, admission(12, 21, 31, 50));
    book.post_collateral(collateral(14, 40, 20, 200), &Defmi, 100)
        .unwrap();
    book.post_collateral(collateral(15, 41, 21, 200), &Defmi, 100)
        .unwrap();
    for (operation, participant) in [(16, 20), (17, 21)] {
        let statement = margin_approval_digest(&id(operation), &id(participant), 150, 0, 0);
        book.set_margin(
            MarginUpdate {
                operation_id: id(operation),
                participant_id: id(participant),
                initial_margin: 150,
                variation_margin: 0,
                expected_sequence: 0,
            },
            &fixture.approval(statement),
            100,
        )
        .unwrap();
    }
    let open_statement =
        open_cycle_approval_digest(&id(18), &id(50), NettingMode::NetNet, &id(70), &id(72), 100);
    book.open_cycle(
        OpenCycleRequest {
            operation_id: id(18),
            cycle_id: id(50),
            mode: NettingMode::NetNet,
            settlement_asset_id: id(70),
            policy_digest: id(72),
            opened_at: 100,
        },
        &fixture.approval(open_statement),
    )
    .unwrap();
    let first_obligation = ClearingObligation {
        operation_id: id(19),
        obligation_id: id(51),
        cycle_id: id(50),
        payer_id: id(20),
        payee_id: id(21),
        asset_id: id(70),
        amount: 100,
        risk_value: 100,
        zkpi_digest: id(73),
    };
    assert_eq!(
        book.submit_obligation(first_obligation.clone(), &RejectInstructions, 100),
        Err(DeCcpError::InstructionRejected(
            "zkPI proof rejected".into()
        ))
    );
    book.submit_obligation(first_obligation, &Instructions, 100)
        .unwrap();
    book.submit_obligation(
        ClearingObligation {
            operation_id: id(22),
            obligation_id: id(52),
            cycle_id: id(50),
            payer_id: id(21),
            payee_id: id(20),
            asset_id: id(70),
            amount: 30,
            risk_value: 30,
            zkpi_digest: id(74),
        },
        &Instructions,
        100,
    )
    .unwrap();
    let proposal = book.prepare_close(&id(50)).unwrap();
    assert_eq!(proposal.legs.len(), 1);
    assert_eq!(proposal.legs[0].payer_id, id(20));
    assert_eq!(proposal.legs[0].payee_id, id(21));
    assert_eq!(proposal.legs[0].amount, 70);
    assert_eq!(
        proposal.risk_debits.values().copied().collect::<Vec<_>>(),
        vec![70]
    );
    let approval = fixture.approval(proposal.proposal_digest);
    book.commit_close(proposal.clone(), &approval).unwrap();
    book.record_cycle_settlement(
        &id(50),
        proposal.proposal_digest,
        DefmiSettlementReceipt {
            receipt_digest: id(75),
            context_digest: proposal.proposal_digest,
            finalized_at: 110,
        },
        &Defmi,
        110,
    )
    .unwrap();
}

#[test]
fn gross_gross_mode_preserves_each_leg_and_requires_gross_margin() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 500);
    admit(&mut book, &fixture, admission(10, 20, 30, 50));
    admit(&mut book, &fixture, admission(12, 21, 31, 50));
    book.post_collateral(collateral(14, 40, 20, 200), &Defmi, 100)
        .unwrap();
    book.post_collateral(collateral(15, 41, 21, 200), &Defmi, 100)
        .unwrap();
    for (operation, participant) in [(16, 20), (17, 21)] {
        let statement = margin_approval_digest(&id(operation), &id(participant), 150, 0, 0);
        book.set_margin(
            MarginUpdate {
                operation_id: id(operation),
                participant_id: id(participant),
                initial_margin: 150,
                variation_margin: 0,
                expected_sequence: 0,
            },
            &fixture.approval(statement),
            100,
        )
        .unwrap();
    }
    let open_statement = open_cycle_approval_digest(
        &id(18),
        &id(50),
        NettingMode::GrossGross,
        &id(70),
        &id(72),
        100,
    );
    book.open_cycle(
        OpenCycleRequest {
            operation_id: id(18),
            cycle_id: id(50),
            mode: NettingMode::GrossGross,
            settlement_asset_id: id(70),
            policy_digest: id(72),
            opened_at: 100,
        },
        &fixture.approval(open_statement),
    )
    .unwrap();
    for obligation in [
        ClearingObligation {
            operation_id: id(19),
            obligation_id: id(51),
            cycle_id: id(50),
            payer_id: id(20),
            payee_id: id(21),
            asset_id: id(70),
            amount: 100,
            risk_value: 100,
            zkpi_digest: id(73),
        },
        ClearingObligation {
            operation_id: id(22),
            obligation_id: id(52),
            cycle_id: id(50),
            payer_id: id(21),
            payee_id: id(20),
            asset_id: id(70),
            amount: 30,
            risk_value: 30,
            zkpi_digest: id(74),
        },
    ] {
        book.submit_obligation(obligation, &Instructions, 100)
            .unwrap();
    }
    let proposal = book.prepare_close(&id(50)).unwrap();
    assert_eq!(proposal.legs.len(), 2);
    let mut debits = proposal.risk_debits.values().copied().collect::<Vec<_>>();
    debits.sort_unstable();
    assert_eq!(debits, vec![30, 100]);
}

#[test]
fn concurrent_guarantee_reservations_use_one_sequence_and_never_exceed_capacity() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 500);
    admit(&mut book, &fixture, admission(10, 20, 30, 50));
    let facility = GuaranteeFacility {
        facility_id: id(40),
        guarantor_id: id(20),
        beneficiary_subject_line_id: id(31),
        settlement_asset_id: id(70),
        capacity: 100,
        reserved: 0,
        consumed: 0,
        defmi_facility_id: id(41),
        policy_digest: id(42),
        valid_until: 900,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let statement = guarantee_facility_approval_digest(&id(11), &facility);
    book.register_guarantee_facility(id(11), facility, &fixture.approval(statement), &Defmi, 100)
        .unwrap();
    let first = book
        .reserve_guarantee(
            GuaranteeReservation {
                operation_id: id(12),
                hold_id: id(43),
                facility_id: id(40),
                purpose_digest: id(44),
                amount: 60,
                defmi_hold_id: id(45),
                relation_proof_digest: id(46),
                expected_facility_sequence: 0,
                valid_until: 800,
            },
            &Defmi,
            100,
        )
        .unwrap();
    assert_eq!(first.status, GuaranteeHoldStatus::Reserved);
    assert_eq!(
        book.reserve_guarantee(
            GuaranteeReservation {
                operation_id: id(13),
                hold_id: id(47),
                facility_id: id(40),
                purpose_digest: id(48),
                amount: 50,
                defmi_hold_id: id(49),
                relation_proof_digest: id(50),
                expected_facility_sequence: 1,
                valid_until: 800,
            },
            &Defmi,
            100,
        ),
        Err(DeCcpError::GuaranteeCapacityExceeded)
    );
    let second = book
        .reserve_guarantee(
            GuaranteeReservation {
                operation_id: id(14),
                hold_id: id(51),
                facility_id: id(40),
                purpose_digest: id(52),
                amount: 40,
                defmi_hold_id: id(53),
                relation_proof_digest: id(54),
                expected_facility_sequence: 1,
                valid_until: 800,
            },
            &Defmi,
            100,
        )
        .unwrap();
    assert_eq!(second.amount, 40);
    assert_eq!(book.guarantee_facility(&id(40)).unwrap().reserved, 100);
    book.release_guarantee(
        id(15),
        id(43),
        DefmiSettlementReceipt {
            receipt_digest: id(55),
            context_digest: guarantee_release_context(&id(43)),
            finalized_at: 120,
        },
        &Defmi,
        120,
    )
    .unwrap();
    assert_eq!(book.guarantee_facility(&id(40)).unwrap().reserved, 40);
}

#[test]
fn confidential_guarantees_use_commitment_cas_without_opening_amounts() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 500);
    admit(&mut book, &fixture, admission(10, 20, 30, 50));
    let facility = ConfidentialGuaranteeFacility {
        facility_id: id(40),
        guarantor_id: id(20),
        beneficiary_subject_line_id: id(31),
        settlement_asset_id: id(70),
        capacity_commitment: id(41),
        latest_facility_state_digest: id(42),
        defmi_facility_id: id(43),
        policy_digest: id(44),
        valid_until: 900,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let statement = confidential_guarantee_facility_approval_digest(&id(11), &facility);
    book.register_confidential_guarantee_facility(
        id(11),
        facility,
        &fixture.approval(statement),
        &Defmi,
        100,
    )
    .unwrap();
    let reservation = ConfidentialGuaranteeReservation {
        operation_id: id(12),
        hold_id: id(45),
        facility_id: id(40),
        purpose_digest: id(46),
        coverage_commitment: id(47),
        defmi_hold_id: id(48),
        relation_proof_digest: id(49),
        expected_facility_state_digest: id(42),
        after_facility_state_digest: id(50),
        expected_facility_sequence: 0,
        valid_until: 800,
    };
    book.reserve_confidential_guarantee(reservation.clone(), &Defmi, 100)
        .unwrap();
    assert_eq!(
        book.reserve_confidential_guarantee(
            ConfidentialGuaranteeReservation {
                operation_id: id(13),
                hold_id: id(51),
                defmi_hold_id: id(52),
                ..reservation
            },
            &Defmi,
            100,
        ),
        Err(DeCcpError::StaleSequence)
    );
    book.bind_confidential_guarantee(id(14), id(45), id(53), 110)
        .unwrap();
    let mut claim = ConfidentialGuaranteeClaimRequest {
        operation_id: id(15),
        hold_id: id(45),
        exposure_id: id(53),
        default_event_digest: id(54),
        expected_facility_state_digest: id(50),
        after_facility_state_digest: id(55),
        expected_facility_sequence: 1,
        transition_proof_digest: id(56),
        receipt: DefmiSettlementReceipt {
            receipt_digest: id(57),
            context_digest: [0; 32],
            finalized_at: 120,
        },
    };
    claim.receipt.context_digest = confidential_guarantee_claim_context(&claim);
    book.consume_confidential_guarantee(claim, &Defmi, 120)
        .unwrap();
    assert_eq!(
        book.confidential_guarantee_hold(&id(45)).unwrap().status,
        GuaranteeHoldStatus::Consumed
    );
    assert_eq!(
        book.confidential_guarantee_facility(&id(40))
            .unwrap()
            .latest_facility_state_digest,
        id(55)
    );

    book.reserve_confidential_guarantee(
        ConfidentialGuaranteeReservation {
            operation_id: id(16),
            hold_id: id(58),
            facility_id: id(40),
            purpose_digest: id(59),
            coverage_commitment: id(60),
            defmi_hold_id: id(61),
            relation_proof_digest: id(62),
            expected_facility_state_digest: id(55),
            after_facility_state_digest: id(63),
            expected_facility_sequence: 2,
            valid_until: 800,
        },
        &Defmi,
        120,
    )
    .unwrap();
    let mut release = ConfidentialGuaranteeReleaseRequest {
        operation_id: id(17),
        hold_id: id(58),
        expected_facility_state_digest: id(63),
        after_facility_state_digest: id(64),
        expected_facility_sequence: 3,
        transition_proof_digest: id(65),
        receipt: DefmiSettlementReceipt {
            receipt_digest: id(66),
            context_digest: [0; 32],
            finalized_at: 130,
        },
    };
    release.receipt.context_digest = confidential_guarantee_release_context(&release);
    book.release_confidential_guarantee(release, &Defmi, 130)
        .unwrap();
    assert_eq!(
        book.confidential_guarantee_hold(&id(58)).unwrap().status,
        GuaranteeHoldStatus::Released
    );
    assert_eq!(
        book.confidential_guarantee_facility(&id(40))
            .unwrap()
            .sequence,
        4
    );
}

#[test]
fn default_waterfall_draws_margin_then_member_funds_then_ccp_capital() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 100);
    admit(&mut book, &fixture, admission(10, 20, 30, 40));
    admit(&mut book, &fixture, admission(12, 21, 31, 50));
    book.post_collateral(collateral(14, 40, 20, 100), &Defmi, 100)
        .unwrap();
    let margin_statement = margin_approval_digest(&id(15), &id(20), 100, 0, 0);
    book.set_margin(
        MarginUpdate {
            operation_id: id(15),
            participant_id: id(20),
            initial_margin: 100,
            variation_margin: 0,
            expected_sequence: 0,
        },
        &fixture.approval(margin_statement),
        100,
    )
    .unwrap();
    let evidence = DefaultEvidence {
        event_id: id(60),
        source_id: id(61),
        participant_id: id(20),
        event_digest: id(62),
        observed_at: 110,
    };
    let statement = default_declaration_approval_digest(&id(16), &id(63), &evidence, 120);
    book.declare_default(id(16), id(63), evidence, &fixture.approval(statement), 120)
        .unwrap();
    let resolution = book.prepare_default_resolution(&id(63), 250).unwrap();
    assert_eq!(
        resolution
            .draws
            .iter()
            .map(|draw| (draw.source_kind, draw.amount))
            .collect::<Vec<_>>(),
        vec![
            (DefaultSourceKind::DefaulterMargin, 100),
            (DefaultSourceKind::DefaulterFund, 40),
            (DefaultSourceKind::MutualizedFund, 50),
            (DefaultSourceKind::CcpCapital, 60),
        ]
    );
    let approval = fixture.approval(resolution.resolution_digest);
    let settlement_context = resolution.settlement_context_digest;
    assert_eq!(
        book.commit_default_resolution(
            resolution.clone(),
            &approval,
            DefmiSettlementReceipt {
                receipt_digest: id(64),
                context_digest: id(65),
                finalized_at: 130,
            },
            &Defmi,
            130,
        ),
        Err(DeCcpError::InvalidDefaultResolution)
    );
    assert_eq!(book.ccp_capital_remaining(), 100);
    book.commit_default_resolution(
        resolution,
        &approval,
        DefmiSettlementReceipt {
            receipt_digest: id(64),
            context_digest: settlement_context,
            finalized_at: 130,
        },
        &Defmi,
        130,
    )
    .unwrap();
    assert_eq!(book.ccp_capital_remaining(), 40);
    assert_eq!(
        book.default_case(&id(63)).unwrap().defmi_settlement_receipt,
        Some(id(64))
    );
}

#[test]
fn defaulted_guarantor_cannot_reserve_and_expired_hold_cannot_be_claimed() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 500);
    admit(&mut book, &fixture, admission(10, 20, 30, 50));
    admit(&mut book, &fixture, admission(12, 21, 31, 50));
    let facility = GuaranteeFacility {
        facility_id: id(60),
        guarantor_id: id(20),
        beneficiary_subject_line_id: id(61),
        settlement_asset_id: id(70),
        capacity: 100,
        reserved: 0,
        consumed: 0,
        defmi_facility_id: id(62),
        policy_digest: id(63),
        valid_until: 900,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let approval = fixture.approval(guarantee_facility_approval_digest(&id(13), &facility));
    book.register_guarantee_facility(id(13), facility, &approval, &Defmi, 100)
        .unwrap();
    let reservation = |operation: u8, hold: u8, valid_until: u64| GuaranteeReservation {
        operation_id: id(operation),
        hold_id: id(hold),
        facility_id: id(60),
        purpose_digest: id(64),
        amount: 10,
        defmi_hold_id: id(hold + 1),
        relation_proof_digest: id(65),
        expected_facility_sequence: 0,
        valid_until,
    };
    // A hold that expires before the claim is not claimable.
    let hold = book
        .reserve_guarantee(reservation(14, 66, 150), &Defmi, 100)
        .unwrap();
    book.bind_guarantee(id(15), hold.hold_id, id(67), 110)
        .unwrap();
    let mut claim = GuaranteeClaimRequest {
        operation_id: id(16),
        hold_id: id(66),
        exposure_id: id(67),
        default_event_digest: id(68),
        receipt: DefmiSettlementReceipt {
            receipt_digest: id(69),
            context_digest: [0; 32],
            finalized_at: 160,
        },
    };
    claim.receipt.context_digest = guarantee_claim_context(&id(66), &id(67), &id(68));
    assert_eq!(
        book.consume_guarantee(claim, &Defmi, 160),
        Err(DeCcpError::GuaranteeHoldUnavailable)
    );
    // Once the guarantor is in default it can no longer reserve capacity.
    let evidence = DefaultEvidence {
        event_id: id(80),
        source_id: id(81),
        participant_id: id(20),
        event_digest: id(82),
        observed_at: 160,
    };
    let approval = fixture.approval(default_declaration_approval_digest(
        &id(17),
        &id(83),
        &evidence,
        160,
    ));
    book.declare_default(id(17), id(83), evidence, &approval, 160)
        .unwrap();
    let mut late = reservation(18, 84, 500);
    late.expected_facility_sequence = 1;
    assert_eq!(
        book.reserve_guarantee(late, &Defmi, 160),
        Err(DeCcpError::ParticipantNotActive)
    );
    book.validate().unwrap();
}

#[test]
fn snapshot_restores_only_with_quorum_approval_and_intact_invariants() {
    let fixture = Fixture::new();
    let mut book = new_book(&fixture, 500);
    admit(&mut book, &fixture, admission(10, 20, 30, 50));
    book.post_collateral(collateral(14, 40, 20, 200), &Defmi, 100)
        .unwrap();
    let statement = margin_approval_digest(&id(16), &id(20), 150, 0, 0);
    book.set_margin(
        MarginUpdate {
            operation_id: id(16),
            participant_id: id(20),
            initial_margin: 150,
            variation_margin: 0,
            expected_sequence: 0,
        },
        &fixture.approval(statement),
        100,
    )
    .unwrap();
    let facility = GuaranteeFacility {
        facility_id: id(60),
        guarantor_id: id(20),
        beneficiary_subject_line_id: id(61),
        settlement_asset_id: id(70),
        capacity: 100,
        reserved: 0,
        consumed: 0,
        defmi_facility_id: id(62),
        policy_digest: id(63),
        valid_until: 900,
        sequence: 0,
        status: GuaranteeFacilityStatus::Active,
    };
    let approval = fixture.approval(guarantee_facility_approval_digest(&id(13), &facility));
    book.register_guarantee_facility(id(13), facility, &approval, &Defmi, 100)
        .unwrap();
    book.reserve_guarantee(
        GuaranteeReservation {
            operation_id: id(19),
            hold_id: id(66),
            facility_id: id(60),
            purpose_digest: id(64),
            amount: 10,
            defmi_hold_id: id(67),
            relation_proof_digest: id(65),
            expected_facility_sequence: 0,
            valid_until: 800,
        },
        &Defmi,
        100,
    )
    .unwrap();
    book.validate().unwrap();

    let snapshot = book.snapshot();
    let digest = snapshot.digest().unwrap();
    let restored = ClearingBook::restore(
        &fixture.authorities,
        snapshot.clone(),
        &fixture.approval(digest),
    )
    .unwrap();
    assert_eq!(restored.snapshot(), snapshot);
    assert_eq!(restored, book);

    // One signature is not a quorum, and a foreign authority set is refused.
    let single = QuorumApproval::sign(1, digest, &[(fixture.keys[0].0, &fixture.keys[0].1)]);
    assert_eq!(
        ClearingBook::restore(&fixture.authorities, snapshot.clone(), &single).map(|_| ()),
        Err(DeCcpError::InsufficientQuorum)
    );
    let other = Fixture::new();
    assert_eq!(
        ClearingBook::restore(
            &other.authorities,
            snapshot.clone(),
            &other.approval(digest)
        )
        .map(|_| ()),
        Err(DeCcpError::InvalidAuthoritySet)
    );
    // An approved snapshot whose facility accounting disagrees with its holds
    // is refused even though the quorum signed it.
    let mut inflated = snapshot.clone();
    inflated
        .guarantee_facilities
        .values_mut()
        .for_each(|facility| facility.reserved = 0);
    let inflated_digest = inflated.digest().unwrap();
    assert_eq!(
        ClearingBook::restore(
            &fixture.authorities,
            inflated,
            &fixture.approval(inflated_digest)
        )
        .map(|_| ()),
        Err(DeCcpError::InvalidState)
    );
    // The digest covers every field: a changed snapshot fails the old approval.
    let mut altered = snapshot.clone();
    altered.ccp_capital_remaining += 1;
    assert_eq!(
        ClearingBook::restore(&fixture.authorities, altered, &fixture.approval(digest)).map(|_| ()),
        Err(DeCcpError::InvalidQuorumApproval)
    );

    // A host that authenticates its own storage (a consensus-committed VM
    // state) restores without a second quorum signature, but the invariants
    // still run: the same inflated snapshot is refused on that route too.
    let hosted = ClearingBook::restore_authenticated(snapshot.clone()).unwrap();
    assert_eq!(hosted, book);
    let mut inflated = snapshot;
    inflated
        .guarantee_facilities
        .values_mut()
        .for_each(|facility| facility.reserved = 0);
    assert_eq!(
        ClearingBook::restore_authenticated(inflated).map(|_| ()),
        Err(DeCcpError::InvalidState)
    );
}
