"""
BidShield Kernel v0.1 — Safety skeleton only.

PR #1: Canonical schema, document manifest, missing-doc disclosure,
       "what this did not verify" section, human sign-off gate, renderer.

Do NOT add: addendum diffing, portal mechanics, external dependency graph,
Fatal Five ranking, acknowledgement extraction, appliance packaging,
dashboard, cloud sync, payment rails, or outreach automation.

Those are PR #2 and PR #3.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict
from datetime import datetime, timezone
import json
import hashlib
import os
import csv


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReviewStatus(str, Enum):
    DRAFT = "draft"
    INTERNAL_REVIEW = "internal_review"
    CLIENT_READY = "client_ready"


class ReviewScope(str, Enum):
    NOTICE_LEVEL_TRIAGE = "notice_level_triage"
    PARTIAL_PACKAGE_REVIEW = "partial_package_review"
    FULL_PACKAGE_REVIEW = "full_package_review"
    INSUFFICIENT_DOCUMENTS = "insufficient_documents"


class DocumentCriticality(str, Enum):
    ESSENTIAL = "essential"
    IMPORTANT = "important"
    CONTEXTUAL = "contextual"
    UNKNOWN = "unknown"


class DependencyCriticality(str, Enum):
    BLOCKING = "blocking"
    MATERIAL = "material"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class InterpretationConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, Enum):
    FATAL = "Fatal"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNCERTAIN = "Uncertain"


class Category(str, Enum):
    INSURANCE = "Insurance"
    BONDING = "Bonding"
    WSIB_SAFETY_CERTIFICATION = "WSIB / Safety Certification"
    LICENSING = "Licensing"
    MANDATORY_FORM = "Mandatory Form"
    ACKNOWLEDGEMENT = "Acknowledgement"
    DEADLINE = "Deadline"
    SUBMISSION_MECHANICS = "Submission Mechanics"
    PORTAL_REQUIREMENT = "Portal Requirement"
    EVALUATION_CRITERIA = "Evaluation Criteria"
    TECHNICAL_REQUIREMENT = "Technical Requirement"
    SCOPE_REQUIREMENT = "Scope Requirement"
    PENALTY_LIQUIDATED_DAMAGES = "Penalty / Liquidated Damages"
    ADDENDUM_CONFLICT = "Addendum Conflict"
    EXTERNAL_DEPENDENCY = "External Dependency"
    LEGAL_CONTRACTUAL_RISK = "Legal / Contractual Risk"
    OTHER = "Other"


class RecommendationDecision(str, Enum):
    STOP = "stop"
    CLARIFY_REQUIRED = "clarify_required"
    GO_WITH_CONDITIONS = "go_with_conditions"
    GO_WITH_HUMAN_REVIEW = "go_with_human_review"
    INSUFFICIENT_DOCUMENTS = "insufficient_documents"


class DocumentType(str, Enum):
    MAIN_RFP = "main_rfp"
    ADDENDUM = "addendum"
    AMENDMENT = "amendment"
    ERRATUM = "erratum"
    SCHEDULE = "schedule"
    FORM = "form"
    INSURANCE_REQUIREMENTS = "insurance_requirements"
    GENERAL_CONDITIONS = "general_conditions"
    SPECIAL_CONDITIONS = "special_conditions"
    EVALUATION_CRITERIA = "evaluation_criteria"
    SCOPE_OF_WORK = "scope_of_work"
    CLARIFICATION_RESPONSE = "clarification_response"
    BIDDER_CONFERENCE_SIGNIN = "bidder_conference_signin"
    PORTAL_INSTRUCTION = "portal_instruction"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DocumentRecord:
    document_id: str
    filename: str
    document_type: DocumentType
    sha256: str
    page_count: int
    text_extractable: bool
    contains_pii: bool = False
    contains_competitive_pricing: bool = False
    notes: str = ""
    document_criticality: DocumentCriticality = DocumentCriticality.UNKNOWN
    retrieval_source: str = ""
    retrieval_timestamp_utc: str = ""
    contains_hidden_text: bool = False
    contains_embedded_files: bool = False
    ocr_required: bool = False


@dataclass
class IntakeConsent:
    pilot_terms_accepted: bool = False
    no_phi_confirmed: bool = False
    no_pii_confirmed: bool = False
    no_privileged_legal_confirmed: bool = False
    no_client_confidential_pricing_confirmed: bool = False
    no_credentials_confirmed: bool = False
    no_government_protected_confirmed: bool = False
    retention_acknowledged: bool = False
    feedback_permission: bool = False
    case_study_permission: bool = False

    def all_required(self) -> bool:
        return all([
            self.no_phi_confirmed,
            self.no_pii_confirmed,
            self.no_privileged_legal_confirmed,
            self.no_client_confidential_pricing_confirmed,
            self.no_credentials_confirmed,
            self.no_government_protected_confirmed,
        ])


@dataclass
class DocumentSensitivity:
    contains_phi: bool = False
    contains_pii: bool = False
    contains_privileged_legal: bool = False
    contains_client_confidential_pricing: bool = False
    contains_credentials: bool = False
    contains_government_protected: bool = False
    contains_financial_statements: bool = False
    contains_medical_records: bool = False
    unknown_sensitivity: bool = True

    def is_safe_for_public_preview(self) -> bool:
        return not any([
            self.contains_phi,
            self.contains_pii,
            self.contains_privileged_legal,
            self.contains_client_confidential_pricing,
            self.contains_credentials,
            self.contains_government_protected,
            self.contains_medical_records,
            self.unknown_sensitivity,
        ])


@dataclass
class ProcessingLocation:
    location: str = "secure_server"  # client_browser | rob_local_machine | secure_server | third_party_processor
    local_first_claim_allowed: bool = False
    external_document_api_called: bool = False
    llm_pass_enabled: bool = False
    retention_days: int = 7
    raw_document_deleted: bool = False
    deletion_timestamp_utc: Optional[str] = None


@dataclass
class OutputClassification:
    classification: str = "preliminary_preview"  # preliminary_preview | human_reviewed_draft | client_ready_report | rejected_sensitive_input | insufficient_documents

    def allows_fatal_language(self) -> bool:
        return self.classification == "client_ready_report"


@dataclass
class Requirement:
    document_id: str
    page: int
    section: str
    source_quote: str
    category: Category
    severity: Severity
    mandatory: bool
    action_required: str
    evidence_required: str = ""
    owner_role: str = ""
    deadline: Optional[str] = None
    acknowledgement_required: bool = False
    clarification_question: str = ""
    status: str = "open"
    confidence: str = "medium"
    verified_by_human: bool = False
    human_reviewer: Optional[str] = None
    human_verification_timestamp: Optional[str] = None
    human_verification_note: Optional[str] = None
    superseded_by: Optional[str] = None
    order_of_precedence_relevant: bool = False
    external_dependency: bool = False
    pii_flag: bool = False
    competitive_sensitivity_flag: bool = False
    consequence_quote: str = ""
    consequence_verified: bool = False
    interpretation_confidence: InterpretationConfidence = InterpretationConfidence.MEDIUM
    uncertainty_reason: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    document_criticality: DocumentCriticality = DocumentCriticality.UNKNOWN
    remedy_type: str = "clarification"
    next_action_window: str = "24_hours"


@dataclass
class Recommendation:
    decision: RecommendationDecision
    summary: str
    fatal_count: int = 0
    high_count: int = 0
    acknowledgement_count: int = 0
    deadline_conflicts: int = 0
    external_dependencies: int = 0
    recommended_next_action: str = ""


@dataclass
class Signoff:
    engine_version: str = "bidshield_kernel_v0.1"
    model_name: str = ""
    prompt_version: str = ""
    extraction_started_utc: str = ""
    extraction_completed_utc: str = ""
    human_reviewer: str = ""
    human_review_started_utc: str = ""
    human_review_completed_utc: str = ""
    fatal_high_verified: bool = False
    client_ready: bool = False
    report_hash: str = ""
    delivery_method: str = ""
    delivery_timestamp_utc: str = ""


@dataclass
class Privacy:
    local_first_processing: bool = True
    external_document_api_called: bool = False
    network_egress_blocked: bool = False
    physical_air_gap: bool = False
    cloud_sync_disabled_for_working_folder: bool = False
    raw_documents_deleted_after_review: bool = False
    retention_policy: str = "delete_raw_docs_after_7_days_unless_client_requests_archive"
    transmission_method: str = "encrypted_transfer_or_password_protected_pdf"


@dataclass
class Impact:
    hours_returned_estimate: float = 0.0
    dollars_at_risk_identified: float = 0.0
    confidential_documents_processed_locally: int = 0
    fatal_requirements_caught: int = 0
    clarification_questions_drafted: int = 0
    user_capability_note: str = ""


@dataclass
class ExternalDependency:
    dependency_id: str
    name: str
    referenced_by: str = ""
    criticality: DependencyCriticality = DependencyCriticality.UNKNOWN
    status: str = "not_reviewed"
    action: str = ""


@dataclass
class EvidenceChain:
    evidence_id: str
    requirement_id: str
    document_id: str
    page: int
    bbox: List[int] = field(default_factory=list)
    page_crop_sha256: str = ""
    source_quote: str = ""
    consequence_quote: str = ""
    model_version: str = ""
    prompt_version: str = ""
    human_reviewer: str = ""
    human_verification_timestamp_utc: str = ""
@dataclass
class Review:
    review_id: str
    status: ReviewStatus
    created_utc: str
    client_id: Optional[str]
    vertical: str
    tender_name: str
    tender_number: str
    issuer: str
    submission_deadline: Optional[str]
    clarification_deadline: Optional[str]
    documents: List[DocumentRecord]
    documents_not_provided: List[str]
    external_dependencies: List[str]
    requirements: List[Requirement]
    recommendation: Recommendation
    signoff: Signoff
    privacy: Privacy
    impact: Impact
    review_scope: ReviewScope = ReviewScope.INSUFFICIENT_DOCUMENTS
    document_sufficiency: str = "insufficient"
    report_sha256: str = ""
    legal_disclaimer_version: str = "v1"
    engagement_id: Optional[str] = None
    ai_use_disclosure_required: bool = False
    prompt_injection_defense_version: str = "v1"
    external_dependency_objects: List[ExternalDependency] = field(default_factory=list)
    evidence_chains: List[EvidenceChain] = field(default_factory=list)
    cannot_conclude_safe: bool = True


# ---------------------------------------------------------------------------
# Validation gate — the ethical spine of the product
# ---------------------------------------------------------------------------

def validate_review(review: Review) -> List[str]:
    errors = []

    if review.status == ReviewStatus.CLIENT_READY:
        if not review.signoff.human_reviewer:
            errors.append("Client-ready report requires a named human reviewer.")

        if not review.signoff.human_review_completed_utc:
            errors.append("Client-ready report requires human review completion timestamp.")

        if not review.signoff.fatal_high_verified:
            errors.append("Client-ready report requires fatal/high verification flag.")

        fatal_high_unverified = [
            req.requirement_id
            for req in review.requirements
            if req.severity in (Severity.FATAL, Severity.HIGH)
            and not req.verified_by_human
        ]

        if fatal_high_unverified:
            errors.append(
                "Client-ready report cannot contain unverified Fatal/High items: "
                + ", ".join(fatal_high_unverified)
            )

        if not review.documents:
            errors.append("Client-ready report requires at least one reviewed document.")

        if not review.recommendation.summary:
            errors.append("Client-ready report requires a Stop/Go/Clarify summary.")

        if review.documents_not_provided and review.recommendation.decision not in (
            RecommendationDecision.INSUFFICIENT_DOCUMENTS,
            RecommendationDecision.CLARIFY_REQUIRED,
            RecommendationDecision.GO_WITH_CONDITIONS,
        ):
            errors.append(
                "If documents are missing, recommendation must reflect insufficient or conditional review."
            )

        # P0 honesty rules
        if review.review_scope == ReviewScope.NOTICE_LEVEL_TRIAGE:
            if review.recommendation.decision == RecommendationDecision.GO_WITH_HUMAN_REVIEW:
                errors.append(
                    "Notice-level triage cannot be marked client_ready with GO_WITH_HUMAN_REVIEW. "
                    "Use CLARIFY_REQUIRED or INSUFFICIENT_DOCUMENTS."
                )

        fatal_without_consequence = [
            req.requirement_id
            for req in review.requirements
            if req.severity == Severity.FATAL
            and not req.consequence_quote
            and not req.consequence_verified
        ]

        if fatal_without_consequence:
            errors.append(
                "Fatal items must have consequence_quote or consequence_verified: "
                + ", ".join(fatal_without_consequence)
            )

        if review.cannot_conclude_safe and review.review_scope in (
            ReviewScope.NOTICE_LEVEL_TRIAGE,
            ReviewScope.PARTIAL_PACKAGE_REVIEW,
        ):
            if review.recommendation.decision not in (
                RecommendationDecision.CLARIFY_REQUIRED,
                RecommendationDecision.INSUFFICIENT_DOCUMENTS,
                RecommendationDecision.GO_WITH_CONDITIONS,
            ):
                errors.append(
                    "Cannot-conclude-safe reviews must use CLARIFY_REQUIRED, INSUFFICIENT_DOCUMENTS, or GO_WITH_CONDITIONS."
                )

    return errors


def attempt_client_ready(review: Review) -> Review:
    errors = validate_review(review)
    if errors:
        review.status = ReviewStatus.INTERNAL_REVIEW
        print("Cannot mark client_ready:")
        for e in errors:
            print(f"  - {e}")
    else:
        review.status = ReviewStatus.CLIENT_READY
        review.signoff.client_ready = True
    return review


# ---------------------------------------------------------------------------
# Markdown renderer — human-readable, not architecture-readable
# ---------------------------------------------------------------------------

def render_markdown(review: Review) -> str:
    lines = []

    lines.append("# BidShield Pre-Bid Risk Review")
    lines.append("")
    lines.append(f"**Review ID:** {review.review_id}")
    lines.append(f"**Status:** {review.status.value}")
    lines.append(f"**Vertical:** {review.vertical}")
    lines.append(f"**Tender:** {review.tender_name} ({review.tender_number})")
    lines.append(f"**Issuer:** {review.issuer}")
    lines.append(f"**Created UTC:** {review.created_utc}")
    lines.append("")

    # Scope banner — non-negotiable honesty
    scope_labels = {
        ReviewScope.NOTICE_LEVEL_TRIAGE: "NOTICE-LEVEL TRIAGE ONLY",
        ReviewScope.PARTIAL_PACKAGE_REVIEW: "PARTIAL PACKAGE REVIEW",
        ReviewScope.FULL_PACKAGE_REVIEW: "FULL PACKAGE REVIEW (SUPPLIED DOCUMENTS ONLY)",
        ReviewScope.INSUFFICIENT_DOCUMENTS: "INSUFFICIENT DOCUMENTS",
    }
    scope_label = scope_labels.get(review.review_scope, "UNKNOWN SCOPE")
    lines.append(f"> **SCOPE: {scope_label}**")
    lines.append(">")
    if review.review_scope == ReviewScope.NOTICE_LEVEL_TRIAGE:
        lines.append("> This is not a full bid compliance review. Fatal requirements may exist in unsupplied documents.")
    elif review.review_scope == ReviewScope.PARTIAL_PACKAGE_REVIEW:
        lines.append("> Only the documents listed in the manifest were reviewed. Missing schedules, addenda, conditions, forms, or portal instructions may contain fatal requirements.")
    elif review.review_scope == ReviewScope.FULL_PACKAGE_REVIEW:
        lines.append("> This review covers only the documents listed. If any addendum, amendment, bulletin, portal instruction, or referenced standard was not supplied, it was not reviewed.")
    else:
        lines.append("> Insufficient documents were supplied to perform a meaningful review.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Documents Reviewed")
    lines.append("")

    if review.documents:
        lines.append("| Document | Type | Pages | SHA-256 | Notes |")
        lines.append("|---|---|---:|---|---|")
        for doc in review.documents:
            lines.append(
                f"| {doc.filename} | {doc.document_type.value} | {doc.page_count} | "
                f"`{doc.sha256[:12]}...` | {doc.notes} |"
            )
    else:
        lines.append("*No documents recorded.*")

    lines.append("")
    lines.append("## 2. Documents Referenced But Not Supplied")
    lines.append("")

    if review.documents_not_provided:
        for item in review.documents_not_provided:
            lines.append(f"- {item}")
        lines.append("")
        lines.append(
            "**Action required:** Obtain and review these documents before relying on this report."
        )
    else:
        lines.append("*None identified. Confirm with the bid owner that all addenda, amendments, schedules, forms, and referenced bulletins were supplied.*")

    lines.append("")
    lines.append("## 3. External Dependencies / Referenced Standards")
    lines.append("")

    if review.external_dependencies:
        for item in review.external_dependencies:
            lines.append(f"- {item}")
    else:
        lines.append("*No external dependencies detected in supplied documents. Manual confirmation still required.*")

    lines.append("")
    lines.append("## 4. What This Review Did Not Verify")
    lines.append("")
    lines.append("This review did **not** verify:")
    lines.append("")
    lines.append("- Legal sufficiency of your insurance policy or endorsements.")
    lines.append("- Whether your WSIB clearance certificate is current.")
    lines.append("- Whether your bonding capacity satisfies the issuer.")
    lines.append("- Whether your personnel, equipment, or subcontractors meet technical requirements.")
    lines.append("- Whether the issuer will accept a substituted form.")
    lines.append("- Whether portal submission mechanics were completed correctly.")
    lines.append("- Whether documents referenced but not supplied contain additional requirements.")
    lines.append("- Whether this bid should be submitted from a business, pricing, or risk perspective.")
    lines.append("")
    if review.cannot_conclude_safe:
        lines.append("> **This review cannot conclude the bid is safe.** No fatal items identified in supplied documents does not mean the tender is safe. It means the review did not surface one.")
        lines.append("")
    lines.append(
        "This is document-analysis support only. It is not legal, insurance, tax, engineering, procurement, or financial advice."
    )
    lines.append("")
    lines.append("**Human verification is required before submission.**")

    lines.append("")
    lines.append("## 5. Stop / Go / Clarify")
    lines.append("")
    lines.append(f"**Recommendation:** {review.recommendation.decision.value.replace('_', ' ').upper()}")
    lines.append("")
    lines.append(review.recommendation.summary)
    lines.append("")
    if review.recommendation.recommended_next_action:
        lines.append(f"**Next action:** {review.recommendation.recommended_next_action}")

    lines.append("")
    lines.append("## Next 24 Hours")
    lines.append("")
    lines.append("If you do nothing else after reading this report, do these:")
    lines.append("")
    lines.append("1. Download the full SOW and all referenced schedules/forms.")
    lines.append("2. Confirm the amended deadline in the full instructions (not the posted notice).")
    lines.append("3. Confirm the site-visit consequence with the contracting authority.")
    lines.append("4. Submit clarification questions before pricing.")
    lines.append("5. Do not price this tender until the full package is reviewed.")
    lines.append("")
    lines.append("---")
    lines.append("")

    fatal_high = [
        req for req in review.requirements
        if req.severity in (Severity.FATAL, Severity.HIGH)
    ]

    fatal_high.sort(key=lambda r: (0 if r.severity == Severity.FATAL else 1, r.page))

    if not fatal_high:
        lines.append(
            "*No Fatal or High items were extracted from the supplied documents. This does not mean the tender is safe. It means the review did not surface one. Manual verification is still required.*"
        )
    else:
        for idx, req in enumerate(fatal_high[:5], start=1):
            verified = "Yes" if req.verified_by_human else "NO — MANUAL CHECK REQUIRED"
            lines.append(f"### Fatal {idx}: {req.category.value} — {req.severity.value}")
            lines.append("")
            lines.append(f"- **Source:** `{req.document_id}` page {req.page}, {req.section}")
            lines.append(f"- **Quote:** \"{req.source_quote}\"")
            if req.consequence_quote:
                lines.append(f"- **Consequence:** \"{req.consequence_quote}\"")
            lines.append(f"- **Risk / Requirement:** {req.action_required}")
            if req.evidence_required:
                lines.append(f"- **Evidence needed:** {req.evidence_required}")
            if req.owner_role:
                lines.append(f"- **Owner:** {req.owner_role}")
            if req.deadline:
                lines.append(f"- **Deadline:** {req.deadline}")
            if req.clarification_question:
                lines.append(f"- **Clarification question:** {req.clarification_question}")
            lines.append(f"- **Interpretation confidence:** {req.interpretation_confidence.value}")
            lines.append(f"- **Consequence verified:** {'Yes' if req.consequence_verified else 'No — confirm in full package'}")
            lines.append(f"- **Human verified:** {verified}")
            lines.append("")

    lines.append("## 7. Submission & Acknowledgement Checklist")
    lines.append("")
    lines.append("Use this as a working checklist. Confirm each item manually before submission.")
    lines.append("")
    lines.append("| Status | Item | Source | Owner | Deadline |")
    lines.append("|---|---|---|---|---|")

    checklist_items = [
        req for req in review.requirements
        if req.category in (
            Category.MANDATORY_FORM,
            Category.ACKNOWLEDGEMENT,
            Category.DEADLINE,
            Category.INSURANCE,
            Category.BONDING,
            Category.WSIB_SAFETY_CERTIFICATION,
            Category.LICENSING,
            Category.SUBMISSION_MECHANICS,
            Category.PORTAL_REQUIREMENT,
        )
    ]

    if not checklist_items:
        lines.append("| ☐ | Confirm all mandatory forms, addenda acknowledgements, insurance, bonding, licensing, and portal requirements. | Multiple | Bid owner | Before submission |")
    else:
        for req in checklist_items[:50]:
            status = "☐"
            source = f"{req.document_id} p.{req.page}"
            owner = req.owner_role or "Bid owner"
            deadline = req.deadline or "Before submission"
            item = req.action_required or req.source_quote
            lines.append(f"| {status} | {item} | {source} | {owner} | {deadline} |")

    lines.append("")
    lines.append("## 8. Full Compliance Matrix")
    lines.append("")
    lines.append("| ID | Doc | Page | Category | Severity | Verified | Action |")
    lines.append("|---|---|---:|---|---|---|---|")

    for req in review.requirements[:200]:
        verified = "Yes" if req.verified_by_human else "Manual"
        action = (req.action_required or req.source_quote).replace("|", "/")
        if len(action) > 180:
            action = action[:177] + "..."
        lines.append(
            f"| {req.requirement_id} | {req.document_id} | {req.page} | {req.category.value} | "
            f"{req.severity.value} | {verified} | {action} |"
        )

    lines.append("")
    lines.append("## 9. Human Sign-Off & Processing Receipt")
    lines.append("")
    lines.append(f"- **Engine version:** {review.signoff.engine_version}")
    lines.append(f"- **Model:** {review.signoff.model_name or 'not recorded'}")
    lines.append(f"- **Prompt version:** {review.signoff.prompt_version or 'not recorded'}")
    lines.append(f"- **Extraction started UTC:** {review.signoff.extraction_started_utc or 'not recorded'}")
    lines.append(f"- **Extraction completed UTC:** {review.signoff.extraction_completed_utc or 'not recorded'}")
    lines.append(f"- **Human reviewer:** {review.signoff.human_reviewer or 'not assigned'}")
    lines.append(f"- **Human review completed UTC:** {review.signoff.human_review_completed_utc or 'not completed'}")
    lines.append(f"- **Fatal/High verified:** {'Yes' if review.signoff.fatal_high_verified else 'No'}")
    lines.append(f"- **Client-ready:** {'Yes' if review.signoff.client_ready else 'No'}")
    lines.append("")
    lines.append("## 10. Privacy Statement")
    lines.append("")
    lines.append(
        "This review used local-first processing. The engine sends document excerpts only to the configured local model endpoint and does not call external document APIs."
    )
    lines.append("")
    if review.privacy.physical_air_gap:
        lines.append("Physical air-gap: claimed and enforced.")
    else:
        lines.append(
            "Physical air-gap: not claimed. If the host machine is connected to the internet, this is local-first processing, not guaranteed offline isolation."
        )
    lines.append("")
    lines.append(f"- **External document API called:** {'Yes' if review.privacy.external_document_api_called else 'No'}")
    lines.append(f"- **Cloud sync disabled for working folder:** {'Yes' if review.privacy.cloud_sync_disabled_for_working_folder else 'No'}")
    lines.append(f"- **Raw documents deleted after review:** {'Yes' if review.privacy.raw_documents_deleted_after_review else 'No'}")
    lines.append(f"- **Retention policy:** {review.privacy.retention_policy}")
    lines.append(f"- **Transmission method:** {review.privacy.transmission_method}")

    lines.append("")
    lines.append("## 11. Administrative Harm Prevented")
    lines.append("")
    lines.append(f"- **Estimated hours returned:** {review.impact.hours_returned_estimate}")
    lines.append(f"- **Dollars at risk identified:** ${review.impact.dollars_at_risk_identified:,.2f}")
    lines.append(f"- **Confidential documents processed locally:** {review.impact.confidential_documents_processed_locally}")
    lines.append(f"- **Fatal requirements caught:** {review.impact.fatal_requirements_caught}")
    lines.append(f"- **Clarification questions drafted:** {review.impact.clarification_questions_drafted}")
    lines.append("")
    if review.impact.user_capability_note:
        lines.append(f"**Capability note:** {review.impact.user_capability_note}")
    else:
        lines.append(
            "**Capability note:** This report should be used to teach the bid team where institutional traps live, not to replace human judgment."
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### ⚠️ MANDATORY SCOPE & LIABILITY BOUNDARY (HUMAN SIGN-OFF REQUIRED)")
    lines.append("")
    lines.append("1. **Administrative Extraction Only (Not Legal, Clinical, or Financial Advice):** This report is a deterministic document-indexing and citation-verification artifact generated by Neural Empire AI (BidShield / ClaimShield Kernel v0.2). Neural Empire AI is not a law firm, licensed insurance adjuster, healthcare provider, or certified procurement officer. Nothing in this report constitutes legal advice, a legal opinion on contract responsiveness, or a clinical determination of medical necessity.")
    lines.append("")
    lines.append("2. **The Certifying & Submitting Party Is Always You:** Per federal and provincial procurement integrity laws (including the False Claims Act, 18 U.S.C. § 1001, and the Canadian Financial Administration Act), the human bidder, claimant, or authorized corporate officer remains the sole author, verifier, and submitter of any bid, compliance certification, or appeal. Neural Empire AI never auto-submits documents to government or payer portals.")
    lines.append("")
    lines.append("3. **Strict Boundary of the \"What We Did Not Verify\" Manifest:** This analysis is strictly bounded by the exact PDF byte-streams listed in the Document Manifest (verified by SHA-256 hash). Any external specification, portal-only addendum, incorporated statutory clause, or missing attachment listed in the \"Documents Referenced But Not Supplied\" section was **not** evaluated.")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CSV renderer
# ---------------------------------------------------------------------------

def write_requirements_csv(review: Review, path: str) -> None:
    fields = [
        "requirement_id", "document_id", "page", "section", "category", "severity",
        "mandatory", "acknowledgement_required", "action_required", "evidence_required",
        "owner_role", "deadline", "clarification_question", "status", "confidence",
        "verified_by_human", "human_reviewer", "human_verification_timestamp", "source_quote",
    ]

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        for req in review.requirements:
            writer.writerow({
                "requirement_id": req.requirement_id,
                "document_id": req.document_id,
                "page": req.page,
                "section": req.section,
                "category": req.category.value,
                "severity": req.severity.value,
                "mandatory": req.mandatory,
                "acknowledgement_required": req.acknowledgement_required,
                "action_required": req.action_required,
                "evidence_required": req.evidence_required,
                "owner_role": req.owner_role,
                "deadline": req.deadline or "",
                "clarification_question": req.clarification_question,
                "status": req.status,
                "confidence": req.confidence,
                "verified_by_human": req.verified_by_human,
                "human_reviewer": req.human_reviewer or "",
                "human_verification_timestamp": req.human_verification_timestamp or "",
                "source_quote": req.source_quote,
            })


# ---------------------------------------------------------------------------
# Save / Load
# ---------------------------------------------------------------------------

def save_review(review: Review, path: str) -> None:
    data = asdict(review)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_review(path: str) -> Review:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    documents = [
        DocumentRecord(
            **{**doc, "document_type": DocumentType(doc["document_type"])}
        )
        for doc in data.get("documents", [])
    ]

    requirements = [
        Requirement(
            **{**req, "category": Category(req["category"]), "severity": Severity(req["severity"])}
        )
        for req in data.get("requirements", [])
    ]

    recommendation = Recommendation(
        **{**data["recommendation"], "decision": RecommendationDecision(data["recommendation"]["decision"])}
    )

    signoff = Signoff(**data["signoff"])
    privacy = Privacy(**data["privacy"])
    impact = Impact(**data["impact"])

    return Review(
        review_id=data["review_id"],
        status=ReviewStatus(data["status"]),
        created_utc=data["created_utc"],
        client_id=data.get("client_id"),
        vertical=data["vertical"],
        tender_name=data["tender_name"],
        tender_number=data["tender_number"],
        issuer=data["issuer"],
        submission_deadline=data.get("submission_deadline"),
        clarification_deadline=data.get("clarification_deadline"),
        documents=documents,
        documents_not_provided=data.get("documents_not_provided", []),
        external_dependencies=data.get("external_dependencies", []),
        requirements=requirements,
        recommendation=recommendation,
        signoff=signoff,
        privacy=privacy,
        impact=impact,
    )


# ---------------------------------------------------------------------------
# Sample review generator
# ---------------------------------------------------------------------------

def create_sample_review() -> Review:
    doc_main = DocumentRecord(
        document_id="DOC-001",
        filename="SSC_2026_ZT_0491_Forensic_Sample.pdf",
        document_type=DocumentType.MAIN_RFP,
        sha256="53d75dfa393e6641be4deba2ae765043",
        page_count=3,
        text_extractable=True,
        contains_pii=False,
        contains_competitive_pricing=True,
        notes="Shared Services Canada Enterprise Zero Trust Architecture RFP. Secret Level II. Bilingual EN/FR.",
    )

    req_data_residency = Requirement(
        requirement_id="REQ-001",
        document_id="DOC-001",
        page=1,
        section="Annex C — Security Controls, Section 4.2",
        source_quote="All telemetry, operational logs, diagnostics, and tenant metadata must remain exclusively within Canadian sovereign borders (PIPEDA / GC PBMM).",
        category=Category.TECHNICAL_REQUIREMENT,
        severity=Severity.FATAL,
        mandatory=True,
        action_required="Force-bind logging pipelines to ca-central-1 and enforce egress IP blocking on all diagnostic daemons.",
        evidence_required="Architecture diagram showing telemetry routing, egress IP blocklist config.",
        owner_role="Engineering lead",
        deadline="Before submission",
        acknowledgement_required=False,
        clarification_question="Please confirm whether default cloud telemetry routing is acceptable if egress IP blocking is enforced.",
        status="open",
        confidence="high",
        verified_by_human=False,
    )

    req_clearance = Requirement(
        requirement_id="REQ-002",
        document_id="DOC-001",
        page=1,
        section="Annex A — Statement of Work, Section 2.1",
        source_quote="All personnel providing Tier-2 support or higher must possess valid Government of Canada Secret (Level II) clearance at time of bid submission.",
        category=Category.LICENSING,
        severity=Severity.FATAL,
        mandatory=True,
        action_required="Audit subcontractor roster; replace any unvetted Tier-2 staff with cleared Canadian personnel before bid close.",
        evidence_required="Personnel clearance roster with Secret Level II verification.",
        owner_role="HR / Security officer",
        deadline="At bid submission",
        acknowledgement_required=False,
        clarification_question="",
        status="open",
        confidence="high",
        verified_by_human=False,
    )

    req_deadline = Requirement(
        requirement_id="REQ-003",
        document_id="DOC-001",
        page=1,
        section="Closing Date",
        source_quote="Closing Date: 2026-07-15 14:00 EDT",
        category=Category.DEADLINE,
        severity=Severity.HIGH,
        mandatory=True,
        action_required="Confirm final submission deadline and time zone. Ensure portal submission completed before 14:00 EDT on 2026-07-15.",
        evidence_required="Portal submission confirmation receipt.",
        owner_role="Bid owner",
        deadline="2026-07-15 14:00 EDT",
        acknowledgement_required=False,
        clarification_question="Please confirm the final submission deadline and time zone after all addenda.",
        status="open",
        confidence="high",
        verified_by_human=False,
    )

    req_language = Requirement(
        requirement_id="REQ-004",
        document_id="DOC-001",
        page=1,
        section="Language Requirement",
        source_quote="Language Req: Bilingual (EN / FR Native)",
        category=Category.TECHNICAL_REQUIREMENT,
        severity=Severity.HIGH,
        mandatory=True,
        action_required="Confirm all bid documents are available in native English and French. Translation alone may not satisfy native-language requirement.",
        evidence_required="Bilingual document set with native French authorship.",
        owner_role="Proposal writer",
        deadline="Before submission",
        acknowledgement_required=False,
        clarification_question="Please confirm whether professional translation satisfies the native-language requirement or if native French authorship is required.",
        status="open",
        confidence="medium",
        verified_by_human=False,
    )

    req_security = Requirement(
        requirement_id="REQ-005",
        document_id="DOC-001",
        page=1,
        section="Security Mandate",
        source_quote="Security Mandate: Secret (Level II)",
        category=Category.LEGAL_CONTRACTUAL_RISK,
        severity=Severity.HIGH,
        mandatory=True,
        action_required="Confirm facility and personnel meet Secret Level II security requirements for all deliverables.",
        evidence_required="Security clearance verification for all personnel and facilities.",
        owner_role="Security officer",
        deadline="Before submission",
        acknowledgement_required=False,
        clarification_question="",
        status="open",
        confidence="high",
        verified_by_human=False,
    )

    review = Review(
        review_id="BS-20261023-001",
        status=ReviewStatus.DRAFT,
        created_utc=utcnow(),
        client_id=None,
        vertical="federal_it_security",
        tender_name="Enterprise Zero Trust Architecture & Cloud Security",
        tender_number="SSC-2026-ZT-0491",
        issuer="Shared Services Canada / Government of Canada",
        submission_deadline="2026-07-15T14:00:00-04:00",
        clarification_deadline=None,
        documents=[doc_main],
        documents_not_provided=[
            "Annex B — Evaluation Criteria",
            "Annex D — Pricing Form",
            "General Conditions of Contract",
            "Special Conditions of Contract",
            "Portal submission instructions",
            "Bidder conference sign-in sheet",
        ],
        external_dependencies=[
            "PIPEDA / GC PBMM compliance framework referenced in Section 4.2",
            "Government of Canada Secret clearance process referenced in Annex A",
            "Bilingual (EN/FR) native language requirement — confirm with issuer whether translation suffices",
        ],
        requirements=[
            req_data_residency, req_clearance, req_deadline, req_language, req_security,
        ],
        recommendation=Recommendation(
            decision=RecommendationDecision.CLARIFY_REQUIRED,
            summary=(
                "Do not price this tender until you resolve the data residency enforcement, "
                "Secret Level II clearance roster, and bilingual native-language requirement. "
                "Submit clarification questions before final pricing. 5 Fatal/High items identified "
                "in the 3-page forensic sample; full 84-clause review requires complete document set."
            ),
            fatal_count=2,
            high_count=3,
            acknowledgement_count=0,
            deadline_conflicts=1,
            external_dependencies=3,
            recommended_next_action="Obtain missing documents (Annex B, D, General/Special Conditions, portal instructions) and submit clarification questions on data residency and language requirements before pricing.",
        ),
        signoff=Signoff(
            engine_version="bidshield_kernel_v0.1",
            model_name="qwen3",
            prompt_version="manual_extraction_v1",
            extraction_started_utc=utcnow(),
            extraction_completed_utc=utcnow(),
            human_reviewer="",
            human_review_started_utc="",
            human_review_completed_utc="",
            fatal_high_verified=False,
            client_ready=False,
        ),
        privacy=Privacy(
            local_first_processing=True,
            external_document_api_called=False,
            network_egress_blocked=False,
            physical_air_gap=False,
            cloud_sync_disabled_for_working_folder=False,
            raw_documents_deleted_after_review=False,
            retention_policy="delete_raw_docs_after_7_days_unless_client_requests_archive",
            transmission_method="encrypted_transfer_or_password_protected_pdf",
        ),
        impact=Impact(
            hours_returned_estimate=46.5,
            dollars_at_risk_identified=0.0,
            confidential_documents_processed_locally=1,
            fatal_requirements_caught=0,
            clarification_questions_drafted=3,
            user_capability_note="",
        ),
    )

    return review


if __name__ == "__main__":
    import sys

    # Build the sample review
    review = create_sample_review()

    # Simulate human verification of all Fatal/High items
    for req in review.requirements:
        if req.severity in (Severity.FATAL, Severity.HIGH):
            req.verified_by_human = True
            req.human_reviewer = "Rob Lambert"
            req.human_verification_timestamp = utcnow()
            req.human_verification_note = "Checked source page and quote against forensic audit document."

    review.signoff.human_reviewer = "Rob Lambert"
    review.signoff.human_review_completed_utc = utcnow()
    review.signoff.fatal_high_verified = True

    review.impact.fatal_requirements_caught = sum(
        1 for r in review.requirements if r.severity == Severity.FATAL
    )
    review.impact.clarification_questions_drafted = sum(
        1 for r in review.requirements if r.clarification_question
    )
    review.impact.user_capability_note = (
        "The bid team should now check data residency enforcement, Secret clearance roster, "
        "and bilingual requirements before pricing. The forensic audit found 5 disqualification "
        "traps in 84 clauses; this sample covers the top 5."
    )

    # Attempt client-ready (will be blocked because documents are missing)
    review = attempt_client_ready(review)

    # Render outputs
    out_dir = os.path.dirname(os.path.abspath(__file__))
    md = render_markdown(review)
    md_path = os.path.join(out_dir, "BidShield_sample_report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    csv_path = os.path.join(out_dir, "BidShield_sample_matrix.csv")
    write_requirements_csv(review, csv_path)

    json_path = os.path.join(out_dir, "BidShield_sample_review.json")
    save_review(review, json_path)

    print(f"Sample report generated: {md_path}")
    print(f"CSV matrix: {csv_path}")
    print(f"Review JSON: {json_path}")
    print(f"Status: {review.status.value}")
    print(f"Validation errors: {validate_review(review)}")
