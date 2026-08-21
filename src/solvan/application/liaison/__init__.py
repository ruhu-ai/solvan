"""The conversational surface: a mouth for the ledger, and nothing more.

The narrator never knows more than the ledger, and never does more than speak
or request. Specification 14 is the governing contract; this package is its
executable core — templates and predicates (what may be said), grants (on whose
behalf), anchors (about what), and parts (how it is carried).
"""

from solvan.application.liaison.anchors import (
    ANCHORABLE_RECORD_TYPES,
    Anchor,
    AnchorError,
    AnchorKind,
    RecordDirectory,
    anchor_from_mapping,
    entity_set,
    resolve_anchor,
)
from solvan.application.liaison.claims import (
    ClaimDraft,
    ClaimOutcome,
    ComposedClaim,
    CompositionDefects,
    compose_all,
    compose_claim,
)
from solvan.application.liaison.context_compiler import (
    CompactionCandidate,
    CompiledContext,
    ContextBudget,
    ContextCompilationError,
    ReferenceCandidate,
    TranscriptMessage,
    TranscriptPart,
    compile_context,
    context_from_rows,
    select_compaction,
    select_complete_turns,
)
from solvan.application.liaison.grants import (
    Audience,
    ConversationReadGrant,
    GrantError,
    GrantIssuer,
    SteerSubmissionGrant,
    verify_read_request,
)
from solvan.application.liaison.memory_candidates import (
    MemoryCandidateDerivationError,
    derive_verified_outcome_proposal,
)
from solvan.application.liaison.parts import (
    AccessMode,
    AccessReference,
    Part,
    PartKind,
    Verb,
    claim_part,
    connective_part,
    reader_may_see,
    refusal_part,
)
from solvan.application.liaison.predicates import (
    KNOWN_PREDICATES,
    PREDICATES,
    Citation,
    PredicateResult,
    ProjectionReader,
)
from solvan.application.liaison.templates import (
    ClaimTemplate,
    Polarity,
    TemplateRegistry,
    TemplateRegistryError,
    load_registry,
    pin_registry,
    registry_manifest,
)

__all__ = [
    "ANCHORABLE_RECORD_TYPES",
    "KNOWN_PREDICATES",
    "PREDICATES",
    "AccessMode",
    "AccessReference",
    "Anchor",
    "AnchorError",
    "AnchorKind",
    "Audience",
    "Citation",
    "ClaimDraft",
    "ClaimOutcome",
    "ClaimTemplate",
    "CompactionCandidate",
    "CompiledContext",
    "ComposedClaim",
    "CompositionDefects",
    "ContextBudget",
    "ContextCompilationError",
    "ConversationReadGrant",
    "GrantError",
    "GrantIssuer",
    "MemoryCandidateDerivationError",
    "Part",
    "PartKind",
    "Polarity",
    "PredicateResult",
    "ProjectionReader",
    "RecordDirectory",
    "ReferenceCandidate",
    "SteerSubmissionGrant",
    "TemplateRegistry",
    "TemplateRegistryError",
    "TranscriptMessage",
    "TranscriptPart",
    "Verb",
    "anchor_from_mapping",
    "claim_part",
    "compile_context",
    "compose_all",
    "compose_claim",
    "connective_part",
    "context_from_rows",
    "derive_verified_outcome_proposal",
    "entity_set",
    "load_registry",
    "pin_registry",
    "reader_may_see",
    "refusal_part",
    "registry_manifest",
    "resolve_anchor",
    "select_compaction",
    "select_complete_turns",
    "verify_read_request",
]
