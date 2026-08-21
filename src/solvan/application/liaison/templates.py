"""The claim-template registry: the only source of factual sentence forms.

A gate that trusts a model-authored claim kind is prompt discipline wearing a
schema. So the model never authors one. It selects a template id and fills
typed slots; this module owns the kind, the polarity, the sentence, and which
verifier decides whether the claim may be said at all.

The registry is pinned by digest at startup exactly like the tool registry:
configuration drift refuses to serve rather than silently widening what the
Liaison may assert. Specification 14 §7 governs.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml

#: Slot references inside a sentence form, e.g. `{subject_label}`.
_SLOT = re.compile(r"\{([a-z_]+)\}")


class TemplateRegistryError(RuntimeError):
    """The template registry is unusable; the service must refuse to serve."""


class Polarity(StrEnum):
    AFFIRMATIVE = "AFFIRMATIVE"
    HOLDING = "HOLDING"
    NEUTRAL = "NEUTRAL"


@dataclass(frozen=True, slots=True)
class SlotSource:
    """Where one rendered word comes from.

    A predicate can be perfectly true and the sentence around it still a
    fabrication, because the predicate checks the citation while the slots
    carry the prose. So slots are bound: `record`/`field` means the application
    reads the value and discards whatever the model supplied.
    """

    kind: str  # RECORD | SUBJECT | HOLDING_REASON | MODEL_QUOTED
    record_type: str | None = None
    field: str | None = None


@dataclass(frozen=True, slots=True)
class ClaimTemplate:
    """One sayable factual form, owned by configuration and code together."""

    id: str
    kind: str
    polarity: Polarity
    held: bool
    sentence: str
    slots: tuple[str, ...]
    slot_sources: dict[str, SlotSource]
    predicate: str
    releasing_record: str | None
    holding_template: str | None

    def render(self, values: dict[str, str]) -> str:
        """Fill the sentence from typed slots.

        A missing or unexpected slot is a defect, not a formatting nicety: the
        rendered sentence is what a reader will treat as Solvan's word.
        """

        missing = [slot for slot in self.slots if slot not in values]
        if missing:
            raise TemplateRegistryError(
                f"template {self.id} is missing slot values: {', '.join(sorted(missing))}"
            )
        extra = [key for key in values if key not in self.slots]
        if extra:
            raise TemplateRegistryError(
                f"template {self.id} received unknown slots: {', '.join(sorted(extra))}"
            )
        return self.sentence.format(**values)


@dataclass(frozen=True, slots=True)
class ConnectiveTemplate:
    """Non-factual joining text. Enumerated so prose carries no assertion."""

    id: str
    sentence: str
    slots: tuple[str, ...]
    allowed_leads: tuple[str, ...]

    def render(self, value: str) -> str:
        if value not in self.allowed_leads:
            raise TemplateRegistryError(
                f"connective {self.id} does not permit the phrase {value!r}"
            )
        return self.sentence.format(**{self.slots[0]: value})


@dataclass(frozen=True, slots=True)
class TemplateRegistry:
    """The loaded, validated registry plus the digest the service pins."""

    templates: dict[str, ClaimTemplate]
    connectives: dict[str, ConnectiveTemplate]
    digest: str

    def claim(self, template_id: str) -> ClaimTemplate:
        template = self.templates.get(template_id)
        if template is None:
            raise TemplateRegistryError(f"unknown claim template {template_id}")
        return template

    def connective(self, template_id: str) -> ConnectiveTemplate:
        template = self.connectives.get(template_id)
        if template is None:
            raise TemplateRegistryError(f"unknown connective template {template_id}")
        return template

    def held_ids(self) -> frozenset[str]:
        return frozenset(item.id for item in self.templates.values() if item.held)


_SLOT_KINDS = frozenset({"RECORD", "SUBJECT", "HOLDING_REASON", "MODEL_QUOTED"})


def _slot_source(raw: Any) -> SlotSource:
    """Parse one slot binding, failing closed on anything unrecognised."""

    if isinstance(raw, str):
        if raw not in _SLOT_KINDS or raw == "RECORD":
            raise TemplateRegistryError(f"unknown slot source {raw!r}")
        return SlotSource(kind=raw)
    if isinstance(raw, dict) and "record" in raw and "field" in raw:
        return SlotSource(kind="RECORD", record_type=str(raw["record"]), field=str(raw["field"]))
    raise TemplateRegistryError(f"malformed slot source: {raw!r}")


def _validate_claim(raw: dict[str, Any], known_predicates: frozenset[str]) -> ClaimTemplate:
    try:
        template = ClaimTemplate(
            id=str(raw["id"]),
            kind=str(raw["kind"]),
            polarity=Polarity(str(raw["polarity"])),
            held=bool(raw["held"]),
            sentence=str(raw["sentence"]),
            slots=tuple(str(item) for item in raw["slots"]),
            slot_sources={
                str(name): _slot_source(value)
                for name, value in (raw.get("slot_sources") or {}).items()
            },
            predicate=str(raw["predicate"]),
            releasing_record=None
            if raw.get("releasing_record") is None
            else str(raw["releasing_record"]),
            holding_template=None
            if raw.get("holding_template") is None
            else str(raw["holding_template"]),
        )
    except (KeyError, ValueError) as error:
        raise TemplateRegistryError(f"malformed claim template: {error}") from error

    if template.predicate not in known_predicates:
        raise TemplateRegistryError(
            f"template {template.id} names predicate {template.predicate}, "
            "which has no implementation"
        )
    # The sentence and the declared slots must agree exactly, so a template
    # cannot smuggle an unfilled placeholder or ignore a supplied value.
    referenced = set(_SLOT.findall(template.sentence))
    if referenced != set(template.slots):
        raise TemplateRegistryError(
            f"template {template.id} sentence slots {sorted(referenced)} "
            f"do not match declared slots {sorted(template.slots)}"
        )
    # Every slot must declare where its words come from, and a held template may
    # not take any of them from the model: an affirmative claim whose sentence
    # the model wrote is exactly the failure this registry exists to prevent.
    unbound = [slot for slot in template.slots if slot not in template.slot_sources]
    if unbound:
        raise TemplateRegistryError(
            f"template {template.id} leaves slots unbound: {', '.join(sorted(unbound))}"
        )
    if template.held:
        model_written = [
            slot for slot, source in template.slot_sources.items() if source.kind == "MODEL_QUOTED"
        ]
        if model_written:
            raise TemplateRegistryError(
                f"held template {template.id} may not render model text: "
                f"{', '.join(sorted(model_written))}"
            )

    # A held template must name both what releases it and what to say meanwhile.
    if template.held:
        if template.polarity is not Polarity.AFFIRMATIVE:
            raise TemplateRegistryError(f"held template {template.id} must be affirmative")
        if template.releasing_record is None or template.holding_template is None:
            raise TemplateRegistryError(
                f"held template {template.id} must name a releasing record and a holding template"
            )
    return template


def _validate_connective(raw: dict[str, Any]) -> ConnectiveTemplate:
    try:
        template = ConnectiveTemplate(
            id=str(raw["id"]),
            sentence=str(raw["sentence"]),
            slots=tuple(str(item) for item in raw["slots"]),
            allowed_leads=tuple(str(item) for item in raw["allowed_leads"]),
        )
    except KeyError as error:
        raise TemplateRegistryError(f"malformed connective template: {error}") from error
    if len(template.slots) != 1:
        raise TemplateRegistryError(f"connective {template.id} must declare exactly one slot")
    if not template.allowed_leads:
        raise TemplateRegistryError(f"connective {template.id} permits no phrases")
    return template


def load_registry(path: Path, *, known_predicates: frozenset[str]) -> TemplateRegistry:
    """Load, validate, and digest the registry, or refuse to serve."""

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise TemplateRegistryError(f"template registry is unreadable: {error}") from error
    document = yaml.safe_load(raw_text)
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise TemplateRegistryError("template registry must declare schema_version 1")

    templates: dict[str, ClaimTemplate] = {}
    for entry in document.get("templates", []):
        template = _validate_claim(entry, known_predicates)
        if template.id in templates:
            raise TemplateRegistryError(f"duplicate claim template {template.id}")
        templates[template.id] = template

    connectives: dict[str, ConnectiveTemplate] = {}
    for entry in document.get("connectives", []):
        connective = _validate_connective(entry)
        if connective.id in connectives:
            raise TemplateRegistryError(f"duplicate connective template {connective.id}")
        connectives[connective.id] = connective

    if not templates:
        raise TemplateRegistryError("template registry declares no claim templates")

    # Holding references must resolve, and a holding form may not itself be held
    # — otherwise a refusal could recurse into another refusal.
    for template in templates.values():
        if template.holding_template is None:
            continue
        holding = templates.get(template.holding_template)
        if holding is None:
            raise TemplateRegistryError(
                f"template {template.id} names missing holding template {template.holding_template}"
            )
        if holding.held:
            raise TemplateRegistryError(f"holding template {holding.id} must not itself be held")

    digest = f"sha256:{hashlib.sha256(raw_text.encode('utf-8')).hexdigest()}"
    return TemplateRegistry(templates=templates, connectives=connectives, digest=digest)


def pin_registry(registry: TemplateRegistry, expected_digest: str) -> TemplateRegistry:
    """Refuse to serve when the pinned digest and the loaded registry differ.

    The pin is mandatory. It previously accepted `None` as "record the current
    digest", which made the control absent by default: an edited template file
    reached production with nothing to compare against. A template change must
    change the pin in the same reviewed commit (§7 governance).
    """

    if expected_digest != registry.digest:
        raise TemplateRegistryError(
            "claim template registry digest does not match the pinned value; refusing to serve"
        )
    return registry


def registry_manifest(registry: TemplateRegistry) -> str:
    """A stable, sorted description used by tests and audit records."""

    return json.dumps(
        {
            "digest": registry.digest,
            "templates": {
                item.id: {
                    "kind": item.kind,
                    "polarity": str(item.polarity),
                    "held": item.held,
                    "predicate": item.predicate,
                    "releasing_record": item.releasing_record,
                }
                for item in sorted(registry.templates.values(), key=lambda entry: entry.id)
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    )
