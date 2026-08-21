import pytest

from solvan.domain import IdentifierError, new_identifier, validate_identifier


def test_identifier_has_canonical_prefix_timestamp_and_randomness() -> None:
    identifier = new_identifier(
        "inc",
        timestamp_ms=1_754_650_000_000,
        randomness=bytes.fromhex("00112233445566778899"),
    )

    assert identifier == "inc_01K24MMEM0008J4CT4ANK7F24S"
    assert validate_identifier(identifier, expected_prefix="inc") == identifier


def test_default_identifier_sources_time_and_randomness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("solvan.domain.identifiers.time.time", lambda: 1_754_650_000.0)
    monkeypatch.setattr(
        "solvan.domain.identifiers.secrets.token_bytes",
        lambda count: bytes.fromhex("00112233445566778899") if count == 10 else b"",
    )

    assert new_identifier("evt") == "evt_01K24MMEM0008J4CT4ANK7F24S"


@pytest.mark.parametrize("prefix", ["I", "incident", "i1", "_"])
def test_invalid_prefix_is_rejected(prefix: str) -> None:
    with pytest.raises(IdentifierError, match="prefix"):
        new_identifier(prefix, timestamp_ms=0, randomness=b"0" * 10)


@pytest.mark.parametrize("timestamp", [-1, 2**48])
def test_invalid_timestamp_is_rejected(timestamp: int) -> None:
    with pytest.raises(IdentifierError, match="timestamp_ms"):
        new_identifier("inc", timestamp_ms=timestamp, randomness=b"0" * 10)


def test_invalid_randomness_size_is_rejected() -> None:
    with pytest.raises(IdentifierError, match="10 bytes"):
        new_identifier("inc", timestamp_ms=0, randomness=b"short")


@pytest.mark.parametrize(
    "value",
    ["INC-0001", "inc_lowercase000000000000000000", "inc_0", f"inc_Z{'0' * 25}"],
)
def test_malformed_identifier_is_rejected(value: str) -> None:
    with pytest.raises(IdentifierError, match="type-prefixed"):
        validate_identifier(value)


def test_wrong_expected_prefix_is_rejected() -> None:
    value = new_identifier("inc", timestamp_ms=0, randomness=b"0" * 10)
    with pytest.raises(IdentifierError, match="does not match"):
        validate_identifier(value, expected_prefix="rel")
