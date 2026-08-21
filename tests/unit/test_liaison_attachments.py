from apps.api.liaison_attachment_routes import _scan_attachment


def test_inert_text_and_matching_images_pass_the_local_quarantine_scanner() -> None:
    assert (
        _scan_attachment(claimed_mime="text/plain", content=b"bounded incident note")[0] == "CLEAN"
    )
    assert (
        _scan_attachment(claimed_mime="image/png", content=b"\x89PNG\r\n\x1a\nbody")[0] == "CLEAN"
    )


def test_credentials_active_formats_and_spoofed_images_are_blocked() -> None:
    assert (
        _scan_attachment(claimed_mime="text/plain", content=b"credential AKIAIOSFODNN7EXAMPLE")[0]
        == "BLOCKED"
    )
    assert (
        _scan_attachment(claimed_mime="application/zip", content=b"PK\x03\x04body")[0] == "BLOCKED"
    )
    assert _scan_attachment(claimed_mime="image/png", content=b"not-a-png")[0] == "BLOCKED"
