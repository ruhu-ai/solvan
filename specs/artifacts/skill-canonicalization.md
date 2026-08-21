# Agent Skills canonicalization profile

Status: target implementation artifact; excluded from the Minimum Submittable
Release gate.

Version: `skill-canonicalization/1`

This file is the executable definition of the four hashes in specification 18
§8. Implementations must use these rules and the test vectors below; an
implementation must not substitute a generic archive hash or JSON serializer.

## Normalized file records

1. Archive member names are decoded as UTF-8, normalized to Unicode NFC, and
   converted to relative POSIX paths. NUL bytes, empty components, `.` or `..`
   components, backslashes, absolute paths, and names that normalize to the
   same path are rejected.
2. File bytes are preserved for hashing except that UTF-8 prompt files are
   normalized to LF and a UTF-8 BOM is removed. Binary/inert files are hashed
   byte-for-byte. File modes, ownership, symlinks, hard links, special files,
   and empty directories are not part of a manifest.
3. A manifest is a UTF-8 JSON array of objects with exactly `path`, `size`, and
   `sha256` keys. Objects are sorted by the UTF-8 byte sequence of `path`;
   JSON uses sorted keys, no insignificant whitespace, UTF-8 output, and no
   escaping of non-ASCII characters. `size` is the normalized byte length and
   `sha256` is the lowercase hexadecimal SHA-256 of the normalized bytes.

## Domain-separated hashes

The digest input is the ASCII domain prefix, a NUL byte, the ASCII decimal
length of the manifest, a NUL byte, and the manifest bytes. The prefixes are:

| Digest | Prefix | Manifest contents |
|---|---|---|
| `source_bundle_hash` | `solvan/skill/source-bundle/v1` | exact uploaded archive bytes, or the provider's canonical subtree manifest |
| `normalized_package_hash` | `solvan/skill/normalized-package/v1` | every accepted file plus its disposition |
| `guidance_content_hash` | `solvan/skill/guidance-content/v1` | `SKILL.md` body and `references/*.md` only |
| `export_bundle_hash` | `solvan/skill/export-bundle/v1` | exact deterministic export bytes, represented as one `bytes` manifest record |

The displayed form is always `sha256:<64 lowercase hexadecimal characters>`.
No digest may be reused as another digest merely because the underlying bytes
are equal.

## Deterministic export container

Exports use ZIP with DEFLATE level 9. Entries are sorted by normalized POSIX
path, timestamps are `1980-01-01T00:00:00Z`, permissions are regular-file
`0644`, and no directory entries are emitted. The ZIP comment is empty and
entry extra fields are empty. The package contains only the conforming
`SKILL.md`, `references/*.md`, and generated provenance metadata described in
specification 18 §9.

## Test vectors

For the one-file manifest `[{'path':'SKILL.md','size':3,'sha256':'acbd18db4cc2f85cedef654fccc4a4d8'}]`
where the bytes are `abc`, implementations must verify the vectors in
`tests/unit/test_skill_interchange.py`. The test suite also verifies NFC/path
collision rejection, domain separation, deterministic export bytes, and
round-trip content-hash equality. New vectors require a new profile version.
