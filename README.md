![](https://github.com/enigmata/lockdown/workflows/Build%20and%20test/badge.svg) [![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/enigmata/lockdown.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/enigmata/lockdown/context:cpp)

# lockdown

A cryptographic library primarily focused on usability, performance, and
indestructability, and originally intended to support my _hephaestus_
project (coming soon).

### Status

Most certainly a work-in-progress, kicked off at the beginning of 2019.

## Cyptographic Hash Functions

The following is a list of the supported algorithms, together with some
algorithmic details and type representation in the library:

Family|Variant     |Library type             |Digest size|Block size |Rounds
------|------------|-------------------------|-----------|-----------|----
SHA-2 | SHA-224    |`crypto::sha224_hash`    |28 bytes   |64 bytes   |64
SHA-2 | SHA-256    |`crypto::sha256_hash`    |32 bytes   |64 bytes   |64
SHA-2 | SHA-384    |`crypto::sha384_hash`    |48 bytes   |128 bytes  |80
SHA-2 | SHA-512    |`crypto::sha512_hash`    |64 bytes   |128 bytes  |80
SHA-2 | SHA-512/224|`crypto::sha512_224_hash`|28 bytes   |128 bytes  |80
SHA-2 | SHA-512/256|`crypto::sha512_256_hash`|32 bytes   |128 bytes  |80
MD5   |            |N/A - cryptographically weak
SHA-0 |            |N/A - cryptographically weak
SHA-1 |            |N/A - cryptographically weak
