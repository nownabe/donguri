# Requirements: donguri — a CLI that encrypts and decrypts a file with a password

A CLI that encrypts a single file with a password and decrypts it with the same password. Encrypted files are expected to be stored for a long time and opened years later. **The top priority is that a file can always be opened, years from now, on a machine with no network access.**

Name: `donguri` (a squirrel buries acorns and digs them up months later). License: MIT. Suggested file extension: `.donguri` (not enforced).

## 1. Assumptions and constraints

- Use **only the Go standard library**. `go.mod` must have no `require` lines at all (no `golang.org/x/...` either). Minimum Go version: 1.24 (the release that added `crypto/pbkdf2` to the standard library)
- Do not design any cryptography. Use exactly the construction in "File format" below
- Security depends only on the password. Publishing the format does not weaken it, so document the format in full
- Targets small files (e.g. text containing secrets). The whole file is processed in memory. Maximum size: 16 MiB

## 2. File format (v1)

Fields are laid out in this order. Integers are big-endian.

| Offset | Length | Content                                     |
| ------ | ------ | ------------------------------------------- |
| 0      | 8      | Magic: ASCII `DONGURI` followed by `0x00`   |
| 8      | 1      | Format version: `0x01`                      |
| 9      | 1      | KDF identifier: `0x01` = PBKDF2-HMAC-SHA256 |
| 10     | 4      | Iteration count (uint32). Default 600,000   |
| 14     | 16     | Salt (`crypto/rand`)                        |
| 30     | 12     | Nonce (`crypto/rand`)                       |
| 42     | rest   | AES-256-GCM ciphertext + 16-byte tag        |

- Key: `pbkdf2.Key(sha256.New, password, salt, iterations, 32)`
- Encryption: AES-256-GCM. **Pass the first 42 bytes (the whole header) as additional authenticated data (AAD)**, so that any change to the header makes decryption fail
- Generate a fresh salt and nonce on every encryption. Never reuse them
- The plaintext is an arbitrary byte sequence
- On decryption, if the magic, version, or KDF identifier is unknown, say so and stop
- Never create or decrypt a file with an iteration count below 100,000 (so that weak files are neither produced nor accepted)

## 3. Commands

The password is **always read from the terminal, without echo** (`/dev/tty` on Unix, `CONIN$` on Windows). Standard input is reserved for data. If there is no terminal, fail with an error. Implement no-echo input per OS with the standard `syscall` package (`golang.org/x/term` is not allowed).

### `donguri encrypt -o <out> [<in>]`

- Read the plaintext from `<in>` (standard input if omitted), encrypt it, and write it to `<out>`
- Ask for the password twice; stop if they do not match
- Stop if `<out>` already exists (`--force` to overwrite)
- Write to a temporary file in the same directory, then rename, so a crash never leaves a broken file. Permissions 0600 (may be ignored on Windows)
- Immediately after writing, read the temporary file back, decrypt it, and confirm it matches the original plaintext before renaming it to `<out>` (to catch a faulty storage medium on the spot without destroying an existing `<out>`)

### `donguri decrypt <file>`

- Write the decrypted plaintext **to standard output only**. There is no option to write it to a file (to avoid leaving plaintext on disk; users can redirect if they need to)
- On failure, report "wrong password or corrupted file" (GCM cannot tell the two apart, so do not pretend to)

### `donguri verify <file> [<file2>]`

- Only check that the file decrypts; never print the plaintext. Output is `OK` or the reason for failure
- If `<file2>` is given, decrypt both and report whether the plaintexts are identical (for checking that copies kept in several places all open and still match; separately encrypted files have different salts and nonces, so comparing file hashes cannot tell). Ask for the password once and use it for both
- Exit code: 0 on success, 1 on failure

### Common

- `--version` prints the version and commit
- Messages are in English. Never print the plaintext, password, or key in logs or errors
- Overwrite password and key bytes with zeros after use (Go cannot guarantee this fully; do what is possible)

## 4. Release artifacts

Pushing a tag builds with GitHub Actions and publishes the following to the Release:

- Binaries (`CGO_ENABLED=0`, `-trimpath`): `windows/amd64`, `windows/arm64`, `linux/amd64`, `linux/arm64`, `darwin/arm64`
- **One bundle zip**: all of the binaries above + the full source + `README.md` + `FORMAT.md`. Keeping this one file should be enough to run the tool on any of these platforms, or to rebuild it from source
- `SHA256SUMS`: sha256 of every file in the Release (including the bundle zip)
- A build provenance attestation for every file in `SHA256SUMS`, signed in a job separate from the build; only that job has `id-token: write`

## 5. Documentation

- `README.md`: usage, how to verify the artifacts (`sha256sum -c SHA256SUMS`, and `gh attestation verify` pinned to `publish.yaml` and the tag), how to build from source (plain `go build` must be enough)
- `FORMAT.md`: describes the format in section 2 so that it can be read on its own. Include **how to decrypt without Go** (e.g. Python's `hashlib.pbkdf2_hmac` plus any AES-GCM implementation) and **test vectors** (password, salt, nonce, iteration count, plaintext, and the resulting encrypted file in hex). Even if this tool disappears, this document alone must be enough to decrypt a file

## 6. Tests

- Encrypt → decrypt round-trips (empty, 1 byte, exactly the maximum size). Input over the maximum is rejected
- Changing any single byte of the file makes decryption fail (every byte of the header, ciphertext, and tag, one at a time)
- A wrong password fails
- The test vectors in `FORMAT.md` produce the expected output (checked through an internal function that accepts the salt and nonce from outside)
- `verify` tells two files with identical and with different contents apart
- CI runs `go vet` and `go test ./...`

## 7. Out of scope

- A GUI, or structured contents (per-item management, etc.). The contents are just bytes
- Password generation or storage, key files, public-key encryption, cloud sync
- Chunked processing for large files (streaming)
- Writing plaintext to a file
- Changes that break backward compatibility with format v1. If the format changes, bump the version and keep the code that reads v1

## 8. Definition of done

- All commands and tests above are in place and CI passes
- The Release contains the binaries, the bundle zip, and `SHA256SUMS`
- `encrypt` → `verify` → `decrypt` works on Windows and Linux
- The test file can be decrypted without Go by following `FORMAT.md`
