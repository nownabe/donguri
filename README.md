# donguri

A CLI that encrypts a single file with a password and decrypts it with the same password.

Encrypted files are meant to be stored for years. The top priority is that a file can always be opened, years from now, on a machine with no network access: donguri is a single static binary built only from the Go standard library, and its file format is fully documented in [FORMAT.md](FORMAT.md) so that a file can be decrypted even without donguri.

A squirrel buries acorns (_donguri_) and digs them up months later.

## Usage

The password is always read from the terminal without echo, never from standard input or arguments.

```sh
# Encrypt a file (or standard input when <in> is omitted). Asks for the password twice.
donguri encrypt -o secret.txt.donguri secret.txt

# Check that the file opens, without printing the contents. Prints OK, exits 1 on failure.
donguri verify secret.txt.donguri

# Check that two copies open with the same password and hold the same contents.
donguri verify secret.txt.donguri /mnt/backup/secret.txt.donguri

# Decrypt to standard output. Redirect it if you need a file.
donguri decrypt secret.txt.donguri
```

- `encrypt` refuses to overwrite an existing output file unless `--force` is given. It writes the file atomically with permissions 0600, then reads it back and decrypts it to confirm it matches the input before reporting success.
- `decrypt` only writes to standard output, so plaintext never lands on disk unless you redirect it there.
- A failed decryption reports `wrong password or corrupted file`; the two cannot be told apart.
- Input is limited to 16 MiB.
- `donguri --version` prints the version and commit.

## Install

Download from the [latest release](https://github.com/nownabe/donguri/releases/latest):

- `donguri_<version>_<os>_<arch>[.exe]` — a binary for `linux` / `windows` (`amd64`, `arm64`) or `darwin` (`arm64`)
- `donguri_<version>_bundle.zip` — every binary above, the full source, this README, `FORMAT.md`, and `LICENSE`. Keeping this one file is enough to run donguri on any of those platforms or to rebuild it.
- `SHA256SUMS` — SHA-256 checksums of every file in the release

### Verify the download

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

On macOS use `shasum -a 256 -c SHA256SUMS --ignore-missing`. On Windows, compare the output of `Get-FileHash <file>` in PowerShell with the line for that file in `SHA256SUMS`.

### Use the bundle

```sh
unzip donguri_<version>_bundle.zip
cd donguri_<version>
bin/linux_amd64/donguri --version   # bin/<os>_<arch>/donguri[.exe]
```

## Build from source

Requires Go 1.24 or later. There are no dependencies outside the standard library, so this works offline, including from the source in the bundle:

```sh
go build
```

## Development

Prerequisite: [mise](https://mise.jdx.dev/).

```sh
mise run setup
go vet ./... && go test ./...
```

Releases are automated: release-please maintains a release PR from [Conventional Commits](https://www.conventionalcommits.org/), and merging it tags the release and runs GoReleaser to publish the artifacts.

## License

[MIT](LICENSE)
