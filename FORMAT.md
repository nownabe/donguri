# donguri file format, version 1

This document describes the encrypted file format written by donguri. It is meant to be read on its own: with only this document and standard cryptographic primitives, you can decrypt a donguri file without donguri itself.

The format uses only well-known primitives — PBKDF2-HMAC-SHA256 and AES-256-GCM — and contains no secret parts. Its security rests entirely on the password.

## Layout

All integers are big-endian.

| Offset | Length | Field          | Value                                                    |
| ------ | ------ | -------------- | -------------------------------------------------------- |
| 0      | 8      | Magic          | ASCII `DONGURI` followed by one `0x00` byte              |
| 8      | 1      | Format version | `0x01`                                                   |
| 9      | 1      | KDF identifier | `0x01` = PBKDF2-HMAC-SHA256                              |
| 10     | 4      | Iterations     | Unsigned 32-bit integer, 100,000 to 10,000,000 inclusive |
| 14     | 16     | Salt           | Random                                                   |
| 30     | 12     | Nonce          | Random                                                   |
| 42     | rest   | Ciphertext     | AES-256-GCM ciphertext followed by its 16-byte tag       |

The first 42 bytes (offsets 0–41) are called the **header**. The ciphertext is exactly as long as the plaintext, so a file is always 58 bytes plus the plaintext length.

## Decryption

1. Check that the magic is `DONGURI\0`, the version is 1, and the KDF identifier is 1. Anything else is not a version 1 file.
2. Check that the iteration count is between 100,000 and 10,000,000 inclusive. donguri refuses anything outside this range, so a value outside it means the file is corrupted (or was not written by donguri).
3. Derive a 32-byte key:

   ```
   key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32 bytes)
   ```

   The password is the exact bytes that were typed, encoded as UTF-8, without the trailing newline.

4. Decrypt with AES-256-GCM using that key, the nonce, and the **whole 42-byte header as additional authenticated data (AAD)**. The input is everything from offset 42 to the end: the ciphertext with its 16-byte tag appended (the layout most libraries expect).

If authentication fails, either the password is wrong or the file is corrupted. GCM cannot tell the two apart. Because the header is authenticated, a change to any byte of the file — header included — makes decryption fail.

## Encryption

Encryption mirrors decryption. donguri always writes version 1 with PBKDF2-HMAC-SHA256 and 600,000 iterations, and generates a fresh random salt and nonce for every file. A salt or nonce must never be reused. The plaintext is an arbitrary byte sequence of at most 16 MiB (16,777,216 bytes).

## Decrypting without donguri

This Python script decrypts a file using `hashlib` from the standard library and AES-GCM from the [`cryptography`](https://pypi.org/project/cryptography/) package (`pip install cryptography`). Any other AES-GCM implementation works the same way.

```python
import getpass
import hashlib
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = open(sys.argv[1], "rb").read()
header, ciphertext = data[:42], data[42:]
magic, version, kdf, iterations = struct.unpack(">8sBBI", header[:14])
if (magic, version, kdf) != (b"DONGURI\x00", 1, 1):
    sys.exit("not a donguri version 1 file")
if not 100_000 <= iterations <= 10_000_000:
    sys.exit("iteration count out of range: corrupted file")
salt, nonce = header[14:30], header[30:42]

password = getpass.getpass().encode("utf-8")
key = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, 32)
sys.stdout.buffer.write(AESGCM(key).decrypt(nonce, ciphertext, header))
```

```sh
python3 decrypt.py secret.donguri > secret.txt
```

A wrong password or a corrupted file makes `decrypt` raise `cryptography.exceptions.InvalidTag`.

## Test vector

| Input      | Value                                                                          |
| ---------- | ------------------------------------------------------------------------------ |
| Password   | `correct horse battery staple` (ASCII)                                         |
| Salt       | `000102030405060708090a0b0c0d0e0f`                                             |
| Nonce      | `101112131415161718191a1b`                                                     |
| Iterations | 600,000 (`000927c0`)                                                           |
| Plaintext  | `Buried in autumn, dug up in spring.` followed by a newline (`0x0a`), 36 bytes |

Derived key:

```
ef177144eec9420cbc1093d2a8b344a92bc506d0d4ec9c028dd19f8324d8c1e6
```

Encrypted file (94 bytes), as hex:

```
444f4e47555249000101000927c0000102030405060708090a0b0c0d0e0f101112131415161718191a1b4e670fac759b881ea59af8bdb88619943d18fe91e147a3dbe35975cabbc93286f0a4a1e374db4e153dcdf7ff92d73f1c6c168ef6
```

The same bytes split into fields:

```
444f4e4755524900                          magic
01                                        format version
01                                        KDF identifier
000927c0                                  iterations (600,000)
000102030405060708090a0b0c0d0e0f          salt
101112131415161718191a1b                  nonce
4e670fac759b881ea59af8bdb88619943d18fe91  ciphertext (36 bytes)
e147a3dbe35975cabbc93286f0a4a1e3
74db4e153dcdf7ff92d73f1c6c168ef6          tag (16 bytes)
```
