# Project 2 — Multithreaded Password Hash Cracker

**Group WDTQ:** Waylon Erlandson, Dang Cuong Nguyen, Tan Hoang Khoa Nguyen, Quang Hien Tran

Given a dictionary of candidate passwords and a list of target hashes, find which
password produces each hash. Speeds up a sequential baseline with multithreading
(pthreads). Each target hash was produced by one of **MD5, SHA1, SHA256, or SHA512**.

## Build

```bash
cd src
make          # builds ./project2 (requires OpenSSL: libssl-dev / -lcrypto)
```

## Run

```bash
./project2 <password_list> <hash_list> <output_file>
# example:
./project2 data/common-passwords.txt data/hashes.txt output.txt
```

- **password_list** — whitespace-separated candidate passwords.
- **hash_list** — one hex hash per line (first 16 bytes / 32 hex chars are compared).
- **output_file** — one line per target, in input order: `password:ALGORITHM` or `not found`.

`main.c` also prints total wall-clock seconds to stdout.

## Test

```bash
cd src
make test     # runs on data/ and diffs output against data/expected.txt
```

A passing run prints the timing line and no `diff` output.

## Docker

```bash
docker build -t project2 .
docker run --rm -it project2   # drops into a shell in /app/src with project2 built
```

## How it works

1. **Load hashes** → convert each to 16 bytes, build an open-addressing hash table
   (linear probing) that groups identical hashes.
2. **Load passwords** → one bulk read, tokenized in place (no per-word allocation).
3. **Crack in parallel** → the password list is split into contiguous ranges across
   4 threads (3 pthreads + main). Each password is hashed with all 4 algorithms and
   looked up in the table; matches are recorded per worker in dictionary order.
4. **Merge & write** → matches are replayed to fill targets, duplicates included,
   then written to the output file.

Source layout:

| File | Role |
|------|------|
| `main.c` | Entry point + timing (do not modify) |
| `hash.c` | All cracking logic: I/O, indexing, threading, output |
| `hash_functions.c/.h` | MD5/SHA1/SHA256/SHA512 wrappers over OpenSSL |
| `hash.h` | Public `crack_hashed_passwords()` declaration |
