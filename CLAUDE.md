# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**bloom-ldns** is a fork of [ldns v1.9.0](https://nlnetlabs.nl/ldns/) (a C DNS library) extended with bloom filter functionality. The primary addition is `examples/ldns-gen-filter-rr.c`, a tool that compares two RRSIG zone files and generates a DNS TXT record containing a bloom filter of the signatures that were removed between the two zone versions.

The generated TXT record is named `_filter.<domain>` and encodes: a header (`r=<buffer_sec>;a=0;d=`) followed by the raw bloom filter struct and its bitmap bytes. This allows a DNS resolver to efficiently determine which signatures have been withdrawn.

## Build Commands

**Building from the git repository (first time):**
```bash
git submodule update --init
libtoolize -ci          # use glibtoolize on macOS
autoreconf -fi
./configure --with-examples --with-drill
make
```

**Subsequent builds:**
```bash
make
make clean
```

**Run tests:**
```bash
make test
# or directly:
test/test_ci.sh
```

## Architecture

### Core ldns library (`ldns/`)
The upstream DNS library. Key modules: `rr.c` (resource records), `packet.c`, `resolver.c`, `dnssec.c`, `keys.c`, `net.c`. Wire format conversion is split across `host2wire.c`, `wire2host.c`, `host2str.c`, `str2host.c`.

### The bloom filter tool (`examples/ldns-gen-filter-rr.c`)
This is the main new code. Its pipeline:

1. **Input**: two zone RRSIG text files (`file1`, `file2`). `file2` is the new zone snapshot; `file1` is the old zone.
2. **Diff**: loads `file2` into a hash set (`khashl` — see `examples/khashl.h`), then iterates `file1` to find lines absent from `file2` (i.e., RRSIGs that were removed).
3. **Bloom filter**: for each removed RRSIG, encodes `(owner_name_wire || covered_type_string)` and adds it to a bloom filter (`examples/bloom_filter/bloom.c`, seeded via `MurmurHash2`).
4. **Output**: prints a TXT RR to stdout. Owner name: `_filter.<domain>`. Payload: header string + raw `struct bloom` + bloom bitmap, chunked into 255-byte TXT strings per RFC.

Key flags:
- `-d <domain>` — required; sets the TXT record owner domain
- `-p <rate>` — false positive rate for the bloom filter (default 0.2)
- `-b <seconds>` — expiration buffer in seconds (default 172800 = 2 days), written into the `r=` header field
- `-t <ttl>` — TTL of the output TXT record (default 900)

### File mmapping pattern
Input files are opened with `mmap(MAP_PRIVATE | PROT_WRITE)` so newlines can be mutated to null terminators in-place, enabling zero-copy string parsing without allocating line buffers.

### Dependencies
- `examples/khashl.h` — header-only hash set used for the RRSIG diff
- `examples/bloom_filter/bloom.{c,h}` + `MurmurHash2.c` — bloom filter implementation
- `ldns/` — used for parsing RRSIG text (`ldns_rr_new_frm_str`), wire-encoding owner names (`ldns_dname2buffer_wire`), and building/printing the TXT RR

## macOS Notes
Use `glibtoolize` instead of `libtoolize`. Set `MACOSX_DEPLOYMENT_TARGET=10.4` if you encounter linker issues on older SDKs.
