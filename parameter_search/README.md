# MPSI HElib Parameter Search

This directory is intentionally isolated from `bitmap/` and `cuckoo/`. It
finds candidate HElib parameter rows before the protocol tables are updated.


## Contents

- `find_parameters.cpp` and `Makefile`: the standalone HElib parameter search tool.

The tool writes candidate rows to standard output. Review passing rows before
copying them into `bitmap/psi/CryptoUtils.h` and
`cuckoo/psi/CryptoUtils.h`.

A row in the current protocol table is:

```cpp
{ n, bits, ring_dim }
```

The protocol passes it to HElib as:

```cpp
helib::ContextBuilder<helib::BGV>()
    .m(ring_dim)
    .p(2)
    .r(n)
    .bits(bits)
    .c(2)
```

`ring_dim` is HElib's cyclotomic index `m`; the real ring dimension is derived from `phi(m)`. For batching with `p = 2`, the slot count is:

```text
slots = phi(m) / ord_m(2)
```

## Checks Performed

`find_parameters.cpp` uses a two-stage check.

1. Cheap arithmetic and HElib feasibility checks:
   - `m` is odd, so `gcd(2, m) = 1`.
   - `ord_m(2)` exists.
   - slot count is at least `--min-slots`.
   - `bits` search starts below the estimate, constructs a real HElib BGV context, then increments until the smoke workload passes.
   - `context.securityLevel()` must be at least `--security`.

2. MPSI-shaped smoke test:
   - sequential multiparty key generation for all `n` parties.
   - packed leader vote plaintexts using `base = 1 << (threshold - 1)`.
   - repeated `multByConstant()` by member vote plaintexts (`1` for present, `2` for absent), plus `Enc(0)` rerandomization.
   - reject ciphertexts where `Ctxt::isCorrect()` is false before calling patched HElib `PartialDecrypt()` from every party and `DecryptFusion()`.
   - traceable-style extra masking by a late member's `0/1` bitmap before decryption, including slots where a threshold-passing vote is zeroed.
   - a cuckoo-shaped pass using sender `1/-2` factors, leader `0/1` receiver contributions, empty-bin slots, and traceable subtraction over first/middle/last sender rounds.

This is still not a full PSI benchmark. It is a parameter sanity filter that is much closer to the protocol workload than a generic HElib multiplication demo.

## Build

```bash
cd "$OT_MPSI/parameter_search"
make
```

This requires the locally installed HElib to include the repo's patched multiparty methods:

- `SequentialMultipartyGenSecKey`
- `PartialDecrypt`
- `DecryptFusion`

## Find Rows Up To 20 Parties

```bash
OMP_NUM_THREADS=1 ./bin/find_parameters --n-min 4 --n-max 20 --threads 12
```

The default output is a C++ initializer. CSV output is also available:

```bash
OMP_NUM_THREADS=1 ./bin/find_parameters --n-min 4 --n-max 20 --format csv > candidates.csv
```

Useful options:

- `--security 128`: minimum HElib security level.
- `--min-slots 512`: minimum batching slots.
- `--domain-bits 20`: cost model reference domain size, default `2^20`.
- `--bits-step 8`: coarse bit probe step. Failed probes can jump using observed HElib capacity, and passing probes refine with a capacity-guided bracket search. Returned rows are still explicitly validated by HElib security and the smoke workload.
- `--max-extra-bits 128`: how far above the estimate to search.
- `--below-estimate-bits 64`: how far below the estimate to start searching; this matters for high-party rows where valid historical settings are below the estimate.
- `--max-smoke-candidates 0`: ranked candidate cap per `n`; default `0` means try all candidate `m` values.
- `--threads 12`: parallel worker count for independent `n` searches; the tool rejects values above 12. Use `OMP_NUM_THREADS=1` so dependency-internal OpenMP does not oversubscribe the run.
- `--mode traceable|nontraceable|quick`: choose the smoke workload. `traceable` is the default and includes the extra traceability-shaped checks. `nontraceable` runs the bitmap and cuckoo non-traceable checks. `quick` runs only the bitmap-shaped prefilter.
- `--quick`: alias for `--mode quick`; useful for prefiltering, not final validation.
- `--threshold-mode majority|half`: choose the threshold used by the smoke workload. `majority` is the default (`n / 2 + 1`); `half` uses `floor(n / 2)`.
- `--m-list 8191,16383,...`: override the candidate `m` list.

The search can be CPU- and memory-intensive for large party counts. The tool
does not modify protocol source files or write result files automatically.
