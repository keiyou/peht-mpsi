# PeHT-MPSI

Research implementation for the experimental evaluation of **PeHT-MPSI: Faster
OT-MPSI and TT-MPSI with Per-Element Hidden Thresholds**. The launchers use
synthetic inputs and emulate all parties on one host. This artifact is not
intended for production deployment.

- `cuckoo/`: Cuckoo-hashing backend for larger input domains.
- `bitmap/`: Bitmap backend for small input domains.
- `parameter_search/`: Standalone HElib parameter-search utility.
- `third-party/`: Patches required by the pinned HElib and VOLE-PSI versions.

## Get the source

Clone this repository as `peht-mpsi`, then enter the checkout:

```bash
cd peht-mpsi
export OT_MPSI="$PWD"
```

The commands below use `OT_MPSI` as the checkout path. Set it again after
opening a new shell.

## Build on Ubuntu

The build targets x86-64 Linux and requires a C++20 compiler. The Makefiles use
`g++` by default and enable AES-NI, PCLMUL, AVX2, OpenMP, and native CPU tuning;
override `CXX` to use another compatible compiler. The quick examples below
are small; high-party configurations can require hundreds of gigabytes of
memory.

Install the system packages:

```bash
sudo apt update
sudo apt install -y \
  build-essential cmake ninja-build git curl ca-certificates pkg-config \
  python3 python3-pip python3-venv \
  libboost-all-dev libgmp-dev libntl-dev libsodium-dev libssl-dev
```

HElib and VOLE-PSI need the patches shipped in this repository. Install the
exact revisions below; unpatched or newer versions are not supported.

### 1. Install patched HElib

```bash
mkdir -p ../ot_mpsi-deps
cd ../ot_mpsi-deps

git clone --depth 1 --branch v2.3.0 https://github.com/homenc/HElib.git
cp "$OT_MPSI/third-party/HElib/include/keys.h" HElib/include/helib/keys.h
cp "$OT_MPSI/third-party/HElib/src/keys.cpp" HElib/src/keys.cpp

cmake -S HElib -B HElib/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build HElib/build --parallel "$(nproc)"
sudo cmake --install HElib/build
```

### 2. Install patched VOLE-PSI

```bash
git clone https://github.com/Visa-Research/volepsi.git
cd volepsi
git checkout --detach ec76012ed516e25d3f460af9b8680e1140a5d491
git submodule update --init --recursive

git apply --check \
  "$OT_MPSI/third-party/volepsi/0001-separate-cuckoo-layout-seed.patch"
git apply \
  "$OT_MPSI/third-party/volepsi/0001-separate-cuckoo-layout-seed.patch"

python3 build.py \
  -DVOLE_PSI_ENABLE_BOOST=ON \
  -DFETCH_AUTO=ON \
  -DVOLE_PSI_NO_SYSTEM_PATH=true \
  --par="$(nproc)"
sudo cmake --install out/build/linux
sudo install -Dm644 \
  out/build/linux/volePSI/config.h /usr/local/include/volePSI/config.h
sudo ldconfig
```

### 3. Build both backends

```bash
make -C "$OT_MPSI/cuckoo" clean
make -C "$OT_MPSI/cuckoo" -j"$(nproc)"

make -C "$OT_MPSI/bitmap" clean
make -C "$OT_MPSI/bitmap" -j"$(nproc)"
```

The binaries are `cuckoo/bin/ot_mpsi` and `bitmap/bin/ot_mpsi`.

## Run a benchmark

The Python runner starts every party over loopback-only sockets and anchors the
binary and generated `keys/` paths to the selected backend directory. Party
`N-1` is the leader.

Cuckoo example:

```bash
cd "$OT_MPSI/cuckoo"
python3 tools/run_benchmark.py \
  --numParties 5 --threshold 3 \
  --senderSize 10 --receiverSize 10 \
  --numRuns 3 --debug
```

Bitmap example:

```bash
cd "$OT_MPSI/bitmap"
python3 tools/run_benchmark.py \
  --numParties 5 --threshold 3 \
  --senderSize 8 --receiverSize 8 \
  --inputBitSize 16 --numRuns 3 --debug
```

The size arguments are exponents: `--senderSize 10` means `2^10` elements.
Both set-size exponents must be in `0..30`, with
`receiverSize >= senderSize`. For Bitmap, both must also be smaller than
`inputBitSize`.

Common options:

| Option | Meaning |
| --- | --- |
| `--numParties N` | Required. `4..38`, or `4..36` with `--traceable`. |
| `--threshold T` | Default: `ceil(N/2)`. Valid values are `0` or `2..N`. |
| `--senderSize S` | Required sender set-size exponent in `0..30`. |
| `--receiverSize R` | Required receiver exponent in `S..30`. |
| `--numRuns R` | Number of measured runs; must be positive. |
| `--traceable` | Run the traceable protocol. |
| `--debug` | Print intersection and trace diagnostics. |
| `--binPath PATH` | Binary path, default `bin/ot_mpsi`. |

Bitmap also requires `--inputBitSize B`, where `1 <= B <= 22` and both set
size exponents are smaller than `B`. For correctness checks, keep the universe
comfortably larger than the sets; otherwise synthetic unique items can collide
and legitimately enlarge the intersection.

`--threshold 0` generates a balanced set of per-element thresholds in
`[2, N]` and privately shuffles their assignment. Only the leader knows the
assignment. Use a value in `2..N` for one threshold shared by all elements;
`1` is invalid. Threshold mode `0` also works with `--traceable`.

Each invocation replaces the backend's `keys/` directory during an untimed
setup step. The files remain after the run and are ignored by Git; remove them
when they are no longer needed.
If a party fails or the launcher is interrupted, it stops the other parties and
exits with a nonzero status.

The runner prints results to the terminal and does not create a result file.
Use `--debug` when checking the intersection. Trace diagnostics show at most
the first 256 positions. A valid run contains the leader's `Average time` and
communication summary and contains no `Fatal error` from any party.

## Reproducing the paper settings

Run the single-configuration command once for each parameter choice, using
`--numRuns 10`. The paper evaluates `N` in `{5, 10, 15, 20}` with
`T = ceil(N/2)` unless stated otherwise. Bitmap experiments use universe-size
exponents `{14, 16, 18, 20}`; Cuckoo experiments use set-size exponents
`{14, 16, 18, 20}`. The statistical security parameter for Cuckoo defaults to
40 in the binary.

The reported experiments used two 48-core Intel Xeon 8558P CPUs and 512 GB of
RAM. The launcher runs all parties on one host. It does not configure WAN
emulation; the paper's 200 Mbps, 96 ms RTT setting must be applied externally.
Baseline implementations are not included in this repository.

## Troubleshooting

- Missing HElib multiparty methods usually means the unpatched library was
  installed. Copy both shipped HElib files again, then rebuild and reinstall
  HElib and the benchmark.
- Missing `volePSI/config.h` means the generated header was not copied; repeat
  the explicit `install -Dm644` step above. Missing `setCuckooSeed` means the
  VOLE-PSI patch is absent: start from a clean checkout at the pinned commit,
  apply the patch once, rebuild, and reinstall.
- `cannot find -l...` or a shared-library error usually means an install is
  missing or the linker cache is stale. Keep the `/usr/local` prefix, run
  `sudo ldconfig`, then clean and rebuild the benchmark.
- The local parties use loopback ports beginning at `30081`. Stop any earlier
  run that still owns one of these ports before starting another.

The HElib parameter search tool is documented separately in
[`parameter_search/README.md`](parameter_search/README.md).

## License

The project is licensed under the [Apache License 2.0](LICENSE.md).
Third-party material retains its original terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
