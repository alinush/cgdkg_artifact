# CLAUDE.md

Notes for future Claude working in this repo.

## What this is

Upstream: the Kate-Mangipudi-Mukherjee-Saleem-Thyagarajan (KMM+23) class-group
non-interactive VSS artifact, aka **cgVSS**. The repo ships DKG-oriented code
and benchmarks; we added:

- `classgroup/src/pvss.rs` — a clean PVSS abstraction (deal / verify /
  decrypt_share / transcript serde / tests).
- `benches/benchmarks_pvss.rs` — PVSS benchmarks.
- Swapped the BLS12-381 backend in `classgroup/` from `miracl_core_bls12381`
  to `blstrs` v0.7.1 (with `blst` pinned to `no-threads` so the Pippenger MSM
  is single-threaded, matching Chunky's apples-to-apples baseline).

The upstream `benches/benchmarks_cgdkg.rs` is disabled in the root
`Cargo.toml` because it used the old MIRACL-based classgroup API. The `cd/`
and `groth/` crates still use MIRACL and their benches
(`benchmarks_cd_dkg`, `benchmarks_grothdkg`) still work.

## Build prerequisites (arm64 macOS)

The repo's build infra had pre-existing issues on arm64. Fixes already applied
in-tree or in the registry cache:

1. `supra-bicycl/build_script_data.json` — added `AArch64/MacOS` known target.
2. `supra-bicycl/c_lib/CMakeLists.txt` — bumped `cmake_minimum_required` to
   3.5 and added `/opt/homebrew/include` / `/opt/homebrew/lib` paths.
3. `~/.cargo/registry/src/index.crates.io-*/cpp_std-0.1.1/build_script_data.json`
   — hand-patched to add `AArch64/MacOS` + `X86_64/MacOS` known targets.
4. `~/.cargo/registry/src/.../cpp_std-0.1.1/c_lib/CMakeLists.txt` — cmake min
   bumped to 3.5.
5. `classgroup/Cargo.toml` — `proptest` added to `[dev-dependencies]`; MIRACL
   removed; `blstrs`/`blst(no-threads)`/`ff`/`group`/`pairing`/`sha2` added.
6. `classgroup/src/bls12381_serde.rs` — three dangling `#[cfg(test)] mod
   *_tests;` declarations commented out (files never existed).

If cargo refetches cpp_std, re-apply patches (3) and (4).

Build needs homebrew gmp + openssl visible to the linker, and every `cargo`
invocation must pin rayon to a single thread (criterion / downstream crates
may otherwise parallelize silently and pollute timings). On arm64:

```bash
export RUSTFLAGS="-L /opt/homebrew/lib -L /opt/homebrew/opt/openssl@3/lib"
export RAYON_NUM_THREADS=1
```

All `cargo test` / `cargo bench` commands in this doc assume both env vars
are set (or inlined per invocation, as shown below).

`CMAKE_POLICY_VERSION_MINIMUM=3.5` is no longer needed (we bumped the
CMakeLists directly).

## Running the PVSS tests

```bash
cd classgroup
RAYON_NUM_THREADS=1 \
RUSTFLAGS="-L /opt/homebrew/lib -L /opt/homebrew/opt/openssl@3/lib" \
  cargo test --release pvss::
```

There are 4 tests: `deal_then_verify`, `serialize_roundtrip_still_verifies`,
`decrypt_share_matches_dealt_share`, `interpolation_recovers_secret`. All must
pass.

## Running the PVSS benchmarks

From the repo root:

```bash
RAYON_NUM_THREADS=1 \
RUSTFLAGS="-L /opt/homebrew/lib -L /opt/homebrew/opt/openssl@3/lib" \
  cargo bench --bench benchmarks_pvss
```

Criterion sample size is fixed at 10 (see `group.sample_size(10)` in
`benches/benchmarks_pvss.rs`). Total runtime depends on the `configs()` list.
Current config: `(t, n) ∈ {(3,4), (6,8), (11,16), (22,32), (43,64), (86,128),
(171,256), (342,512), (683,1024)}`. The n=512 and n=1024 sizes are slow —
expect the full run to take tens of minutes.

To subset, pass a criterion filter (regex) as a trailing arg:

```bash
# Only n=128 and n=256:
RAYON_NUM_THREADS=1 cargo bench --bench benchmarks_pvss -- "n=(128|256)"
# Only verify benches:
RAYON_NUM_THREADS=1 cargo bench --bench benchmarks_pvss -- verify
```

### What metrics the bench reports, and where to find them

For each `(t, n)` config, the bench emits three Criterion benchmarks:

- **Deal time** — bench id `classgroup-pvss/deal/t=..., n=...`. Criterion
  prints `time: [low, mid, high]` in ms. Use the middle value.
- **Verify time** — bench id `classgroup-pvss/verify/t=..., n=...`.
- **Decrypt-share time** — bench id `classgroup-pvss/decrypt_share/t=...,
  n=...`. Time to decrypt a single share (node 0). Should be flat (~10 ms)
  across n because it's one CL15 decryption.

After the three benches for each config, the bench prints one summary line:

```
PVSS transcript size: X.XX KiB (NNNN bytes) (t=..., n=...)
```

…which is also the roundtripped-and-reverified transcript, so a passing run
implicitly sanity-checks serialization.

To pull just the metrics out of a bench run, tee the output and grep:

```bash
RAYON_NUM_THREADS=1 cargo bench --bench benchmarks_pvss 2>&1 | tee /tmp/pvss.log \
  | grep -E "classgroup-pvss/(deal|verify|decrypt_share)/|^ *time:|transcript size:"
```

Or after the fact:

```bash
grep -E "time:|transcript size:" /tmp/pvss.log
```

Criterion `time:` lines appear in bench order, so the triples are:
`deal` / `verify` / `decrypt_share` for each `(t, n)` in the `configs()`
order, followed by the transcript size for that config.

## Config to tweak sizes

Edit `benches/benchmarks_pvss.rs` → `fn configs()`. Currently:

```rust
let ns = [4, 8, 16, 32, 64, 128, 256, 512, 1024];
let ts = [3, 6, 11, 22, 43, 86,  171, 342, 683];
```

`t` is the reconstruction threshold (polynomial has `t` coefficients → degree
`t-1` → `t` shares needed to reconstruct).

## Interpreting numbers vs. the Chunky blog post

The blog post lives at `~/repos/alinush.github.io/_posts/2025-11-18-chunky-weighted-pvss-for-field-elements.md`.
The `#full-benchmarks-table` has 5 rows per `(t, n)` group: Chunky, Groth21,
Golden, GHL21e, cgVSS. The cgVSS row format is:

```
| cgVSS[^KMMplus23e] | BLS12-381 + CL15 | `blstrs` v0.7.1 + `bicycl` v0.1.0 | -- | t | n | transcript | deal | verify | decrypt_share |
```

Relative multipliers in the `(N.NNx)` suffix are always >1, with color
indicating direction vs. Chunky (green = better, red = worse).

CSS rule `#full-benchmarks-table tbody tr:nth-child(5n+1)` controls the
thick-border group separator — if rows per group change, update the `5n+1`.

## Gotchas

- **Decrypt-share is always ~10 ms.** It's one CL15 decryption, no BLS work.
  If you see drift, something's wrong.
- **Deal and Verify scale with both t and n**, but differently. Deal has `t`
  G1 scalar muls (polynomial commitment) + `n` CL-HSM encryptions; Verify
  has a size-`t` G1 MSM + two size-`n` class-group mult_exps.
- **blstrs `no-threads`** is required for fair comparison. With threads
  enabled, small MSMs actually get *slower* because of thread-launch overhead
  — we saw a 30% regression at n=128 from blst's default thread pool.
- **Transcript size is deterministic.** Re-running doesn't change it.
