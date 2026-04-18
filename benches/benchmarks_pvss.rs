//! PVSS benchmarks for the class-group non-interactive VSS.
//!
//! Measures the three primitives needed to fill in the Chunky comparison
//! table: dealing time, verification time, and per-share decryption time.
//! The benchmark also prints the transcript size in KiB for each (t, n) pair.

extern crate classgroup;

use bicycl::b_i_c_y_c_l::{Mpz, RandGen};
use bicycl::cpp_core;
use bicycl::cpp_std::VectorOfUchar;
use bicycl::rust_vec_to_cpp;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use classgroup::pvss::{deal, decrypt_share, keygen, verify, PvssParams, Transcript, DEFAULT_DST};
use classgroup::rng::RAND_ChaCha20;

struct PvssConfig {
    t: usize,
    n: usize,
}

/// (t, n) pairs covering the Chunky full-benchmarks table plus smaller and
/// larger sizes.
fn configs() -> Vec<PvssConfig> {
    let ns = [4, 8, 16, 32, 64, 128, 256, 512, 1024];
    let ts = [3, 6, 11, 22, 43, 86,  171, 342, 683];
    ns.iter()
        .zip(ts.iter())
        .map(|(&n, &t)| PvssConfig { t, n })
        .collect()
}

fn bench_pvss(c: &mut Criterion) {
    let mut group = c.benchmark_group("classgroup-pvss");
    group.sample_size(10);

    let seed = [4u8; 32];
    let seed_cpp = unsafe { rust_vec_to_cpp(seed.to_vec()) };
    let ref_seed: cpp_core::Ref<VectorOfUchar> = unsafe { cpp_core::Ref::from_raw_ref(&seed_cpp) };
    let seed_mpz = unsafe { Mpz::from_vector_of_uchar(ref_seed) };
    let ref_seed_mpz: cpp_core::Ref<Mpz> = unsafe { cpp_core::Ref::from_raw_ref(&seed_mpz) };

    let mut rng = RAND_ChaCha20::new(seed);
    let mut rng_cpp = unsafe { RandGen::new_1a(ref_seed_mpz) };

    let params = PvssParams::new(DEFAULT_DST);

    for cfg in configs() {
        let ad: Vec<u8> = Vec::new();
        let mut sks = Vec::with_capacity(cfg.n);
        let mut pks = Vec::with_capacity(cfg.n);
        for _ in 0..cfg.n {
            let (sk, pk, _pop) = keygen(&params, &mut rng_cpp, &ad);
            sks.push(sk);
            pks.push(pk);
        }

        let id = |label: &str| {
            BenchmarkId::new(label, format!("t={}, n={}", cfg.t, cfg.n))
        };
        group.throughput(Throughput::Elements(1));

        // Deal
        group.bench_with_input(id("deal"), &cfg, |b, _| {
            b.iter(|| {
                let (_t, _dealt) = deal(&params, &pks, cfg.t, &mut rng, &mut rng_cpp);
            });
        });

        // Produce one transcript for the remaining measurements.
        let (transcript, _dealt) = deal(&params, &pks, cfg.t, &mut rng, &mut rng_cpp);

        // Verify
        group.bench_with_input(id("verify"), &cfg, |b, _| {
            b.iter(|| {
                let ok = verify(&params, &pks, &transcript);
                assert!(ok);
            });
        });

        // Decrypt share (node 0)
        group.bench_with_input(id("decrypt_share"), &cfg, |b, _| {
            b.iter(|| {
                let _s = decrypt_share(&params, 0, &sks[0], &transcript);
            });
        });

        // Serialization roundtrip (sanity + reports transcript size)
        let bytes = transcript.to_bytes();
        let round = Transcript::from_bytes(&bytes, &params).expect("deserialize");
        assert!(verify(&params, &pks, &round), "round-tripped transcript failed to verify");

        let kib = bytes.len() as f64 / 1024.0;
        println!(
            "PVSS transcript size: {:.2} KiB ({} bytes) (t={}, n={})",
            kib,
            bytes.len(),
            cfg.t,
            cfg.n
        );
    }

    group.finish();
}

criterion_group!(benches, bench_pvss);
criterion_main!(benches);
