//! Barretenberg BN254 Poseidon2: width 4, rate 3, RF=8, RP=56, exponent 5.
//! Alignment vectors must match Noir and the TypeScript/Go implementations.

use ark_bn254::Fr;

use crate::field::{bytes_to_field, field_to_bytes_be, u64_to_field};
use crate::poseidon_constants::{internal_diag, round_constants, FULL_ROUNDS, PARTIAL_ROUNDS, T};

const POSEIDON2_RATE: usize = 3;
const HALF_FULL: usize = FULL_ROUNDS / 2;

/// Domain-separated hash: prepend `domain` field to inputs, then sponge.
///
pub fn h(domain: u64, inputs: &[&[u8; 32]]) -> [u8; 32] {
    let mut fr_inputs: Vec<Fr> = Vec::with_capacity(1 + inputs.len());
    fr_inputs.push(u64_to_field(domain));
    for input in inputs {
        fr_inputs.push(bytes_to_field(*input));
    }
    let result = hash(&fr_inputs);
    field_to_bytes_be(result)
}

/// Raw sponge hash (no domain prepending). Mirrors nexus `Poseidon2Hash([]*big.Int)`.
///
/// Used by alignment tests + advanced callers. Most clients should use [`h`].
///
/// Sponge semantics (mirror Noir main.nr poseidon2_sponge_hash exactly):
///   - iv = fr(len) * 2^64; state = [0, 0, 0, iv]
///   - absorb inputs in RATE=3 chunks: fill a 3-slot cache; when the cache is
///     full AND another input arrives, add cache into state[0..3) and permute,
///     then start a fresh cache with that input
///   - after the loop, add the remaining cache into state[0..cache_size) and
///     permute once more (the final permutation always runs)
///   - output state[0]
pub fn hash(inputs: &[Fr]) -> Fr {
    // 2^64 as Fr — fits in u128 (2^64 < 2^128).
    let two_pow_64 = Fr::from(1u128 << 64);
    let iv = Fr::from(inputs.len() as u64) * two_pow_64;

    let mut state: [Fr; T] = [Fr::from(0u64), Fr::from(0u64), Fr::from(0u64), iv];

    let mut cache: [Fr; POSEIDON2_RATE] = [Fr::from(0u64); POSEIDON2_RATE];
    let mut cache_size: usize = 0;

    for x in inputs {
        if cache_size == POSEIDON2_RATE {
            for j in 0..POSEIDON2_RATE {
                state[j] += cache[j];
            }
            permutation(&mut state);
            cache[0] = *x;
            cache_size = 1;
        } else {
            cache[cache_size] = *x;
            cache_size += 1;
        }
    }

    for j in 0..cache_size {
        state[j] += cache[j];
    }
    permutation(&mut state);

    state[0]
}

/// Aztec/Barretenberg BN254 t=4 Poseidon2 permutation:
///   - initial external matrix multiplication
///   - 4 full rounds:    addRoundKey(all) → sbox(all) → matMulExternal
///   - 56 partial rounds: addRoundKey(lane0) → sbox(lane0) → matMulInternal
///   - 4 full rounds:    addRoundKey(all) → sbox(all) → matMulExternal
fn permutation(state: &mut [Fr; T]) {
    let rc = round_constants();
    let diag = internal_diag();

    mat_mul_external(state);

    for r in 0..HALF_FULL {
        add_round_key_full(state, &rc[r]);
        sbox_full(state);
        mat_mul_external(state);
    }
    for r in HALF_FULL..HALF_FULL + PARTIAL_ROUNDS {
        state[0] += rc[r][0];
        sbox(&mut state[0]);
        mat_mul_internal(state, &diag);
    }
    for r in HALF_FULL + PARTIAL_ROUNDS..FULL_ROUNDS + PARTIAL_ROUNDS {
        add_round_key_full(state, &rc[r]);
        sbox_full(state);
        mat_mul_external(state);
    }
}

fn add_round_key_full(state: &mut [Fr; T], rc_row: &[Fr; T]) {
    for j in 0..T {
        state[j] += rc_row[j];
    }
}

/// x → x^5 via x^2 → x^4 → x^5.
fn sbox(x: &mut Fr) {
    let x2 = (*x) * (*x);
    let x4 = x2 * x2;
    *x = (*x) * x4;
}

fn sbox_full(state: &mut [Fr; T]) {
    for j in 0..T {
        sbox(&mut state[j]);
    }
}

/// t=4 external MDS matrix M4 — verbatim from barretenberg matrix_multiplication_4x4.
fn mat_mul_external(input: &mut [Fr; T]) {
    let t0 = input[0] + input[1];
    let t1 = input[2] + input[3];
    let mut t2 = input[1] + input[1];
    t2 += t1;
    let mut t3 = input[3] + input[3];
    t3 += t0;
    let mut t4 = t1 + t1;
    t4 += t4;
    t4 += t3;
    let mut t5 = t0 + t0;
    t5 += t5;
    t5 += t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    input[0] = t6;
    input[1] = t5;
    input[2] = t7;
    input[3] = t4;
}

/// t=4 internal matrix M_I = J + diag.
/// result[i] = (D_i - 1) * input[i] + sum(all input[j])
/// (note: stored diagonal is `D_i - 1`, not `D_i`)
fn mat_mul_internal(input: &mut [Fr; T], diag: &[Fr; T]) {
    let mut sum = input[0];
    for i in 1..T {
        sum += input[i];
    }
    for i in 0..T {
        input[i] *= diag[i];
        input[i] += sum;
    }
}
