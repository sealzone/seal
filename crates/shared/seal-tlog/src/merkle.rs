//! RFC 9162 §2.1 Merkle Tree Hash, audit paths and consistency proofs, computed from all
//! leaves. The log side: the dev log builds its proofs with these, and the tests check the
//! verifiers in `lib.rs` against them.

use sha2::{Digest, Sha256};

use crate::node_hash;

/// `MTH({})`: SHA-256 of the empty string.
pub(crate) fn empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

/// The largest power of two strictly below `n` (`n >= 2`).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// `MTH(D[n])` over leaf hashes.
pub(crate) fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// `PATH(m, D[n])`: the audit path of leaf `m`, leaf to root.
pub(crate) fn inclusion_path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    assert!(m < n, "leaf {m} is not in a tree of {n}");
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    let (mut path, sibling) = if m < k {
        (inclusion_path(m, &leaves[..k]), root(&leaves[k..]))
    } else {
        (inclusion_path(m - k, &leaves[k..]), root(&leaves[..k]))
    };
    path.push(sibling);
    path
}

/// `PROOF(m, D[n])`: proves the first `m` leaves are a prefix of all `n`. Empty for
/// `m == 0` and `m == n`.
pub(crate) fn consistency_proof(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    assert!(m <= leaves.len());
    if m == 0 {
        return Vec::new();
    }
    subproof(m, leaves, true)
}

fn subproof(m: usize, leaves: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        return if complete { Vec::new() } else { vec![root(leaves)] };
    }
    let k = split(n);
    let (mut proof, sibling) = if m <= k {
        (subproof(m, &leaves[..k], complete), root(&leaves[k..]))
    } else {
        (subproof(m - k, &leaves[k..], false), root(&leaves[..k]))
    };
    proof.push(sibling);
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_is_the_largest_power_of_two_below() {
        for (n, k) in [(2, 1), (3, 2), (4, 2), (5, 4), (8, 4), (9, 8), (64, 32), (65, 64)] {
            assert_eq!(split(n), k, "{n}");
        }
    }
}
