//! Domain-separated SHA-256 Merkle trees with the RFC 6962 shape: a tree
//! over n leaves splits at the largest power of two strictly less than n.
//! This structure supports both inclusion proofs (for directory lookups) and
//! consistency proofs (for the append-only epoch log).
//!
//! Leaves arrive pre-hashed: callers compute leaf hashes with their own
//! domain label (e.g. `nymstr-leaf-v2:` for directory entries,
//! `nymstr-epoch-v2:` for epoch headers), which provides the leaf/interior
//! separation that RFC 6962 gets from its 0x00/0x01 prefixes.

use super::{labeled_hash, labels, FederationError};

pub type Hash = [u8; 32];

/// Hash of an interior node.
fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    labeled_hash(labels::NODE, &data)
}

/// Root of the empty tree.
pub fn empty_root() -> Hash {
    labeled_hash(labels::EMPTY, b"")
}

/// Largest power of two strictly less than n (n >= 2).
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle tree root over a list of leaf hashes.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Inclusion proof (audit path) for the leaf at `index` (RFC 6962 §2.1.1).
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Result<Vec<Hash>, FederationError> {
    if index >= leaves.len() {
        return Err(FederationError::BadProof);
    }
    fn path(leaves: &[Hash], m: usize) -> Vec<Hash> {
        if leaves.len() == 1 {
            return Vec::new();
        }
        let k = split_point(leaves.len());
        if m < k {
            let mut p = path(&leaves[..k], m);
            p.push(root(&leaves[k..]));
            p
        } else {
            let mut p = path(&leaves[k..], m - k);
            p.push(root(&leaves[..k]));
            p
        }
    }
    Ok(path(leaves, index))
}

/// Verify an inclusion proof (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(
    leaf_hash: &Hash,
    index: u64,
    tree_size: u64,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    if index >= tree_size {
        return false;
    }
    if tree_size == 1 {
        return proof.is_empty() && leaf_hash == expected_root;
    }
    let mut fn_ = index;
    let mut sn = tree_size - 1;
    let mut r = *leaf_hash;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                while fn_ != 0 && fn_ & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *expected_root
}

/// Consistency proof showing that the tree over `leaves[..old_size]` is a
/// prefix of the tree over all of `leaves` (RFC 6962 §2.1.2).
pub fn consistency_proof(leaves: &[Hash], old_size: usize) -> Result<Vec<Hash>, FederationError> {
    if old_size == 0 || old_size > leaves.len() {
        return Err(FederationError::BadProof);
    }
    fn subproof(leaves: &[Hash], m: usize, whole: bool) -> Vec<Hash> {
        let n = leaves.len();
        if m == n {
            if whole {
                return Vec::new();
            }
            return vec![root(leaves)];
        }
        let k = split_point(n);
        if m <= k {
            let mut p = subproof(&leaves[..k], m, whole);
            p.push(root(&leaves[k..]));
            p
        } else {
            let mut p = subproof(&leaves[k..], m - k, false);
            p.push(root(&leaves[..k]));
            p
        }
    }
    Ok(subproof(leaves, old_size, true))
}

/// Verify a consistency proof between two tree heads (RFC 9162 §2.1.4.2).
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    // If old_size is an exact power of two, the old root is implied and the
    // verifier prepends it to the path.
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if old_size.is_power_of_two() {
        path.push(*old_root);
    }
    path.extend_from_slice(proof);
    if path.is_empty() {
        return false;
    }

    let mut fn_ = old_size - 1;
    let mut sn = new_size - 1;
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let mut fr = path[0];
    let mut sr = path[0];
    for p in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(p, &fr);
            sr = node_hash(p, &sr);
            if fn_ & 1 == 0 {
                while fn_ != 0 && fn_ & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            sr = node_hash(&sr, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *old_root && sr == *new_root && sn == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::labeled_hash;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| labeled_hash("test-leaf:", format!("leaf-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn empty_and_single_roots() {
        assert_eq!(root(&[]), empty_root());
        let l = leaves(1);
        assert_eq!(root(&l), l[0]);
    }

    #[test]
    fn root_changes_with_any_leaf() {
        let base = leaves(7);
        let r = root(&base);
        for i in 0..7 {
            let mut tampered = base.clone();
            tampered[i] = labeled_hash("test-leaf:", b"tampered");
            assert_ne!(root(&tampered), r, "leaf {i} tamper must change root");
        }
    }

    #[test]
    fn inclusion_roundtrip_all_sizes_all_indices() {
        for n in 1..=24usize {
            let ls = leaves(n);
            let r = root(&ls);
            for i in 0..n {
                let proof = inclusion_proof(&ls, i).unwrap();
                assert!(
                    verify_inclusion(&ls[i], i as u64, n as u64, &proof, &r),
                    "inclusion must verify for size {n}, index {i}"
                );
                // Wrong leaf, wrong index, wrong root must all fail.
                let bogus = labeled_hash("test-leaf:", b"bogus");
                assert!(!verify_inclusion(&bogus, i as u64, n as u64, &proof, &r));
                assert!(!verify_inclusion(
                    &ls[i], i as u64, n as u64, &proof, &bogus
                ));
                if n > 1 {
                    let j = (i + 1) % n;
                    assert!(
                        !verify_inclusion(&ls[i], j as u64, n as u64, &proof, &r),
                        "size {n}: proof for index {i} must not verify at index {j}"
                    );
                }
            }
        }
    }

    #[test]
    fn inclusion_rejects_truncated_and_extended_proofs() {
        let ls = leaves(11);
        let r = root(&ls);
        let proof = inclusion_proof(&ls, 5).unwrap();
        assert!(!verify_inclusion(
            &ls[5],
            5,
            11,
            &proof[..proof.len() - 1],
            &r
        ));
        let mut extended = proof.clone();
        extended.push(empty_root());
        assert!(!verify_inclusion(&ls[5], 5, 11, &extended, &r));
    }

    #[test]
    fn consistency_roundtrip_all_size_pairs() {
        for n in 1..=20usize {
            let ls = leaves(n);
            let new_root = root(&ls);
            for m in 1..=n {
                let old_root = root(&ls[..m]);
                let proof = consistency_proof(&ls, m).unwrap();
                assert!(
                    verify_consistency(m as u64, n as u64, &old_root, &new_root, &proof),
                    "consistency must verify for old={m}, new={n}"
                );
            }
        }
    }

    #[test]
    fn consistency_rejects_forked_history() {
        // Build two logs that agree on the first 5 leaves then diverge.
        let honest = leaves(9);
        let mut forked = leaves(9);
        forked[6] = labeled_hash("test-leaf:", b"rewritten-history");

        let old_root = root(&honest[..5]);
        let forked_root = root(&forked);
        let proof = consistency_proof(&forked, 5).unwrap();
        // The forked tree IS consistent with its own prefix...
        assert!(verify_consistency(
            5,
            9,
            &root(&forked[..5]),
            &forked_root,
            &proof
        ));
        // ...but a fork after a divergent prefix cannot produce a proof
        // against the honest old root.
        let mut diverged_early = leaves(9);
        diverged_early[3] = labeled_hash("test-leaf:", b"rewrite-inside-prefix");
        let bad_proof = consistency_proof(&diverged_early, 5).unwrap();
        assert!(!verify_consistency(
            5,
            9,
            &old_root,
            &root(&diverged_early),
            &bad_proof
        ));
    }

    #[test]
    fn consistency_same_size() {
        let ls = leaves(6);
        let r = root(&ls);
        assert!(verify_consistency(6, 6, &r, &r, &[]));
        assert!(!verify_consistency(6, 6, &r, &empty_root(), &[]));
    }
}
