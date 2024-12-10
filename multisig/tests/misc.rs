use data_encoding::HEXLOWER;

struct TestCase<'a> {
    /// message
    m: &'a str,
    /// public key
    k: &'a str,
    /// signature
    s: &'a str,
    /// expected verification result
    v: bool,
}

/// Quoting section 5.1 of "Taming the many EdDSAs" (https://eprint.iacr.org/2020/1244.pdf):
///
/// "Test vectors 0-3 are made to pass both cofactored and cofactorless verification,
/// vectors 0-2 have small R, A or both, vector 3 only has mixed-order A and R.
/// Vector 4 is made to pass cofactored and fail in cofactorless verification, this vector
/// is the main indicator of what type of verification is used in the implementation
/// (assuming that vector 3 passes which implies that mixed-order points are not
/// checked for). Vector 5 will be rejected in cofactored libraries that erroneously
/// pre-reduce the scalar: compute (8h mod L)A instead of 8(hA), note that the
/// former might not clear the low order component from A, while the later will
/// always do. Vector 6 or 7 will be accepted in libraries that accept non-canonical
/// S (i.e. S > L) or do an incomplete cheaper check. Vectors 8-9 have small R that
/// is serialized in a non-canonical way, libraries that reduce R prior to hashing will
/// accept vector 8 and reject 9, and libraries that do not reduce R for hashing will
/// behave in an oposite way on vectors 8-9. Vectors 10-11 behave in the same way
/// for a public A serialized in a non-canonical way.
///
/// SUF-CMA secure libraries should reject non-canonical S, i.e. reject vectors 6-
/// 7. Libraries that offer SBS security should reject small order public keys, i.e.
/// reject vectors 0-1. Vector 4 can be used to differentiate between cofactored vs.
/// cofactorless verification."
///
/// where
///
/// SUF-CMA := strong unforgeability under chosen message attacks and
/// SBS     := strongly binding signature
const TESTS: &[(usize, TestCase<'static>)] = &[
    (0, TestCase {
        m: "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
        k: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        s: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
        v: false
    }),
    (1, TestCase {
        m: "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        k: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        s: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        v: false
    }),
    (2, TestCase {
        m: "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
        k: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        s: "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        v: true
    }),
    (3, TestCase {
        m: "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
        k: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        s: "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        v: true
    }),
    (4, TestCase {
        m: "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        k: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        s: "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        v: true
    }),
    (5, TestCase {
        m: "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
        k: "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
        s: "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        v: true
    }),
    (6, TestCase {
        m: "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        k: "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        s: "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        v: false
    }),
    (7, TestCase {
        m: "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
        k: "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
        s: "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        v: false
    }),
    (8, TestCase {
        m: "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        k: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        s: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        v: false
    }),
    (9, TestCase {
        m: "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
        k: "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
        s: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        v: true
    }),
    (10, TestCase {
        m: "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
        k: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        s: "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        v: false
    }),
    (11, TestCase {
        m: "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
        k: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        s: "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        v: false
    }),
];

fn from_hex<const N: usize>(s: &str) -> [u8; N] {
    HEXLOWER.decode(s.as_bytes()).unwrap().try_into().unwrap()
}

#[test]
fn test_vectors_compact() {
    use multisig::{PublicKey, Signature};

    let mut ok = true;

    for (i, t) in TESTS {
        let v = if let Ok(k) = PublicKey::try_from(&from_hex::<32>(t.k)[..]) {
            let s = Signature::try_from(&from_hex::<64>(t.s)[..]).unwrap();
            let m = HEXLOWER.decode(t.m.as_bytes()).unwrap();
            k.is_valid(&m, &s)
        } else {
            false
        };

        if v != t.v {
            ok = false;
            eprintln!("{i:2} FAIL")
        } else {
            eprintln!("{i:2} PASS")
        }
    }

    assert!(ok)
}

#[test]
#[ignore]
fn test_vectors_dalek() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let mut ok = true;

    for (i, t) in TESTS {
        let k = VerifyingKey::from_bytes(&from_hex(t.k)).unwrap();
        let s = Signature::from(from_hex(t.s));
        let m = HEXLOWER.decode(t.m.as_bytes()).unwrap();
        if (!k.is_weak() && k.verify(&m, &s).is_ok()) != t.v {
            ok = false;
            eprintln!("{i:2} FAIL")
        } else {
            eprintln!("{i:2} PASS")
        }
    }

    assert!(ok)
}

#[test]
#[ignore]
fn test_vectors_consensus() {
    use ed25519_consensus::{Signature, VerificationKey};

    let mut ok = true;

    for (i, t) in TESTS {
        let k = VerificationKey::try_from(from_hex(t.k)).unwrap();
        let s = Signature::from(from_hex(t.s));
        let m = HEXLOWER.decode(t.m.as_bytes()).unwrap();
        if k.verify(&s, &m).is_ok() != t.v {
            ok = false;
            eprintln!("{i:2} FAIL")
        } else {
            eprintln!("{i:2} PASS")
        }
    }

    assert!(ok)
}
