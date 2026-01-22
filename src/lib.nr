use dep::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

// the multiples of BN_P that are still less than 2^254 split into (lo, hi)
global BN_P_m: [(Field, Field); 6] = [
    (0, 0),
    (201385395114098847380338600778089168199, 64323764613183177041862057485226039389),
    (62488423307259231297302594124410124942, 128647529226366354083724114970452078779),
    (263873818421358078677641194902499293141, 192971293839549531125586172455678118168),
    (124976846614518462594605188248820249884, 257295058452732708167448229940904157558),
    (326362241728617309974943789026909418083, 321618823065915885209310287426130196947),
];

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature(
    public_key: EmbeddedCurvePoint,
    signature: [u8; 64],
    message: Field,
) -> bool {
    //scalar lo/hi from bytes
    let sig_s = scalar_from_bytes(signature, 0);
    let sig_e = scalar_from_bytes(signature, 32);
    // pub_key is on Grumpkin curve
    let mut is_ok = (public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17)
        & (!public_key.is_infinite);

    if ((sig_s.lo != 0) | (sig_s.hi != 0)) & ((sig_e.lo != 0) | (sig_e.hi != 0)) {
        let (r_is_infinite, result) =
            calculate_signature_challenge(public_key, sig_s, sig_e, message);

        is_ok &= !r_is_infinite;
        for i in 0..32 {
            is_ok &= result[i] == signature[32 + i];
        }
    } else {
        is_ok = false;
    }
    is_ok
}

pub fn assert_valid_signature(public_key: EmbeddedCurvePoint, signature: [u8; 64], message: Field) {
    //scalar lo/hi from bytes
    let sig_s = scalar_from_bytes(signature, 0);
    let sig_e = scalar_from_bytes(signature, 32);

    // assert pub_key is on Grumpkin curve
    assert(public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17);
    assert(public_key.is_infinite == false);
    // assert signature is not null
    assert((sig_s.lo != 0) | (sig_s.hi != 0));
    assert((sig_e.lo != 0) | (sig_e.hi != 0));

    let (r_is_infinite, result) = calculate_signature_challenge(public_key, sig_s, sig_e, message);

    assert(!r_is_infinite);
    for i in 0..32 {
        assert(result[i] == signature[32 + i]);
    }
}

fn calculate_signature_challenge(
    public_key: EmbeddedCurvePoint,
    sig_s: EmbeddedCurveScalar,
    sig_e: EmbeddedCurveScalar,
    message: Field,
) -> (bool, [u8; 32]) {
    let g1 = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    let reduced_sig_e = normalize_signature(sig_e);
    let r = multi_scalar_mul([g1, public_key], [sig_s, reduced_sig_e]);
    let challenge = Poseidon2::hash::<4>([r.x, public_key.x, public_key.y, message], 4);
    let result = challenge.to_be_bytes::<32>();
    (r.is_infinite, result)
}

unconstrained fn __gt(a: Field, b: Field) -> bool {
    b.lt(a)
}

// gets the quotient of lo/hi when divided by BN254_Fq modulus
unconstrained fn __get_quotient(hi: Field, lo: Field) -> u32 {
    let mut q: u32 = 0;
    let mut r_hi = hi;
    let mut r_lo = lo;
    let MODULUS = BN_P_m[1];

    for _ in 1..6 {
        // check if rhi, rlo is larger than BN_P
        let borrow = r_lo.lt(MODULUS.0);

        if borrow {
            r_lo = r_lo + TWO_POW_128;
            // rlo is always larger than BN_P lo now
            r_hi = r_hi - 1;
        }

        let MODULUS_hi = MODULUS.1;

        let gt_flag = !r_hi.lt(MODULUS_hi);

        if gt_flag {
            r_hi = r_hi - MODULUS.1;
            r_lo = r_lo - MODULUS.0;
            if TWO_POW_128.lt(r_lo) | TWO_POW_128.lt(r_hi) {
                break;
            }
            q += 1;
        }
    }
    q
}

// this method reduces the signature to the range [0, BN254_Fq_MODULUS)
fn normalize_signature(sig_e: EmbeddedCurveScalar) -> EmbeddedCurveScalar {
    let mut hi = sig_e.hi;
    let mut lo = sig_e.lo;
    // get the quotient
    let q = unsafe { __get_quotient(hi, lo) };
    let MODULUSmq = (BN_P_m[q].0, BN_P_m[q].1);
    let MODULUS = BN_P_m[1];
    // remove MODULUS * q from lo/hi
    let borrow = unsafe { __gt(MODULUSmq.0, lo) };
    // rlo, rhi is the signature without the multiple of MODULUS
    let rlo = lo - MODULUSmq.0 + borrow as Field * TWO_POW_128;
    let rhi = hi - borrow as Field - MODULUSmq.1;
    // now we validate that rlo and rhi are positive
    rlo.assert_max_bit_size::<128>();
    rhi.assert_max_bit_size::<128>();
    // validate that rlo, rhi is smaller than MODULUS
    // if the lo is larger than the modulus lo we have to get a borrow
    let borrow = unsafe { __gt(rlo, MODULUS.0) };
    let rplo = MODULUS.0 - rlo + borrow as Field * TWO_POW_128;
    let rphi = MODULUS.1 - rhi - borrow as Field;
    // check that rplo and rphi are positive
    rplo.assert_max_bit_size::<128>();
    rphi.assert_max_bit_size::<128>();
    EmbeddedCurveScalar::new(rlo, rhi)
}

//Bytes to scalar: take the first (after the specified offset) 16 bytes of the input as the lo value, and the next 16 bytes as the hi value
fn scalar_from_bytes(bytes: [u8; 64], offset: u32) -> EmbeddedCurveScalar {
    let mut v: Field = 1;
    let mut lo: Field = 0;
    let mut hi: Field = 0;
    for i in 0..16 {
        lo = lo + (bytes[offset + 31 - i] as Field) * v;
        hi = hi + (bytes[offset + 15 - i] as Field) * v;
        v = v * 256;
    }
    let sig_s = EmbeddedCurveScalar::new(lo, hi);
    sig_s
}

mod test {
    use super::normalize_signature;
    use super::verify_signature;
    use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

    #[test]
    fn test_zero_signature() {
        let public_key: EmbeddedCurvePoint = EmbeddedCurvePoint {
            x: 1,
            y: 17631683881184975370165255887551781615748388533673675138860,
            is_infinite: false,
        };
        let signature: [u8; 64] = [0; 64];
        let message: Field = 0;
        let verified = verify_signature(public_key, signature, message);
        assert(!verified);
    }

    // This test vector is generated in the SDK's test/grumpkin-schnorr.test.ts.
    #[test]
    fn smoke_test() {
        let message: Field = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        let pub_key_x: Field = 0x01;
        let pub_key_y: Field = 0x2cf135e7506a45d632d270d45f1181294833fc48d823f272c;
        let signature: [u8; 64] = [
            26, 111, 105, 9, 152, 132, 90, 54, 95, 179, 1, 32, 58, 106, 176, 38, 107, 163, 249, 157,
            107, 44, 35, 99, 234, 252, 182, 248, 159, 175, 187, 117, 10, 201, 155, 137, 230, 71,
            104, 61, 88, 66, 7, 175, 65, 89, 254, 151, 141, 247, 199, 59, 7, 143, 226, 152, 174,
            101, 51, 70, 220, 212, 128, 29,
        ];

        let pub_key = EmbeddedCurvePoint { x: pub_key_x, y: pub_key_y, is_infinite: false };
        let valid_signature = verify_signature(pub_key, signature, message);
        assert(valid_signature);
        super::assert_valid_signature(pub_key, signature, message);
    }

    #[test]
    fn test_normalize_signature() {
        let sig_e = EmbeddedCurveScalar::new(
            201385395114098847380338600778112493540,
            64323764613183177041862057485226039389,
        );
        let normalized = normalize_signature(sig_e);
        let expected = EmbeddedCurveScalar::new(23325341, 0);
        assert(normalized == expected);
    }

    #[test]
    fn test_normalize_signature_2() {
        let sig_e = EmbeddedCurveScalar::new(
            263873818421358078677641194902522618482,
            192971293839549531125586172455678118168,
        );
        let normalized = normalize_signature(sig_e);
        let expected = EmbeddedCurveScalar::new(23325341, 0);
        assert(normalized == expected);
    }

}

mod bench {
    use super::{assert_valid_signature, verify_signature};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: [u8; 64],
        message: Field,
    ) -> bool {
        verify_signature(public_key, signature, message)
    }

    #[export]
    pub fn bench_assert_valid_signature(
        public_key: EmbeddedCurvePoint,
        signature: [u8; 64],
        message: Field,
    ) {
        assert_valid_signature(public_key, signature, message)
    }
}
