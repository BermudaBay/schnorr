use dep::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

pub fn verify_signature(
    public_key: EmbeddedCurvePoint,
    signature: [Field; 4],
    message: Field,
    domain_separator: Field,
) -> bool {
    // signature = [R.x, R.y, z.lo, z.hi]
    let r = EmbeddedCurvePoint { x: signature[0], y: signature[1], is_infinite: false };
    let z = EmbeddedCurveScalar::new(signature[2], signature[3]);
    let mut is_ok = (public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17)
        & (!public_key.is_infinite)
        & (r.y * r.y == r.x * r.x * r.x - 17)
        & (!r.is_infinite);

    if (z.lo != 0) | (z.hi != 0) {
        let c = calculate_signature_challenge(r, public_key, message, domain_separator);
        let c_scalar = field_to_scalar(c);

        // Verify the Schnorr equation: zG == R + cP.
        let lhs = fixed_base_scalar_mul(z);
        let rhs = multi_scalar_mul([r, public_key], [EmbeddedCurveScalar::new(1, 0), c_scalar]);

        is_ok &= c != 0;
        is_ok &= !lhs.is_infinite;
        is_ok &= !rhs.is_infinite;
        is_ok &= (lhs.x == rhs.x) & (lhs.y == rhs.y) & (lhs.is_infinite == rhs.is_infinite);
    } else {
        is_ok = false;
    }
    is_ok
}

fn calculate_signature_challenge(
    r: EmbeddedCurvePoint,
    public_key: EmbeddedCurvePoint,
    message: Field,
    domain_separator: Field,
) -> Field {
    Poseidon2::hash::<6>(
        [r.x, r.y, public_key.x, public_key.y, message, domain_separator],
        6,
    )
}

fn field_to_scalar(value: Field) -> EmbeddedCurveScalar {
    let bits = value.to_le_bits::<254>();
    let mut lo: Field = 0;
    let mut hi: Field = 0;
    let mut lo_pow: Field = 1;
    let mut hi_pow: Field = 1;

    for i in 0..128 {
        if bits[i] == 1 {
            lo += lo_pow;
        }
        lo_pow += lo_pow;
    }

    for i in 128..254 {
        if bits[i] == 1 {
            hi += hi_pow;
        }
        hi_pow += hi_pow;
    }

    EmbeddedCurveScalar::new(lo, hi)
}

mod test {
    use super::verify_signature;
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[test]
    fn test_zero_signature() {
        let public_key: EmbeddedCurvePoint = EmbeddedCurvePoint {
            x: 1,
            y: 17631683881184975370165255887551781615748388533673675138860,
            is_infinite: false,
        };
        let signature: [Field; 4] = [0; 4];
        let message: Field = 0;
        let domain_separator: Field =
            18593004833411356993981768246051920231328811611081460266067910279816360120902;
        let verified = verify_signature(public_key, signature, message, domain_separator);
        assert(!verified);
    }

    // This test vector is generated in the SDK's test/grumpkin-schnorr.test.ts.
    #[test]
    fn smoke_test() {
        let message: Field = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
        let pub_key_x: Field = 0x01;
        let pub_key_y: Field = 0x2cf135e7506a45d632d270d45f1181294833fc48d823f272c;
        // signature = [R.x, R.y, z.lo, z.hi]
        let signature: [Field; 4] = [
            9915432805254769802945759119347258998190753519701002202559057175337257872242,
            10114568562560069786208967066348590975006875861777797572733201883898308679145,
            241980287471428947893681703052123298622,
            42991417619193466760665062508429985938,
        ];
        let domain_separator: Field =
            18593004833411356993981768246051920231328811611081460266067910279816360120902;

        let pub_key = EmbeddedCurvePoint { x: pub_key_x, y: pub_key_y, is_infinite: false };
        let valid_signature = verify_signature(pub_key, signature, message, domain_separator);
        assert(valid_signature);
    }
}

mod bench {
    use super::verify_signature;
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: [Field; 4],
        message: Field,
        domain_separator: Field,
    ) -> bool {
        verify_signature(public_key, signature, message, domain_separator)
    }
}
