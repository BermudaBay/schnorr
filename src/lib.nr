use dep::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature(
    public_key: EmbeddedCurvePoint,
    signature: [Field; 4],
    message: Field,
    domain_separator: Field,
) -> bool {
    // sig_s.lo, sig_s.hi, sig_e.lo, sig_e.hi
    let sig_s = EmbeddedCurveScalar::new(signature[0], signature[1]);
    let sig_e = EmbeddedCurveScalar::new(signature[2], signature[3]);
    let sig_e_field = signature[2] + signature[3] * TWO_POW_128;
    // pub_key is on Grumpkin curve
    let mut is_ok = (public_key.y * public_key.y == public_key.x * public_key.x * public_key.x - 17)
        & (!public_key.is_infinite);

    if ((sig_s.lo != 0) | (sig_s.hi != 0)) & ((sig_e.lo != 0) | (sig_e.hi != 0)) {
        let (r_is_infinite, challenge) =
            calculate_signature_challenge(public_key, sig_s, sig_e, message, domain_separator);

        is_ok &= !r_is_infinite;
        is_ok &= challenge == sig_e_field;
    } else {
        is_ok = false;
    }
    is_ok
}

fn calculate_signature_challenge(
    public_key: EmbeddedCurvePoint,
    sig_s: EmbeddedCurveScalar,
    sig_e: EmbeddedCurveScalar,
    message: Field,
    domain_separator: Field,
) -> (bool, Field) {
    let g1 = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    let r = multi_scalar_mul([g1, public_key], [sig_s, sig_e]);
    let challenge = Poseidon2::hash::<5>(
        [r.x, public_key.x, public_key.y, message, domain_separator],
        5,
    );
    (r.is_infinite, challenge)
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
        // sig_s.lo, sig_s.hi, sig_e.lo, sig_e.hi
        let signature: [Field; 4] = [
            260569492883543726800739203901533056949,
            4377021386512916997028816284466136813,
            71216995451408825481734480678481710045,
            45100468193885201131377609611658323920,
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
