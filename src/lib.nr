use dep::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

global TWO_POW_128: Field = 0x100000000000000000000000000000000;

pub fn verify_signature(
    public_key: EmbeddedCurvePoint,
    signature: [Field; 4],
    message: Field,
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
            calculate_signature_challenge(public_key, sig_s, sig_e, message);

        is_ok &= !r_is_infinite;
        is_ok &= challenge == sig_e_field;
    } else {
        is_ok = false;
    }
    is_ok
}

pub fn assert_valid_signature(
    public_key: EmbeddedCurvePoint,
    signature: [Field; 4],
    message: Field,
) {
    assert(verify_signature(public_key, signature, message));
}

fn calculate_signature_challenge(
    public_key: EmbeddedCurvePoint,
    sig_s: EmbeddedCurveScalar,
    sig_e: EmbeddedCurveScalar,
    message: Field,
) -> (bool, Field) {
    let g1 = EmbeddedCurvePoint {
        x: 1,
        y: 17631683881184975370165255887551781615748388533673675138860,
        is_infinite: false,
    };
    let r = multi_scalar_mul([g1, public_key], [sig_s, sig_e]);
    let challenge = Poseidon2::hash::<4>([r.x, public_key.x, public_key.y, message], 4);
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
        let verified = verify_signature(public_key, signature, message);
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
            143078802728908255222528531053650361205,
            35138403254968750333076497901090943014,
            188707685606044297059945153526364405789,
            14339086325429367795329927995033517719,
        ];

        let pub_key = EmbeddedCurvePoint { x: pub_key_x, y: pub_key_y, is_infinite: false };
        let valid_signature = verify_signature(pub_key, signature, message);
        assert(valid_signature);
        super::assert_valid_signature(pub_key, signature, message);
    }
}

mod bench {
    use super::{assert_valid_signature, verify_signature};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    #[export]
    pub fn bench_verify_signature(
        public_key: EmbeddedCurvePoint,
        signature: [Field; 4],
        message: Field,
    ) -> bool {
        verify_signature(public_key, signature, message)
    }

    #[export]
    pub fn bench_assert_valid_signature(
        public_key: EmbeddedCurvePoint,
        signature: [Field; 4],
        message: Field,
    ) {
        assert_valid_signature(public_key, signature, message)
    }
}
