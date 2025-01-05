//! RFC 7748
use num_bigint::BigUint;
use once_cell::sync::Lazy;

static P: Lazy<BigUint> = Lazy::new(|| BigUint::new(vec![2]).pow(255) - BigUint::new(vec![19]));
pub static GX: Lazy<Vec<u8>> = Lazy::new(|| encode_u_coordinate(BigUint::new(vec![9]), &P));

fn encode_u_coordinate(u: BigUint, p: &BigUint) -> Vec<u8> {
    let ff = BigUint::new(vec![255]);
    let mut u = u % p;
    let bits = p.bits();
    let mut ret = vec![];
    for _ in 0..((bits + 7) / 8) {
        ret.push((&u & &ff).try_into().unwrap());
        u >>= 8;
    }
    ret
}

fn decode_u_coordinate(u: Vec<u8>, p: &BigUint) -> BigUint {
    assert_eq!(u.len(), 32, "u coordinate must be 32 bytes");
    let mut u = u.clone();
    u[31] &= (1 << (p.bits() % 8)) - 1;
    decode_little_endian(u)
}

fn decode_little_endian(b: Vec<u8>) -> BigUint {
    BigUint::from_bytes_le(&b)
}

fn decode_scalar_25519(k: Vec<u8>) -> BigUint {
    let mut k = k.clone();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    decode_little_endian(k)
}

fn cswap(swap: u8, x_2: BigUint, x_3: BigUint) -> (BigUint, BigUint) {
    let mut x_2 = x_2;
    let mut x_3 = x_3;
    let bits = x_2.bits().max(x_3.bits());
    // let swap = BigUint::from_bytes_be(&vec![if swap == 1 { 255 } else { 0 }; bits as usize]);
    let swap = BigUint::from_bytes_be(&vec![(256 as i16 - swap as i16) as u8; bits as usize]);
    let dummy = swap & (x_2.clone() ^ x_3.clone());
    x_2 ^= dummy.clone();
    x_3 ^= dummy.clone();
    (x_2, x_3)
}

fn curve25519_multiply(k: BigUint, u: BigUint) -> BigUint {
    let p = BigUint::new(vec![2]).pow(255) - BigUint::new(vec![19]);
    let two = BigUint::new(vec![2]);
    let x_1 = u.clone();
    let mut x_2 = BigUint::new(vec![1]);
    let mut z_2 = BigUint::new(vec![0]);
    let mut x_3 = u;
    let mut z_3 = BigUint::new(vec![1]);
    let mut swap = 0;
    let bits = p.bits();
    for t in (0..bits).rev() {
        let k_t = ((k.clone() >> t) % BigUint::new(vec![2]))
            .try_into()
            .unwrap();
        swap ^= k_t;
        (x_2, x_3) = cswap(swap, x_2, x_3);
        (z_2, z_3) = cswap(swap, z_2, z_3);
        swap = k_t;
        let a = (&x_2 + &z_2) % &p;
        let aa = a.modpow(&two, &p);
        let b = (&p + x_2 - z_2) % &p;
        let bb = b.modpow(&two, &p);
        let e = (&p + &aa - &bb) % &p;
        let c = (&x_3 + &z_3) % &p;
        let d = (&p + x_3 - z_3) % &p;
        let da = d * a % &p;
        let cb = c * b % &p;
        x_3 = (&da + &cb).modpow(&BigUint::new(vec![2]), &p);
        z_3 = &x_1 * (&p + da - cb).modpow(&BigUint::new(vec![2]), &p) % &p;
        x_2 = &aa * bb % &p;
        z_2 = &e * ((aa + (BigUint::new(vec![121665]) * &e % &p) % &p) % &p) % &p;
    }
    let (x_2, _x_3) = cswap(swap, x_2, x_3);
    let (z_2, _z_3) = cswap(swap, z_2, z_3);
    x_2 * (z_2.clone().modpow(&(&p - &two), &p)) % &p
}

pub fn x25519(k: Vec<u8>, u: Vec<u8>) -> Vec<u8> {
    let p = BigUint::new(vec![2]).pow(255) - BigUint::new(vec![19]);
    let k = decode_scalar_25519(k);
    let u = decode_u_coordinate(u, &p);
    encode_u_coordinate(curve25519_multiply(k, u), &p)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_x25519() -> Result<()> {
        let k = hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")?;
        let u = hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")?;
        let expected =
            hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")?;
        let actual = x25519(k, u);
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    fn test_share() -> Result<()> {
        let a_priv =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?;
        let b_priv =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")?;
        let a_pub = x25519(a_priv.clone(), GX.clone());
        let b_pub = x25519(b_priv.clone(), GX.clone());
        let expected =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")?;
        let actual = x25519(a_priv, b_pub);
        assert_eq!(actual, expected);
        let actual = x25519(b_priv, a_pub);
        assert_eq!(actual, expected);
        Ok(())
    }
}
