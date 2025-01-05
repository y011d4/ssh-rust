//! RFC 8032
use anyhow::{anyhow, Result};
use num_bigint::BigUint;
use once_cell::sync::Lazy;
use sha2::Digest;
use std::ops::{Add, Mul};
use std::str::FromStr;

static P: Lazy<BigUint> = Lazy::new(|| BigUint::new(vec![2]).pow(255) - BigUint::new(vec![19]));

static Q: Lazy<BigUint> = Lazy::new(|| {
    // 2**252 + 27742317777372353535851937790883648493
    BigUint::from_str(
        "7237005577332262213973186563042994240857116359379907606001950938285454250989",
    )
    .unwrap()
});

static BASE: Lazy<Point> = Lazy::new(|| Point {
    x: BigUint::from_str(
        "15112221349535400772501151409588531511454012693041857206046113283949847762202",
    )
    .unwrap(),
    y: BigUint::from_str(
        "46316835694926478169428394003475163141307993866256225615783033603165251855960", // 4 / 5 % p
    )
    .unwrap(),
    z: BigUint::from_str("1").unwrap(),
    t: BigUint::from_str(
        "46827403850823179245072216630277197565144205554125654976674165829533817101731", // x * y / z
    )
    .unwrap(),
});

#[derive(Clone, Debug)]
struct Point {
    x: BigUint,
    y: BigUint,
    z: BigUint,
    t: BigUint,
}

impl Point {
    fn zero() -> Self {
        Point {
            x: BigUint::new(vec![0]),
            y: BigUint::new(vec![1]),
            z: BigUint::new(vec![1]),
            t: BigUint::new(vec![0]),
        }
    }
}

impl Add for Point {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let d = BigUint::from_str(
            "37095705934669439343138083508754565189542113879843219016388785533085940283555",
        )
        .unwrap();
        let two = BigUint::new(vec![2]);
        let a = &(&self.y + &(*P) - &self.x) * &(&other.y + &(*P) - &other.x) % &(*P);
        let b = &(&self.x + &self.y) * &(&other.x + &other.y) % &(*P);
        let c = &two * &(&self.t * &other.t) % &(*P) * &d % &(*P);
        let d = &two * &(&self.z * &other.z) % &(*P);
        let e = &b + &(*P) - &a;
        let f = &d + &(*P) - &c;
        let g = &d + &c;
        let h = &b + &a;
        let x3 = &e * &f % &(*P);
        let y3 = &g * &h % &(*P);
        let z3 = &f * &g % &(*P);
        let t3 = &e * &h % &(*P);
        Point {
            x: x3,
            y: y3,
            z: z3,
            t: t3,
        }
    }
}

impl Mul<BigUint> for Point {
    type Output = Point;

    fn mul(self, other: BigUint) -> Point {
        let mut p = self.clone();
        let mut q = Point::zero();
        let mut s = other.clone();
        while s > BigUint::new(vec![0]) {
            if &s & BigUint::new(vec![1]) == BigUint::new(vec![1]) {
                q = q + p.clone();
            }
            p = p.clone() + p.clone();
            s >>= 1;
        }
        q
    }
}

impl PartialEq for Point {
    fn eq(&self, other: &Point) -> bool {
        let p = BigUint::from_str(
            "57896044618658097711785492504343953926634992332820282019728792003956564819949",
        )
        .unwrap();
        let zero = BigUint::new(vec![0]);
        if (&self.x * &other.z + &p * &p - &other.x * &self.z) % &p != zero {
            return false;
        }
        if (&self.y * &other.z + &p * &p - &other.y * &self.z) % &p != zero {
            return false;
        }
        true
    }
}

fn point_compress(point: Point) -> Vec<u8> {
    let zinv = point.z.modpow(&(&(*P) - BigUint::new(vec![2])), &P);
    let x = point.x * &zinv % &(*P);
    let y = point.y * &zinv % &(*P);
    let ret: BigUint = y | ((x & BigUint::new(vec![1])) << 255);
    let mut ret = ret.to_bytes_le();
    while ret.len() < 32 {
        ret.push(0);
    }
    ret
}

fn point_decompress(a: Vec<u8>) -> Result<Point> {
    assert_eq!(a.len(), 32);
    let mut y = BigUint::from_bytes_le(&a);
    let sign: u8 = (&y >> 255u8).try_into()?;
    y &= BigUint::from_str(
        "57896044618658097711785492504343953926634992332820282019728792003956564819967",
    )
    .unwrap(); // (1 << 255) - 1
    if let Some(x) = recover_x(y.clone(), sign) {
        let t = &x * &y % &(*P);
        Ok(Point {
            x,
            y,
            z: BigUint::new(vec![1]),
            t,
        })
    } else {
        Err(anyhow!("Invalid point"))
    }
}

fn recover_x(y: BigUint, sign: u8) -> Option<BigUint> {
    let modp_sqrt_m1 = BigUint::from_str("2").unwrap().modpow(
        &((&(*P) - BigUint::from_str("1").unwrap()) / BigUint::from_str("4").unwrap()),
        &P,
    );
    let d = BigUint::from_str(
        "37095705934669439343138083508754565189542113879843219016388785533085940283555",
    )
    .unwrap(); // d = -121665 * modp_inv(121666) % p
    if y >= *P {
        return None;
    }
    let x2: BigUint = (&y * &y - BigUint::from_str("1").unwrap())
        * (&d * &y * &y + BigUint::from_str("1").unwrap())
            .modpow(&(&(*P) - BigUint::from_str("2").unwrap()), &P)
        % &(*P);
    if x2 == BigUint::from_str("0").unwrap() {
        if sign == 0 {
            return Some(BigUint::from_str("0").unwrap());
        } else {
            return None;
        }
    }
    let mut x = x2.modpow(
        &((&(*P) + BigUint::from_str("3").unwrap()) / BigUint::from_str("8").unwrap()),
        &P,
    );
    if (&x * &x - &x2) % &(*P) != BigUint::from_str("0").unwrap() {
        x = x * &modp_sqrt_m1 % &(*P);
    }
    if (&x * &x - &x2) % &(*P) != BigUint::from_str("0").unwrap() {
        return None;
    }
    if (&x & BigUint::from_str("1").unwrap()) != sign.into() {
        x = &(*P) - &x;
    }
    Some(x)
}

fn secret_expand(secret: Vec<u8>) -> (BigUint, Vec<u8>) {
    assert_eq!(secret.len(), 32);
    let mut hasher = sha2::Sha512::new();
    hasher.update(secret);
    let h = hasher.finalize().to_vec();
    let mut a = BigUint::from_bytes_le(&h[..32]);
    a &= BigUint::from_str(
        "28948022309329048855892746252171976963317496166410141009864396001978282409976",
    )
    .unwrap(); // (1 << 254) - 8;
    a |= BigUint::from_str(
        "28948022309329048855892746252171976963317496166410141009864396001978282409984",
    )
    .unwrap(); // 1 << 254
    (a, h[32..].to_vec())
}

fn sha512_modq(bytes: Vec<u8>) -> BigUint {
    let mut hasher = sha2::Sha512::new();
    hasher.update(bytes);
    let h = hasher.finalize().to_vec();
    let ret = BigUint::from_bytes_le(&h);
    ret % &(*Q)
}

pub fn ed25519_sign(secret: Vec<u8>, msg: Vec<u8>) -> Vec<u8> {
    let (a, prefix) = secret_expand(secret);
    let ag = point_compress(BASE.clone() * a.clone());
    let r = sha512_modq([prefix.clone(), msg.clone()].concat());
    let rg = BASE.clone() * r.clone();
    let rs = point_compress(rg);
    let h = sha512_modq([rs.clone(), ag.clone(), msg.clone()].concat());
    let s = (r + h * a) % &(*Q);
    let mut s_bytes = s.to_bytes_le();
    while s_bytes.len() < 32 {
        s_bytes.push(0);
    }
    [rs, s_bytes].concat()
}

pub fn ed25519_verify(msg: Vec<u8>, signature: Vec<u8>, public: Vec<u8>) -> bool {
    if public.len() != 32 {
        println!("a.len() != 32");
        return false;
    }
    if signature.len() != 64 {
        println!("rs.len() != 64");
        return false;
    }
    let rs = signature[..32].to_vec();
    let s = BigUint::from_bytes_le(&signature[32..]);
    if s >= *Q {
        println!("s >= q");
        return false;
    }
    let h = sha512_modq([rs.clone(), public.clone(), msg.clone()].concat());
    let r = match point_decompress(rs) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let a = match point_decompress(public) {
        Ok(x) => x,
        Err(_) => return false,
    };
    r + a * h == BASE.clone() * s
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_ed25519() -> Result<()> {
        let secret =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?;
        let public =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?;
        let msg = vec![];
        let expected = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")?;
        let actual = ed25519_sign(secret, msg.clone());
        assert_eq!(actual, expected);
        assert!(ed25519_verify(msg, actual, public));

        let secret =
            hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")?;
        let public =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")?;
        let msg = vec![0x72];
        let expected = hex::decode("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")?;
        let actual = ed25519_sign(secret, msg.clone());
        assert_eq!(actual, expected);
        assert!(ed25519_verify(msg, actual, public));

        let secret =
            hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")?;
        let public =
            hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")?;
        let msg = vec![0xaf, 0x82];
        let expected = hex::decode("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")?;
        let actual = ed25519_sign(secret, msg.clone());
        assert_eq!(actual, expected);
        assert!(ed25519_verify(msg, actual, public));
        Ok(())
    }
}
