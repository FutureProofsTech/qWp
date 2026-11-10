//! Exhaustive single-byte mutation sweep for every qWp signature format.
//!
//! This is an attack-discovery tool, not a production test. It prints every
//! mutated signature offset that is still accepted.

use qwp_crypto::{
    Qhs2Signature, Qhs3Signature, Qhs4Signature, Qhs5Signature, Qhs6Signature, Qhs42Signature,
    QhsSignature, qhs_keygen, qhs2_keygen, qhs3_keygen, qhs4_keygen, qhs5_keygen, qhs6_keygen,
    qhs42_keygen,
};
use qwp_e::{verify_qhs1, verify_qhs2, verify_qhs3};

fn main() {
    let message = b"qwp-byte-sweep-message";
    let seed = [7_u8; 32];
    let seed64 = [7_u8; 64];

    {
        let (mut sk, pk) = qhs_keygen(&seed).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if pk
                    .verify(message, &QhsSignature::from_bytes(mutated))
                    .is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs1 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
        let mut accepted_e = Vec::new();
        for offset in 0..sig.len() {
            let mut mutated = sig;
            mutated[offset] ^= 1;
            if verify_qhs1(&pk.to_bytes(), message, &mutated).is_ok() {
                accepted_e.push(offset);
            }
        }
        println!("qhs1 qhse accepted mutations: {accepted_e:?}");
    }

    {
        let (mut sk, pk) = qhs2_keygen(&seed).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if pk
                    .verify(message, &Qhs2Signature::from_bytes(mutated))
                    .is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs2 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
        let mut accepted_e = Vec::new();
        for offset in 0..sig.len() {
            let mut mutated = sig;
            mutated[offset] ^= 1;
            if verify_qhs2(&pk.to_bytes(), message, &mutated).is_ok() {
                accepted_e.push(offset);
            }
        }
        println!("qhs2 qhse accepted mutations: {accepted_e:?}");
    }

    {
        let (mut sk, pk) = qhs3_keygen(&seed).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if pk
                    .verify(message, &Qhs3Signature::from_bytes(mutated))
                    .is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs3 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
        let mut accepted_e = Vec::new();
        for offset in 0..sig.len() {
            let mut mutated = sig;
            mutated[offset] ^= 1;
            if verify_qhs3(&pk.to_bytes(), message, &mutated).is_ok() {
                accepted_e.push(offset);
            }
        }
        println!("qhs3 qhse accepted mutations: {accepted_e:?}");
    }

    {
        let (sk, pk) = qhs4_keygen(&seed).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if pk
                    .verify(message, &Qhs4Signature::from_bytes(mutated))
                    .is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs4 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
    }

    {
        let (sk, pk) = qhs42_keygen(&seed).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if pk
                    .verify(message, &Qhs42Signature::from_bytes(mutated))
                    .is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs42 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
    }

    {
        let (mut sk, pk) = qhs5_keygen(&seed64).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if pk
                    .verify(message, &Qhs5Signature::from_bytes(mutated))
                    .is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs5 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
    }

    {
        let (mut sk, pk) = qhs6_keygen(&seed64, &seed).unwrap();
        let sig = sk.sign(message).unwrap().to_bytes();
        let mut accepted = Vec::new();
        for offset in 0..sig.len() {
            for bit in 0..8 {
                let mut mutated = sig;
                mutated[offset] ^= 1 << bit;
                if let Ok(parsed) = Qhs6Signature::from_slice(&mutated)
                    && pk.verify(message, &parsed).is_ok()
                {
                    accepted.push((offset, bit));
                }
            }
        }
        println!("qhs6 accepted mutations: {accepted:?}");
        if !accepted.is_empty() {
            std::process::exit(1);
        }
    }

    println!("sweep: done");
}
