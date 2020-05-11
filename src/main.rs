use std::fs;
use voprf_rs::oprf::{groups, Client, Server, ciphersuite, Input};
use groups::PrimeOrderGroup;
use sha2::Sha512;
use serde::Deserialize;
use groups::redox_ecc::{WPoint,MPoint};

const AUX_DATA: &str = "oprf_finalization_step";

#[derive(Clone, Deserialize, Debug)]
struct TestVector {
    key: String,
    pub_key: String,
    inputs: Vec<String>,
    blinds: Vec<String>,
    dleq_scalar: String
}

fn main() {
    let name = "VOPRF-P384-HKDF-SHA512-SSWU-RO";
    let tvs: Vec<TestVector> = serde_json::from_str(
                    &fs::read_to_string(
                        format!("voprf-poc/test-vectors/{}.json", name)
                    ).unwrap()).unwrap();
    println!("{:?}", tvs[0]);

    p384(&tvs[0].inputs[0], &tvs[0].blinds[0], &tvs[0].key, &tvs[0].dleq_scalar)
}

fn p384(input_str: &str, blind_str: &str, key: &str, dleq_scalar: &str) {
    let verifable = true;
    let pog = PrimeOrderGroup::<WPoint,Sha512>::p384();
    let ciph = ciphersuite::Ciphersuite::<WPoint,Sha512>::new(pog.clone(), verifable);
    let mut srv = Server::<WPoint,Sha512>::setup(ciph.clone());
    srv.set_key(hex::decode(key).unwrap());

    let cli = match Client::<WPoint,Sha512>::setup(ciph.clone(), Some(srv.key.pub_key(&pog))) {
        Ok(c) => c,
        Err(e) => panic!(e),
    };

    let input = Input::<WPoint>{
        data: hex::decode(input_str).unwrap(),
        elem: pog.generator.clone(), 
        blind: hex::decode(blind_str).unwrap()
    };

    println!("Input: {}", hex::encode(&input.data));
    println!("Blind: {}", hex::encode(&input.blind));
    println!("Secret key: {}", srv.key.as_hex());
    println!("Public key: {}", srv.key.pub_key(&pog).as_hex(&pog));

    // generate blinded input
    let blinded_input = cli.blind_fixed(&input.data, &input.blind);

    // eval
    let eval = srv.fixed_eval(&[blinded_input.clone()], &hex::decode(dleq_scalar).unwrap());
    assert_eq!(eval.elems.len(), 1);
    if verifable {
        if let Some(d) = &eval.proof {
            assert_eq!(d.len(), 2)
        } else {
            panic!("a proof should have been provided")
        }
    }

    let mut updated_input = input.clone();
    updated_input.elem = blinded_input;
    // unblind
    let unblinded_output = cli.unblind(&[updated_input], &eval).expect("Error in unblinding operation");

    // finalize
    let out = cli.finalize(&input.data, &unblinded_output[0], &AUX_DATA.as_bytes()).expect("Error in finalizing");

    println!("Output: {}", hex::encode(out));

    if verifable {
        let proof = &eval.proof.unwrap(); 
        println!("Proof: [{}, {}]", hex::encode(&proof[0]), hex::encode(&proof[1]));
    }

}