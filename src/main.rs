use voprf_rs::oprf::{groups, Client, Server, ciphersuite, Input};
use groups::PrimeOrderGroup;
// use groups::p384::NistPoint;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::Sha512;

use groups::redox_ecc::{WPoint,MPoint};

const AUX_DATA: &str = "oprf_finalization_step";

fn main() {
    let verifable = true;
    let input_str = "00";
    let blind_str = "7b";
    let key = "731eb0cbe382f110010d354e3fa36f6512bd056daf3f3d00996ae3ac642edb4726d410db80c2321771a93f0308ded9c9";
    // let dleq_scalar = "9d92c4cc962347d56c05e4b749b57e70461145af696ab61cdefb29f8f88162980410d27fdebad4440431ca0efbffead2";

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
    let eval = srv.eval(&[blinded_input.clone()]);
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

    // println!("Unblinded output: {:?}", hex::encode(unblinded_output[0]));
    println!("Output: {}", hex::encode(out));

    if verifable {
        let proof = &eval.proof.unwrap(); 
        println!("Proof: [{}, {}]", hex::encode(&proof[0]), hex::encode(&proof[1]));
    }
}
