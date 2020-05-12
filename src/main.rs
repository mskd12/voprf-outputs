use std::fs;
use voprf_rs::oprf::{groups, Client, Server, ciphersuite, Input};
use groups::PrimeOrderGroup;
use sha2::Sha512;
use serde::{Serialize, Deserialize};
use groups::redox_ecc::{WPoint,MPoint};

const AUX_DATA: &str = "oprf_finalization_step";

#[derive(Clone, Deserialize, Debug)]
struct TestVector {
    key: String,
    pub_key: String,
    inputs: Vec<String>,
    blinds: Vec<String>,
    dleq_scalar: String,
}

#[derive(Clone, Serialize, Debug)]
struct FinalTestVector {
    key: String,
    pub_key: String,
    inputs: Vec<String>,
    blinds: Vec<String>,
    dleq_scalar: String,
    expected: Expected
}

#[derive(Clone, Serialize, Debug)]
struct Expected {
    outputs: Vec<String>,
    proof: (String, String)
}

fn main() {
    let name = "VOPRF-curve448-HKDF-SHA512-ELL2-RO";
    let tvs: Vec<TestVector> = serde_json::from_str(
                    &fs::read_to_string(
                        format!("voprf-poc/test-vectors/{}.json", name)
                    ).unwrap()).unwrap();

    let mut ftvs: Vec<FinalTestVector> = Vec::new();

    for tv in tvs {
        println!("{:?}", tv);

        let expected = oprf(&tv.inputs, &tv.blinds, &tv.key, &tv.dleq_scalar);
        ftvs.push(FinalTestVector {
            key: tv.key.clone(),
            pub_key: tv.pub_key.clone(),
            inputs: tv.inputs.clone(),
            blinds: tv.blinds.clone(),
            dleq_scalar: tv.dleq_scalar.clone(),
            expected: expected
        });
    }

    fs::write(format!("voprf-poc/test-vectors/{}.json", name),
                serde_json::to_string_pretty(&ftvs).unwrap()).unwrap()
    // println!("{}", serde_json::to_string_pretty(&ftvs).unwrap());
}

fn oprf(inputs: &Vec<String>, blinds: &Vec<String>, key: &str, dleq_scalar: &str) -> Expected {
    let pog = PrimeOrderGroup::<MPoint,Sha512>::c448();
    let ciph = ciphersuite::Ciphersuite::<MPoint,Sha512>::new(pog.clone(), true);
    let mut srv = Server::<MPoint,Sha512>::setup(ciph.clone());
    srv.set_key(hex::decode(key).unwrap());

    let cli = match Client::<MPoint,Sha512>::setup(ciph.clone(), Some(srv.key.pub_key(&pog))) {
        Ok(c) => c,
        Err(e) => panic!(e),
    };

    // generate blinded input
    let mut blinded_inputs: Vec<Input<MPoint>> = Vec::new(); 
    for (input, blind) in inputs.into_iter().zip(blinds) {
        let input = hex::decode(input).unwrap();
        let blind = hex::decode(blind).unwrap();
        let blinded_input = cli.blind_fixed(&input, &blind);
        blinded_inputs.push(Input{
            data: input,
            elem: blinded_input,
            blind: blind
        });
    }

    // eval
    let mut input_elems = Vec::new();
    for input in &blinded_inputs {
        input_elems.push(input.elem.clone());
    }
    let eval = srv.fixed_eval(&input_elems, &hex::decode(dleq_scalar).unwrap());
    if let Some(d) = &eval.proof {
        assert_eq!(d.len(), 2)
    } else {
        panic!("a proof should have been provided")
    }

    // unblind
    let mut outputs: Vec<String> = Vec::new();
    match cli.unblind(&blinded_inputs, &eval) {
        Ok(u) => {
            // finalize
            for i in 0..blinded_inputs.len() {
                let input_data = &blinded_inputs[i].data;
                let out = cli.finalize(&input_data, &u[i], &AUX_DATA.as_bytes()).expect("Error in finalizing");
                outputs.push(hex::encode(out));
            }
        },
        Err(e) => panic!(e)
    };

    let proof = &eval.proof.unwrap();
    Expected {
        outputs: outputs,
        proof: (hex::encode(&proof[0]), hex::encode(&proof[1]))
    }
}