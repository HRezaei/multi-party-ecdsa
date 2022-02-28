/*
 * This file implements the last online round of gg20 tss sign algorithm.
 * It is based on kzen-curv v0.9 and without use of round based framework.
 */

use std::{env, fs, time};
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::cryptographic_primitives::hashing::DigestExt;
use reqwest::Client;
use sha2::{Digest, Sha256};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::{sign_stage6, sign_stage7, SignStage6Input, SignStage7Input};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::LocalSignature;

mod common;
use common::{broadcast, poll_for_broadcasts, postb, Params, PartySignup};

pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-sign".to_string();

    let res_body = postb(&client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}

fn main() {
    if env::args().nth(4).is_some() {
        panic!("too many arguments")
    }
    if env::args().nth(3).is_none() {
        panic!("too few arguments")
    }
    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let threshold = params.threshold.parse::<u16>().unwrap();

    let message_str = env::args().nth(3).unwrap_or_else(|| "".to_string());
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    let client = Client::new();
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let mut input_stage6: SignStage6Input = serde_json::from_str(&data).unwrap();

    let message_bn = Sha256::new()
        .chain_bigint(&BigInt::from_bytes(message))
        .result_bigint();

    input_stage6.message_bn = message_bn;

    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    assert!(broadcast(
        &client,
        party_num_int,
        "round6",
        serde_json::to_string(&res_stage6.local_sig.clone()).unwrap(),
        uuid.clone()
    )
        .is_ok());
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        threshold + 1,
        delay,
        "round6",
        uuid.clone(),
    );
    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..threshold + 2 {
        if i == party_num_int {
            local_sig_vec.push(res_stage6.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round6_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig.clone());
            j += 1;
        }
    }
    let input_stage7 = SignStage7Input {
        local_sig_vec: local_sig_vec.clone(),
        ysum: input_stage6.ysum.clone(),
    };
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");
    let sig = res_stage7.local_sig;
    println!(
        "party {:?} Output Signature: \nR: {:?}\ns: {:?} \nrecid: {:?} \n",
        party_num_int,
        BigInt::from_bytes(sig.r.to_bytes().as_ref()).to_str_radix(16),
        BigInt::from_bytes(sig.s.to_bytes().as_ref()).to_str_radix(16),
        sig.recid.clone()
    );

    let sign_json = serde_json::to_string(&(
        "r",
        (BigInt::from_bytes(&(sig.r.to_bytes())[..])).to_str_radix(16),
        "s",
        (BigInt::from_bytes(&(sig.s.to_bytes())[..])).to_str_radix(16),
    ))
        .unwrap();

    fs::write("signature".to_string(), sign_json).expect("Unable to save !");

}