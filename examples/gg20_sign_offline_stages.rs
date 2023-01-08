/*
 * This file implements the first five offline rounds of gg20 tss sign algorithm.
 * It uses kzen-curv v0.9 and doesn't use round based framework.
 */

#![allow(non_snake_case)]

use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    Keys, Parameters, SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys,
};
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use paillier::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{env, fs, time};
use curv::arithmetic::{Converter, Zero};
use curv::elliptic::curves::{Point, Scalar, Secp256k1};
use zk_paillier::zkproofs::DLogStatement;

mod common;
use common::{broadcast, poll_for_broadcasts, poll_for_p2p, postb, sendp2p, Params, PartySignup};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::{
    sign_stage1, sign_stage2, sign_stage3, sign_stage4, sign_stage5,
    SignStage1Input, SignStage2Input, SignStage3Input, SignStage4Input, SignStage5Input,
    SignStage6Input
};
mod hd_keys;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParamsFile {
    pub parties: String,
    pub threshold: String,
}

impl From<ParamsFile> for Parameters {
    fn from(item: ParamsFile) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS<Secp256k1>>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: Point<Secp256k1>,
    pub h1_h2_N_tilde_vec_s: Vec<DLogStatement>,
}
pub fn signup(client: &Client) -> Result<PartySignup, ()> {
    let key = "signup-sign".to_string();

    let res_body = postb(&client, "signupsign", key).unwrap();
    serde_json::from_str(&res_body).unwrap()
}
#[allow(clippy::cognitive_complexity)]
fn main() {
    if env::args().nth(3).is_none() {
        panic!("You should specify path to the output file as the third argument")
    }

    if env::args().nth(2).is_none() {
        panic!("You should specify path to the output of keygen as the second argument")
    }

    let output_file_path = env::args().nth(3).unwrap();

    let client = Client::new();
    // delay:
    let delay = time::Duration::from_millis(25);
    // read key file
    let data = fs::read_to_string(env::args().nth(2).unwrap())
        .expect("Unable to load keys, did you run keygen first? ");
    let mut keypair: PartyKeyPair = serde_json::from_str(&data).unwrap();

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let THRESHOLD = params.threshold.parse::<u16>().unwrap();

    //signup:
    let (party_num_int, uuid) = match signup(&client).unwrap() {
        PartySignup { number, uuid } => (number, uuid),
    };
    println!("number: {:?}, uuid: {:?}", party_num_int, uuid);

    let path = "0/4/39";
    let chain_code = Scalar::<Secp256k1>::from(1u16);
    let sign_at_path = true;

    // Get root pub key or HD pub key at specified path
    let (f_l_new, y_sum) = match path.is_empty() {
        true => (Scalar::<Secp256k1>::zero(), keypair.y_sum_s),
        false => {
            let path_vector: Vec<BigInt> = path
                .split('/')
                .map(|s| BigInt::from_str_radix(s.trim(), 10).unwrap())
                .collect();
            let chain_code= Point::<Secp256k1>::generator().to_point() * chain_code;
            let (y_sum_child, f_l_new) = hd_keys::get_hd_key(&keypair.y_sum_s, path_vector.clone(), chain_code);
            (f_l_new, y_sum_child.clone())
        }
    };

    keypair.y_sum_s = y_sum;

    if sign_at_path == true {
        // optimize!
        let g: Point<Secp256k1> = Point::<Secp256k1>::generator().to_point();
        // apply on first commitment for leader (leader is party with num=1)
        let com_zero_new = keypair.vss_scheme_vec_s[0].commitments[0].clone() + g * f_l_new.clone();
        // println!("old zero: {:?}, new zero: {:?}", vss_scheme_vec[0].commitments[0], com_zero_new);
        // get iterator of all commitments and skip first zero commitment
        let mut com_iter_unchanged = keypair.vss_scheme_vec_s[0].commitments.iter();
        com_iter_unchanged.next().unwrap();
        // iterate commitments and inject changed commitments in the beginning then aggregate into vector
        let com_vec_new = (0..keypair.vss_scheme_vec_s[1].commitments.len())
            .map(|i| {
                if i == 0 {
                    com_zero_new.clone()
                } else {
                    com_iter_unchanged.next().unwrap().clone()
                }
            })
            .collect::<Vec<Point<Secp256k1>>>();
        let new_vss = VerifiableSS {
            parameters: keypair.vss_scheme_vec_s[0].parameters.clone(),
            commitments: com_vec_new,
        };
        // replace old vss_scheme for leader with new one at position 0
        //    println!("comparing vectors: \n{:?} \nand \n{:?}", vss_scheme_vec[0], new_vss);

        keypair.vss_scheme_vec_s.remove(0);
        keypair.vss_scheme_vec_s.insert(0, new_vss);
        //    println!("NEW VSS VECTOR: {:?}", vss_scheme_vec);
    }

    if sign_at_path == true {
        if party_num_int == 1 {
            // update u_i and x_i for leader
            keypair.party_keys_s.u_i = keypair.party_keys_s.u_i + f_l_new.clone();
            keypair.shared_keys.x_i = keypair.shared_keys.x_i + f_l_new;
        } else {
            // only update x_i for non-leaders
            keypair.shared_keys.x_i = keypair.shared_keys.x_i + f_l_new.clone();
        }
    }

    // round 0: collect signers IDs
    assert!(broadcast(
        &client,
        party_num_int,
        "round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round0_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round0",
        uuid.clone(),
    );

    let mut j = 0;
    //0 indexed vec containing ids of the signing parties.
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == party_num_int {
            signers_vec.push((keypair.party_num_int_s - 1) as usize);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j += 1;
        }
    }

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[(party_num_int - 1) as usize]].clone(),
        index: signers_vec[(party_num_int - 1) as usize],
        s_l: signers_vec.clone(),
        party_ek: keypair.party_keys_s.ek.clone(),
        shared_keys: keypair.shared_keys,
    };
    let res_stage1 = sign_stage1(&input_stage1);
    // publish message A  and Commitment and then gather responses from other parties.
    assert!(broadcast(
        &client,
        party_num_int,
        "round1",
        serde_json::to_string(&(
            res_stage1.bc1.clone(),
            res_stage1.m_a.0.clone(),
            res_stage1.sign_keys.clone().g_w_i
        ))
        .unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round1",
        uuid.clone(),
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut g_w_i_vec: Vec<Point<Secp256k1>> = vec![];

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            let stage1_result = res_stage1.clone();
            bc1_vec.push(stage1_result.bc1.clone());
            g_w_i_vec.push(stage1_result.sign_keys.g_w_i);
            m_a_vec.push(stage1_result.m_a.0.clone());
        } else {
            let (bc1_j, m_a_party_j, g_w_i): (SignBroadcastPhase1, MessageA, Point<Secp256k1>) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            g_w_i_vec.push(g_w_i);
            m_a_vec.push(m_a_party_j);

            j += 1;
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    let input_stage2 = SignStage2Input {
        m_a_vec: m_a_vec.clone(),
        gamma_i: res_stage1.sign_keys.gamma_i.clone(),
        w_i: res_stage1.sign_keys.w_i.clone(),
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    let mut beta_vec: Vec<Scalar<Secp256k1>> = vec![];
    let mut ni_vec: Vec<Scalar<Secp256k1>> = vec![];
    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate there alpha values.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            // private values and they should never be sent out.
            let stage2_result = res_stage2.clone();
            beta_vec.push(stage2_result.gamma_i_vec[j].1.clone());
            ni_vec.push(stage2_result.w_i_vec[j].1.clone());
            // Below two are the C_b messages on page 11 https://eprint.iacr.org/2020/540.pdf
            // paillier encrypted values and are thus safe to send as is.
            let c_b_messageb_gammai = res_stage2.gamma_i_vec[j].0.clone();
            let c_b_messageb_wi = res_stage2.w_i_vec[j].0.clone();

            // If this client were implementing blame(Identifiable abort) then this message should have been broadcast.
            // For the current implementation p2p send is also fine.
            assert!(sendp2p(
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(c_b_messageb_gammai, c_b_messageb_wi,)).unwrap(),
                uuid.clone()
            )
            .is_ok());

            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round2",
        uuid.clone(),
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        let (l_mb_gamma, l_mb_w): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i.clone(),
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        m_b_w_s: m_b_w_rec_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: g_w_i_vec.clone(),
    };

    let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");
    let mut alpha_vec = vec![];
    let mut miu_vec = vec![];
    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            let stage3_result = res_stage3.clone();
            alpha_vec.push(stage3_result.alpha_vec_gamma[j].clone());
            miu_vec.push(stage3_result.alpha_vec_w[j].clone());
            j += 1;
        }
    }

    let input_stage4 = SignStage4Input {
        alpha_vec_s: alpha_vec.clone(),
        beta_vec_s: beta_vec.clone(),
        miu_vec_s: miu_vec.clone(),
        ni_vec_s: ni_vec.clone(),
        sign_keys_s: res_stage1.sign_keys.clone(),
    };
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    //broadcast decommitment from stage1 and delta_i
    assert!(broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i.clone(),)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round4",
        uuid.clone(),
    );
    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            delta_i_vec.push(res_stage4.delta_i.clone());
            decom1_vec.push(res_stage1.decom1.clone());
        } else {
            let (decom_l, delta_l): (SignDecommitPhase1, Scalar<Secp256k1>) =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            delta_i_vec.push(delta_l);
            decom1_vec.push(decom_l);
            j += 1;
        }
    }

    let delta_inv_l = SignKeys::phase3_reconstruct_delta(&delta_i_vec);
    let input_stage5 = SignStage5Input {
        m_b_gamma_vec: m_b_gamma_rec_vec.clone(),
        delta_inv: delta_inv_l.clone(),
        decom_vec1: decom1_vec.clone(),
        bc1_vec: bc1_vec.clone(),
        index: (party_num_int - 1) as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    assert!(broadcast(
        &client,
        party_num_int,
        "round5",
        serde_json::to_string(&(res_stage5.R_dash.clone(), res_stage5.R.clone(),)).unwrap(),
        uuid.clone()
    )
    .is_ok());
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round5",
        uuid.clone(),
    );
    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_vec.push(res_stage5.R.clone());
            R_dash_vec.push(res_stage5.R_dash.clone());
        } else {
            let (R_dash, R): (Point<Secp256k1>, Point<Secp256k1>) = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);
            j += 1;
        }
    }

    let input_stage6 = SignStage6Input {
        R_dash_vec: R_dash_vec.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(party_num_int - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i.clone(),
        randomness: res_stage1.m_a.1.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i.clone(),
        ysum: keypair.y_sum_s.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        //This is just a placeholder, the real message will be set in the online phase:
        message_bn: BigInt::zero(),
    };

    let offline_stage_json = serde_json::to_string(&(input_stage6))
        .unwrap();

    fs::write(output_file_path.to_string(), offline_stage_json).expect("Unable to save !");

    //The remaining of this function is moved to the gg20_sign_online_stage.rs
    /*
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
        THRESHOLD + 1,
        delay,
        "round6",
        uuid.clone(),
    );
    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
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
        ysum: keypair.y_sum_s.clone(),
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
    */
}
