use std::{env, fs, str::FromStr};

use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapNodeHash,
    TapSighashType, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey, absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    key::{Keypair, Secp256k1},
    opcodes::all::OP_CHECKSIG,
    script::Builder,
    secp256k1::{Message, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, NodeInfo, TaprootBuilder, TaprootSpendInfo},
    transaction,
};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    status: UtxoStatus,
    value: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    block_height: Option<u64>,
    block_hash: Option<String>,
    block_time: Option<u64>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_target(false).init();

    let secp = Secp256k1::new();

    // uncomment this to generate a new private key

    // let mut rng = rand::rng();
    // let mut key_bytes = [0u8; 32];
    // rng.fill(&mut key_bytes);
    // let key = SecretKey::from_slice(&key_bytes).expect("Failed to create SecretKey");
    // println!("key: {}", hex::encode(key.as_ref()));

    let key = env::var("PRIVATE_KEY").unwrap();

    let secret_key = SecretKey::from_str(&key).expect("Failed to create SecretKey");
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let pubkey = keypair.public_key();

    let spend_info = create_control_block_address(pubkey.into()).unwrap();

    let address = Address::p2tr_tweaked(spend_info.output_key(), Network::Bitcoin);

    info!("Taproot address: {}", address);

    let res_utxo = reqwest::get(&format!(
        "https://mempool.space/api/address/{}/utxo",
        address
    ))
    .await
    .unwrap()
    .text()
    .await
    .unwrap();

    let utxos: Vec<Utxo> = serde_json::from_str(&res_utxo).unwrap();

    if utxos.is_empty() {
        info!("No UTXOs found, pls fund address {:?}", address);
        return;
    }

    let inputs: Vec<TxIn> = utxos
        .iter()
        .map(|utxo| TxIn {
            previous_output: OutPoint::new(
                Txid::from_str(&utxo.txid).expect("Invalid txid format"),
                utxo.vout,
            ),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            ..Default::default()
        })
        .collect();

    let mut prev_txouts = Vec::new();
    for input in inputs.clone() {
        let url = format!(
            "https://mempool.space/api/tx/{}/hex",
            input.previous_output.txid
        );
        let response = reqwest::get(&url).await.unwrap().text().await.unwrap();
        let tx: Transaction = deserialize(&Vec::<u8>::from_hex(&response).unwrap()).unwrap();

        let mut outpoint: Option<OutPoint> = None;
        for (i, out) in tx.output.iter().enumerate() {
            if address.script_pubkey() == out.script_pubkey {
                outpoint = Some(OutPoint::new(tx.compute_txid(), i as u32));
                break;
            }
        }
        let prevout = outpoint.expect("Outpoint must exist in tx");
        prev_txouts.push(tx.output[prevout.vout as usize].clone());
    }

    let total_amount = utxos.iter().map(|utxo| utxo.value).sum::<u64>();
    let fee = 1337;

    let mut tx_outs = Vec::new();
    tx_outs.push(TxOut {
        value: Amount::from_sat(total_amount - fee),
        script_pubkey: address.script_pubkey(),
    });

    let mut unsigned_tx: Transaction = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: inputs,
        output: tx_outs,
    };

    let spend_script = spend_script(pubkey.into());

    // let annex_hex = fs::read_to_string("annex.hex").expect("annex.hex not found");
    // let annex_bytes: Vec<u8> = Vec::from_hex(annex_hex.split_whitespace().collect::<String>())
    //     .expect("invalid hex in annex");

    let unsigned_tx_clone = unsigned_tx.clone();

    let tap_leaf_hash = TapLeafHash::from_script(&spend_script, LeafVersion::TapScript);

    for input in unsigned_tx.input.iter_mut() {
        let sighash = SighashCache::new(&unsigned_tx_clone)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prev_txouts),
                tap_leaf_hash,
                TapSighashType::Default,
            )
            .expect("failed to construct sighash");

        let message = Message::from(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        let script_ver = (spend_script.clone(), LeafVersion::TapScript);
        let ctrl_block = spend_info.control_block(&script_ver).unwrap();

        input.witness.push(sig.serialize());
        input.witness.push(script_ver.0.into_bytes());
        input.witness.push(ctrl_block.serialize());
        // input.witness.push(annex_bytes.clone());
    }

    info!("Transaction: {:?}", hex::encode(serialize(&unsigned_tx)));
}

pub fn create_annex_address(
    pubkey: XOnlyPublicKey,
) -> Result<TaprootSpendInfo, bitcoin::taproot::TaprootBuilderError> {
    let secp = Secp256k1::new();

    let script = spend_script(pubkey);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script)
        .unwrap()
        .finalize(&secp, pubkey.into())
        .unwrap();

    Ok(taproot_spend_info)
}

pub fn create_control_block_address(
    pubkey: XOnlyPublicKey,
) -> Result<TaprootSpendInfo, bitcoin::taproot::TaprootBuilderError> {
    let secp = Secp256k1::new();
    let script = spend_script(pubkey);

    let mut root_node = NodeInfo::new_leaf_with_ver(script.clone(), LeafVersion::TapScript);

    let payload_hex = fs::read_to_string("controlblock.hex").expect("controlblock.hex not found");
    let payload_bytes: Vec<u8> = Vec::from_hex(payload_hex.split_whitespace().collect::<String>())
        .expect("invalid hex in controlblock");

    let merkle_path = build_merkle_path_from_bytes(&payload_bytes);

    for sibling_hash in &merkle_path {
        let sibling_node = NodeInfo::new_hidden_node(*sibling_hash);
        root_node = NodeInfo::combine(root_node, sibling_node)?;
    }

    let taproot_spend_info = TaprootSpendInfo::from_node_info(&secp, pubkey, root_node);

    Ok(taproot_spend_info)
}

fn build_merkle_path_from_bytes(bytes: &[u8]) -> Vec<TapNodeHash> {
    let mut padded = bytes.to_vec();
    while padded.len() % 32 != 0 {
        padded.push(0);
    }

    padded
        .chunks(32)
        .map(|chunk| TapNodeHash::from_byte_array(chunk.try_into().unwrap()))
        .collect()
}

pub fn spend_script(pubkey: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}
