use std::path::PathBuf;
use std::convert::TryInto;
use std::{fs, ops::Deref, time};
use sha2::{Digest,Sha512};
use hex;

use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt, TryStreamExt};
use structopt::StructOpt;

use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Scalar,};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::sign::{
    OfflineStage, SignManual,
};


use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::hd_acount::account_manage::{account_usage,account_path};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::hd_acount;

use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

mod gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,

    #[structopt(short, long, default_value = "default-signing")]
    room: String,

    #[structopt(short, long, default_value = "local-share1.json")]
    local_share: PathBuf,

    #[structopt(short, long, use_delimiter(true), default_value = "1,2")]
    parties: Vec<u16>,

    #[structopt(short, long, default_value = "hello")]
    data_to_sign: String,

    #[structopt(long, default_value = "0")]
    coin_type: u32,

    #[structopt(long, default_value = "0")]
    account_id: u32,

    #[structopt(long, default_value = "0")]
    usage: u32,    
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let raw_share:hd_acount::account_manage::raw_share<Secp256k1> = serde_json::from_slice(&local_share).context("parse local share")?;


    let coin_type = args.coin_type;
    let account_id = args.account_id;
    
    let usage = match args.usage {
        0 => { account_usage::Receive},
        1 => { account_usage::Change},
        _ => {
            panic!("Unknown usage: {}", args.usage);
        }
    };


    let ac_path = account_path{
        coin_type : coin_type,
        account_index : account_id,
        usage : usage,
    };
    let path = ac_path.get_path_string_bip44();
    
    // let chain_code: [u8; 32] = [2,159,225,26,220,3,10,90,196,167,143,46,129,232,10,246,148,62,105,17,222,213,78,90,3,12,78,30,209,214,26,84];

    let (tweak_sk, y_sum) = 
    hd_acount::btc_hd::call_hd_key(path.as_str(), &raw_share.local_key_hd, raw_share.chain_code);
    
    let local_share = raw_share.local_key_hd.update_hd_key(&Scalar::<Secp256k1>::zero(), &tweak_sk, &y_sum);

    let number_of_parties = args.parties.len();

    let (i, incoming, outgoing) =
        join_computation(args.address.clone(), &format!("{}-offline", args.room))
            .await
            .context("join offline computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(i, args.parties, local_share,)?;
    let completed_offline_stage = AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let (i, incoming, outgoing) = join_computation(args.address, &format!("{}-online", args.room))
        .await
        .context("join online computation")?;

    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let ETHEREUM_HEADER = "\x19Ethereum Signed Message:\n".to_string();
    let data_to_sign = ETHEREUM_HEADER + "5" + args.data_to_sign.as_str();

    use sha3::{Digest,Keccak256};
    extern crate hex;
    let mut hasher = Keccak256::new();
    hasher.update(data_to_sign.as_bytes());
    let result = hex::encode(hasher.finalize());

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(result.as_bytes()),
        completed_offline_stage,
    )?;

    outgoing
        .send(Msg {
            round:7,
            sender: i,
            receiver: None,
            body: partial_signature,
        })
        .await?;

    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;
    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    println!("{}", signature);

    Ok(())
}
