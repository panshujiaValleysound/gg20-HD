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
    
    let (tweak_sk, y_sum) = 
    hd_acount::btc_hd::call_hd_key(path.as_str(), &raw_share.local_key_hd, raw_share.chain_code);
    

    Ok(())
}
