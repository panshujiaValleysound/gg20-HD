use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use std::convert::TryInto;
use std::ops::Deref;
use sha2::{Digest,Sha512};

use bip32::ChainCode;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::Keygen;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::hd_acount::account_manage::raw_share;
use round_based::async_runtime::AsyncProtocol;

mod gg20_sm_client;
use gg20_sm_client::join_computation;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long)]
    output: PathBuf,

    #[structopt(short, long)]
    index: u16,
    #[structopt(short, long)]
    threshold: u16,
    #[structopt(short, long)]
    number_of_parties: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Cli = Cli::from_args();
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)
        .await
        .context("cannot create output file")?;

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(args.index, args.threshold, args.number_of_parties)?;
    let output = AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    let chain_code: ChainCode = Sha512::digest(&output.y_sum_s.to_bytes(false).deref())[..32]
    .try_into()
    .unwrap();

    // let hd_share_m_44_0_0_0 
    // = HD_Account::init(&output,chain_code,0,0,account_usage::Receive);

    let rs: raw_share<curv::elliptic::curves::Secp256k1> = raw_share{
        local_key_hd : output,
        chain_code : chain_code,
    };
    
    let output = serde_json::to_vec_pretty(&rs).context("serialize output")?;
    tokio::io::copy(&mut output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;

    Ok(())
}
