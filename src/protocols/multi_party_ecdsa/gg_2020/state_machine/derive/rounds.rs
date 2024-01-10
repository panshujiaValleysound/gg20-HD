#![allow(non_snake_case)]
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use thiserror::Error;


use round_based::containers::push::Push;
use round_based::Msg;


use crate::protocols::multi_party_ecdsa::gg_2020 as gg20;
use gg20::hd_acount::account_manage::{raw_share,account_path};
use gg20::hd_acount;
use gg20::ErrorType;

type Result<T, E = Error> = std::result::Result<T, E>;



pub struct Round0<C> {
    /// List of parties' indexes from keygen protocol
    ///
    /// I.e. `s_l[i]` must be an index of party `i` that was used by this party in keygen protocol.
    // s_l.len()` equals to `n` (number of parties involved in signing)
    pub ac_path: account_path,
    pub raw_share: raw_share<C>,
}




impl Round0<Secp256k1> {
    pub fn proceed<O,C>(self) -> Result<(Scalar<C>,Point<C>)>
    where
        C: curv::elliptic::curves::Curve,
    {
        let path = self.ac_path.get_path_string_bip44();

        let (tweak_sk, y_sum) = 
        hd_acount::btc_hd::call_hd_key(
            path.as_str(), 
            self.raw_share.local_key_hd, 
            self.raw_share.chain_code);


        Ok((tweak_sk,y_sum))
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
  
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("round 0: {0:?}")]
    Round0(ErrorType),
}
