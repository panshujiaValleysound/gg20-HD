use bip32::{ChainCode,KEY_SIZE};

use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Scalar};
use serde::{Deserialize, Serialize};

use crate::protocols::multi_party_ecdsa::gg_2020::hd_acount::btc_hd;
use crate::protocols::multi_party_ecdsa::gg_2020::state_machine::keygen::LocalKey;

#[derive(Serialize, Deserialize, Clone,Debug)]
pub struct raw_share<E: Curve>{
    pub local_key_hd : LocalKey<E>,
    pub chain_code : ChainCode,
}


#[derive(Clone, Debug)]
pub struct HD_Account<E: Curve> {
    pub local_key_hd : LocalKey<E>,
    pub chain_code : ChainCode,
    pub index : u32,
    pub path : String,
}

#[derive(Clone, Debug)]
pub enum account_usage {
    Receive,
    Change,
}
impl account_usage {
    fn get_num(&self) -> i32 {
        match self {
            account_usage::Receive => 0,
            account_usage::Change => 1,
        }
    }
    pub fn from_num(i:u8) -> Self{
        match i {
            0 => account_usage::Receive,
            1 => account_usage::Change,
            _ => panic!("invlid num"),

        }
    }
}

#[derive(Clone, Debug)]
pub struct account_path{
    pub coin_type : u32,
    pub account_index : u32,
    pub usage : account_usage,
    //pub address_index : u32,
}
impl account_path {
    pub fn init(coin_type:u32,index:u32,usage:account_usage)
    ->Self{
        account_path{
            coin_type : coin_type,
            account_index : index,
            usage : usage,
            //address_index : index,
        }
    }
    pub fn get_path_string_bip44(&self,)
    ->String{
        String::from("m/44") 
        + &String::from("/") 
        + &self.coin_type.to_string()
        + &String::from("/") 
        + &self.account_index.to_string()
        + &String::from("/") 
        + &self.usage.get_num().to_string()
        // + &String::from("/") 
        // + &self.address_index.to_string()
    }
}
impl HD_Account<Secp256k1> {
    pub fn init(
        local_key : &LocalKey<Secp256k1>,
        chain_code : ChainCode,
        coin_type : u32,
        index : u32,
        usage : account_usage)
    ->Self{
        let path = account_path::init(coin_type,index,usage);

        let (tweak_sk, y_sum) = 
        btc_hd::call_hd_key(&path.get_path_string_bip44(), local_key, chain_code);

        HD_Account{
            local_key_hd: local_key.update_hd_key(&Scalar::<Secp256k1>::zero(), &tweak_sk, &y_sum),
            chain_code : chain_code,
            index : index,
            path : path.get_path_string_bip44(),
        }
    }
    
    // pub fn _local_key(
    //     &self,)
    // ->LocalKey<Secp256k1>{
            
    //     let (tweak_sk, y_sum) = 
    //     btc_hd::call_hd_key(&self.path, &self.local_key_base, self.chain_code);
    //     self.local_key_base.update_hd_key(&Scalar::<Secp256k1>::zero(), &tweak_sk, &y_sum)
    //     //self.local_key.clone()
    // }
}