use serde::{Deserialize, Serialize};
use sha2::{Sha512, Digest};

//use aes_gcm::aead::generic_array::typenum::Sqrt;
use curv::BigInt;
use curv::arithmetic::traits::*;
use zk_paillier::zkproofs::SALT_STRING;



//pub const SALT_STRING: &[u8] =    NiCorrectKeyProof::SALT_STRING &[75, 90, 101, 110];
//use std::string::String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoSmallFactorSetUp{
    pub n_tilde_ : BigInt,
    pub s_ : BigInt,
    pub t_ : BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoSmallFactorWitness {
    pub p_ : BigInt,
    pub q_ : BigInt,
}

pub struct NoSmallFactorStatement{
    pub n0_: BigInt,
    pub l_ : u32,
    pub varepsilon_: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoSmallFactorProof {
    pub p__ : BigInt,
    pub q__ : BigInt,
    pub a__ : BigInt,
    pub b__ : BigInt,
    pub t__ : BigInt,
    pub sigma__ : BigInt,
    pub z1__ : BigInt,
    pub z2__ : BigInt,
    pub w1__ : BigInt,
    pub w2__ : BigInt,
    pub v__ : BigInt,
    //pub salt_ : String,


}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoSmallFactorProofK {
    pub z1__ : BigInt,
    pub z2__ : BigInt,
    pub w1__ : BigInt,
    pub w2__ : BigInt,
    pub v__ : BigInt,


}

impl NoSmallFactorProof{
    //pub fn SetSalt(String &salt)->() { Self.salt_ = salt; }
    pub fn prove(setup : &NoSmallFactorSetUp, statement : &NoSmallFactorStatement, witness : &NoSmallFactorWitness)
    ->Option<NoSmallFactorProof>{
        let n_tilde = &setup.n_tilde_;
        let s = &setup.s_;
        let t = &setup.t_;
        
        let n0 = &statement.n0_;
        let l = &statement.l_;
        let varepsilon = &statement.varepsilon_;

        let p = &witness.p_;
        let q = &witness.q_;

        let sqrt_n0 = n0.sqrt();
        let limit_alpha_beta = (BigInt::one() << (l + varepsilon) as usize) * sqrt_n0;
        // 2^l * n_tilde
        let limit_mu_nu = (BigInt::one() << (*l as usize)) * n_tilde;
        // 2^l * n0 * n_tilde
        let limit_sigma = &limit_mu_nu * n0;
        // 2^(l + varepsilon) * n0 * n_tilde
        let limit_r = &limit_sigma << *varepsilon as usize;
        // 2^(l + varepsilon) * n_tilde
        let limit_x_y = &limit_mu_nu << *varepsilon as usize;
        
        let alpha = BigInt::sample_below(&limit_alpha_beta);
        let beta = BigInt::sample_below(&limit_alpha_beta);
        let mu = BigInt::sample_below(&limit_mu_nu);
        let nu = BigInt::sample_below(&limit_mu_nu);
        let sigma__ = BigInt::sample_below(&limit_sigma);
        let r = BigInt::sample_below(&limit_r);
        let x = BigInt::sample_below( &limit_x_y);
        let y = BigInt::sample_below(&limit_x_y);

        // P = s^p * t^mu  mod n_tilde
        let p__ = (BigInt::mod_pow(s,p,n_tilde) * BigInt::mod_pow(t,&mu, n_tilde)) % n_tilde;
        // Q = s^q * t^nu  mod n_tilde
        let q__ = (BigInt::mod_pow(s,q, n_tilde) * BigInt::mod_pow(t,&nu, n_tilde)) % n_tilde;
        // A = s^alpha * t^x  mod n_tilde
        let a__ = (BigInt::mod_pow(s,&alpha, n_tilde) * BigInt::mod_pow(t,&x, n_tilde)) % n_tilde;
        // B = s^beta * t^y  mod n_tilde
        let b__ = (BigInt::mod_pow(s,&beta, n_tilde) * BigInt::mod_pow(t,&y, n_tilde)) % n_tilde;
        // T = Q^alpha * t^r  mod n_tilde
        let t__ = (BigInt::mod_pow(&q__,&alpha, n_tilde) * BigInt::mod_pow(t,&r, n_tilde)) % n_tilde;

        //generate e
        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(&n0.to_bytes());
        sha512_hasher.update(&p__.to_bytes());
        sha512_hasher.update(&q__.to_bytes());
        sha512_hasher.update(&a__.to_bytes());
        sha512_hasher.update(&b__.to_bytes());
        sha512_hasher.update(&t__.to_bytes());
        sha512_hasher.update(&SALT_STRING);
        let sha512_digest = sha512_hasher.finalize();
        let e = BigInt::from_bytes(&sha512_digest);
        //if (&e & BigInt::one()) == BigInt::zero(){ e = -e;}

        let sigma_tilde = &sigma__ - &nu * p;
        let z1__ = alpha + &e * p;
        let z2__ = beta + &e * q;
        let w1__ = x + &e * mu;
        let w2__ = y + &e * &nu;
        let v__ = r + &e * sigma_tilde;

        // println!("----------------------------------");

        // println!("N      {}",n_tilde);
        // println!("h1     {}",s);
        // println!("h2     {}",t);
        // println!("n0     {}",n0);

        // println!("sigma  {}",sigma__);
        // println!("p      {}",p__);
        // println!("q      {}",q__);
        // println!("z1     {}",z1__);
        // println!("z2     {}",z2__);
        // println!("w1     {}",w1__);
        // println!("w2     {}",w2__);
        // println!("v      {}",v__);
        // println!("----------------------------------");

        Some(NoSmallFactorProof{
            p__ : p__,
            q__ : q__,
            a__ : a__,
            b__ : b__,
            sigma__ : sigma__,
            t__ : t__,
            z1__ : z1__,
            z2__ : z2__,
            w1__ : w1__,
            w2__ : w2__,
            v__ : v__,
        })
        //todo!()
    }
    pub fn verify(&self,setup : &NoSmallFactorSetUp, statement : &NoSmallFactorStatement)
    ->bool{
        let n_tilde = &setup.n_tilde_;
        let s = &setup.s_;
        let t = &setup.t_;

        // println!("----------------------------------");
        // println!("N      {}",n_tilde);
        // println!("h1     {}",s);
        // println!("h2     {}",t);
        

        
        let n0 = &statement.n0_;
        let l = &statement.l_;
        let varepsilon = &statement.varepsilon_;
        // println!("n0     {}",n0);
        // println!("sigma  {}",&self.sigma__);
        // println!("----------------------------------");
        // println!("l{}",l);
        // println!("varepsilon{}",varepsilon);

        let sqrt_n0 = &n0.sqrt();
        let limit_alpha_beta = (BigInt::one() << (l + varepsilon) as usize) * sqrt_n0;
        if self.z1__ > limit_alpha_beta.clone() || self.z1__ < BigInt::zero() - &limit_alpha_beta{return false;}
        if self.z2__ > limit_alpha_beta.clone() || self.z2__ < BigInt::zero() - &limit_alpha_beta{return false;}


        let mut sha512_hasher = Sha512::new();
        sha512_hasher.update(&n0.to_bytes());
        sha512_hasher.update(&self.p__.to_bytes());
        sha512_hasher.update(&self.q__.to_bytes());
        sha512_hasher.update(&self.a__.to_bytes());
        sha512_hasher.update(&self.b__.to_bytes());
        sha512_hasher.update(&self.t__.to_bytes());
        sha512_hasher.update(&SALT_STRING);
        let sha512_digest = sha512_hasher.finalize();
        let e = BigInt::from_bytes(&sha512_digest);
        //if (&e & BigInt::one()) == BigInt::zero(){ e = -e;}

        let r = (BigInt::mod_pow(s,n0,n_tilde)*BigInt::mod_pow(t,&self.sigma__,n_tilde)) % n_tilde;

        let mut ok = true;
        let mut left_num : BigInt;
        let mut right_num : BigInt;

        // s^z1 * t^w1 = A * P^e  mod n_tilde
        left_num = (BigInt::mod_pow(s,&self.z1__,n_tilde) * BigInt::mod_pow(t,&self.w1__,n_tilde)) % n_tilde;
        right_num = (&self.a__ * BigInt::mod_pow(&self.p__, &e, n_tilde)) % n_tilde;
        ok = left_num == right_num;
        if !ok {return false;}

        // s^z2 * t^w2 = B * Q^e  mod n_tilde
        left_num = (BigInt::mod_pow(s,&self.z2__,n_tilde) * BigInt::mod_pow(t,&self.w2__,n_tilde)) % n_tilde;
        right_num = (&self.b__ * BigInt::mod_pow(&self.q__, &e, n_tilde)) % n_tilde;
        ok = left_num == right_num;
        if !ok {return false;}

        // Q^z1 * t^v = T * R^e  mod n_tilde
        left_num = (BigInt::mod_pow(&self.q__,&self.z1__,n_tilde) * BigInt::mod_pow(t,&self.v__,n_tilde)) % n_tilde;
        right_num = (&self.t__ * BigInt::mod_pow(&r, &e, n_tilde)) % n_tilde;
        ok = left_num == right_num;
        if !ok {return false;}

        true
    }


}