use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use curv::BigInt;
use sha2::{Sha256};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use paillier::{Paillier, Decrypt, Encrypt,EncryptionKey, RawCiphertext, RawPlaintext};
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, MessageStore, P2PMsgs, P2PMsgsStore, Store};
use round_based::{IsCritical, Msg};
use zk_paillier::zkproofs::DLogStatement;

use bip39::{Language, Mnemonic};

use crate::no_small_proof::no_small_proof::NoSmallFactorProof;
use crate::protocols::multi_party_ecdsa::gg_2018::VerifiableSS;
use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys, SharedKeys,
};
use crate::protocols::multi_party_ecdsa::gg_2020::{self, ErrorType};

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenBroadcastMessage1>>,
    {
        let party_keys = Keys::create(self.party_i as usize);
        println!("party_keys");
        let mnemonic = Mnemonic::from_entropy(&party_keys.u_i.to_bytes(), Language::English).unwrap(); // 24-word mnemonic
        let phrase: &str = mnemonic.phrase();
        println!("phrase {}",&phrase);

        let (bc1, decom1) =
            party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();

        output.push(Msg {
            round: 1,
            sender: self.party_i,
            receiver: None,
            body: bc1.clone(),
        });
        Ok(Round1 {
            keys: party_keys,
            bc1,
            decom1,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    keys: Keys,
    bc1: KeyGenBroadcastMessage1,
    decom1: KeyGenDecommitMessage1,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenBroadcastMessage1>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenDecommitMessage1>>,
    {
        output.push(Msg {
            round: 2,
            sender: self.party_i,
            receiver: None,
            body: self.decom1.clone(),
        });
        Ok(Round2 {
            keys: self.keys,
            received_comm: input.into_vec_including_me(self.bc1),
            decom: self.decom1,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenBroadcastMessage1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round2 {
    keys: gg_2020::party_i::Keys,
    received_comm: Vec<KeyGenBroadcastMessage1>,
    decom: KeyGenDecommitMessage1,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenDecommitMessage1>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<(VerifiableSS<Secp256k1>, Vec<u8>,NoSmallFactorProof)>>,
    {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let received_decom = input.into_vec_including_me(self.decom);

        let vss_result = self
            .keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute_nsf_proof(
                &params,
                &received_decom,
                &self.received_comm,
            )

            .map_err(ProceedError::Round2VerifyCommitments)?;
        for (i, share) in vss_result.1.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }

            let enc_key_for_recipient = &self.received_comm[i].e;
            let encrypted_share =
                Paillier::encrypt(enc_key_for_recipient, RawPlaintext::from(share.to_bigint()));
            output.push(Msg {
                round: 3,
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: (vss_result.0.clone(), encrypted_share.0.to_bytes(),vss_result.2[i].clone()),
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.received_comm,

            own_vss: vss_result.0.clone(),
            own_share: vss_result.1[usize::from(self.party_i - 1)].clone(),
            own_nsf_proof : vss_result.2[usize::from(self.party_i - 1)].clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenDecommitMessage1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

pub struct Round3 {
    keys: gg_2020::party_i::Keys,

    y_vec: Vec<Point<Secp256k1>>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,

    own_vss: VerifiableSS<Secp256k1>,
    own_share: Scalar<Secp256k1>,
    own_nsf_proof : NoSmallFactorProof,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<(VerifiableSS<Secp256k1>, Vec<u8>,NoSmallFactorProof)>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<DLogProof<Secp256k1, Sha256>>>,
    {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };

        let input: P2PMsgs<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>,NoSmallFactorProof)> = {
            let encrypted_input = input.into_iter_indexed();
            let mut decrypted_input = P2PMsgsStore::new(self.party_i, self.n);
            for (i, (vss, encrypted_share,nsf_proofs)) in encrypted_input {
                let v = BigInt::from_bytes(&encrypted_share);
                let c = RawCiphertext::from(v);
                let raw_share: RawPlaintext<'_> = Paillier::decrypt(&self.keys.dk, c);
                let share = Scalar::from_bigint(&raw_share.0.into_owned());
                let _ = decrypted_input.push_msg(Msg {
                    round: 4,
                    sender: i,
                    receiver: Some(self.party_i),
                    body: (vss, share, nsf_proofs),
                });
            }
            decrypted_input.finish().unwrap()
        };

        let vec_including_me = input
        .into_vec_including_me((self.own_vss, self.own_share, self.own_nsf_proof));
        
        let vss_schemes: Vec<_> = vec_including_me.iter().map(|(a, _, _)| a.clone()).collect();
        let party_shares: Vec<_> = vec_including_me.iter().map(|(_, b, _)| b.clone()).collect();
        let nsf_proofs: Vec<_> = vec_including_me.iter().map(|(_, _, c)| c.clone()).collect();

        let (shared_keys, dlog_proof) = self
        .keys
        .phase2_verify_vss_construct_keypair_phase3_pok_dlog_nsf_verify(
            &params,
            &self.y_vec,
            party_shares.as_slice(),
            vss_schemes.as_slice(),
            nsf_proofs.as_slice(),
            &self.bc_vec,
            self.party_i.into(),
        )
        .map_err(ProceedError::Round3VerifyVssConstruct)?;
        output.push(Msg {
            round: 4,
            sender: self.party_i,
            receiver: None,
            body: dlog_proof.clone(),
        });

        Ok(Round4 {
            keys: self.keys.clone(),
            y_vec: self.y_vec.clone(),
            bc_vec: self.bc_vec,
            shared_keys,
            own_dlog_proof: dlog_proof,
            vss_vec: vss_schemes,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(VerifiableSS<Secp256k1>, Vec<u8>,NoSmallFactorProof)>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

pub struct Round4 {
    keys: gg_2020::party_i::Keys,
    y_vec: Vec<Point<Secp256k1>>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,
    shared_keys: gg_2020::party_i::SharedKeys<Secp256k1>,
    own_dlog_proof: DLogProof<Secp256k1, Sha256>,
    vss_vec: Vec<VerifiableSS<Secp256k1>>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<DLogProof<Secp256k1, Sha256>>,
    ) -> Result<LocalKey<Secp256k1>> {
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof.clone());

        Keys::verify_dlog_proofs_check_against_vss(
            &params,
            &dlog_proofs,
            &self.y_vec,
            &self.vss_vec,
        )
        .map_err(ProceedError::Round4VerifyDLogProof)?;
        let pk_vec = (0..params.share_count as usize)
            .map(|i| dlog_proofs[i].pk.clone())
            .collect::<Vec<Point<Secp256k1>>>();

        let paillier_key_vec = (0..params.share_count)
            .map(|i| self.bc_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
        let h1_h2_n_tilde_vec = self
            .bc_vec
            .iter()
            .map(|bc1| bc1.dlog_statement.clone())
            .collect::<Vec<DLogStatement>>();

        let (head, tail) = self.y_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);

        let local_key = LocalKey {
            raw_key : self.keys.clone(),
            paillier_dk: self.keys.dk,
            pk_vec,

            keys_linear: self.shared_keys.clone(),
            paillier_key_vec,
            y_sum_s: y_sum.clone(),
            h1_h2_n_tilde_vec,

            vss_scheme: self.vss_vec[usize::from(self.party_i - 1)].clone(),

            i: self.party_i,
            t: self.t,
            n: self.n,
        };
        
        Ok(local_key)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<Secp256k1, Sha256>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey<E: Curve> {
    pub raw_key : Keys<Secp256k1>,
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: gg_2020::party_i::SharedKeys<E>,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: Point<E>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Old_LocalKey<E: Curve> {
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: gg_2020::party_i::SharedKeys<E>,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: Point<E>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}
impl Old_LocalKey<Secp256k1> {
    pub fn to_LocalKey(&self) -> LocalKey<Secp256k1>{
        LocalKey {
            raw_key : Keys::<Secp256k1>::create(1),
            paillier_dk: self.paillier_dk.clone(),
            pk_vec : self.pk_vec.clone(),

            keys_linear: SharedKeys{
                y : self.keys_linear.y.clone(),
                x_i : self.keys_linear.x_i.clone()
            },
            paillier_key_vec : self.paillier_key_vec.clone(),
            y_sum_s: self.y_sum_s.clone(),
            h1_h2_n_tilde_vec : self.h1_h2_n_tilde_vec.clone(),

            vss_scheme : self.vss_scheme.clone(),

            i: self.i,
            t: self.t,
            n: self.n,
        }
    }
}
impl LocalKey<Secp256k1> {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> Point<Secp256k1> {
        self.y_sum_s.clone()
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.paillier_dk, &RawCiphertext::from(ciphertext))
    }

    pub fn update_private_key(
        &self,
        factor_u_i: &Scalar<Secp256k1>,
        factor_x_i: &Scalar<Secp256k1>,
    ) -> Self {
        LocalKey {
            raw_key : Keys {
                u_i: self.raw_key.u_i.clone() + factor_u_i,
                y_i: self.raw_key.y_i.clone(),
                dk: self.raw_key.dk.clone(),
                ek: self.raw_key.ek.clone(),
                party_index: self.raw_key.party_index.clone(),
                N_tilde: self.raw_key.N_tilde.clone(),
                h1: self.raw_key.h1.clone(),
                h2: self.raw_key.h2.clone(),
                xhi: self.raw_key.xhi.clone(),
                xhi_inv: self.raw_key.xhi_inv.clone(),

            },
            paillier_dk: self.paillier_dk.clone(),
            pk_vec : self.pk_vec.clone(),

            keys_linear: SharedKeys{
                y : self.keys_linear.y.clone(),
                x_i : self.keys_linear.x_i.clone() + factor_x_i
            },
            paillier_key_vec : self.paillier_key_vec.clone(),
            y_sum_s: self.y_sum_s.clone(),
            h1_h2_n_tilde_vec : self.h1_h2_n_tilde_vec.clone(),

            vss_scheme : self.vss_scheme.clone(),

            i: self.i,
            t: self.t,
            n: self.n,
        }
            
    }
    pub fn update_hd_key(
        &self,
        factor_u_i: &Scalar<Secp256k1>,
        factor_x_i: &Scalar<Secp256k1>,
        y_sum : &Point<Secp256k1>,
    ) -> Self {
        //Point::generator()
        // let a = Point::generator() * factor_x_i;
        // let c = self.pk_vec[0]+a;

        let (vss_scheme, secret_shares) =
        VerifiableSS::share(1, 3, &(self.raw_key.u_i.clone() + factor_u_i));
        LocalKey {

            raw_key : Keys {
                u_i: self.raw_key.u_i.clone() + factor_u_i,
                y_i: self.raw_key.y_i.clone(),
                dk: self.raw_key.dk.clone(),
                ek: self.raw_key.ek.clone(),
                party_index: self.raw_key.party_index.clone(),
                N_tilde: self.raw_key.N_tilde.clone(),
                h1: self.raw_key.h1.clone(),
                h2: self.raw_key.h2.clone(),
                xhi: self.raw_key.xhi.clone(),
                xhi_inv: self.raw_key.xhi_inv.clone(),

            },
            paillier_dk: self.paillier_dk.clone(),
            pk_vec : self.pk_vec.iter().map(|b: &Point<Secp256k1>| b + Point::generator() * factor_x_i).collect(),

            keys_linear: SharedKeys{
                y : y_sum.clone(),
                x_i : self.keys_linear.x_i.clone() + factor_x_i
            },
            paillier_key_vec : self.paillier_key_vec.clone(),
            y_sum_s: y_sum.clone(),
            h1_h2_n_tilde_vec : self.h1_h2_n_tilde_vec.clone(),

            vss_scheme : vss_scheme.clone(),

            i: self.i,
            t: self.t,
            n: self.n,
        }
            
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey_HD<E: Curve> {
    pub local_key : LocalKey<E>,
    pub tweak_sk : Scalar<E>,
    pub y_sum : Point<E>,
}
// Errors

type Result<T> = std::result::Result<T, ProceedError>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(ErrorType),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(ErrorType),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(ErrorType),
}

impl IsCritical for ProceedError {
    fn is_critical(&self) -> bool {
        true
    }
}
