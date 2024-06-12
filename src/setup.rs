use ark_ec::pairing::PairingOutput;
use ark_ec::{pairing::Pairing, Group};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use ark_serialize::*;
use ark_std::{rand::RngCore, One, UniformRand, Zero};
use rayon::iter::IntoParallelIterator;
use std::ops::Mul;

use crate::encryption::Ciphertext;
use crate::kzg::{UniversalParams, KZG10};
use rayon::iter::ParallelIterator;
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct SecretKey<E: Pairing> {
    pub sk: E::ScalarField,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct PublicKey<E: Pairing> {
    pub id: usize,
    pub bls_pk: E::G1,          //BLS pk
    pub sk_li: E::G1,           //hint
    pub sk_li_minus0: E::G1,    //hint
    pub sk_li_by_z: Vec<E::G1>, //hint
    pub sk_li_by_tau: E::G1,    //hint
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct AggregateKey<E: Pairing> {
    pub pk: Vec<PublicKey<E>>,
    pub agg_sk_li_by_z: Vec<E::G1>,
    pub ask: E::G1,
    pub z_g2: E::G2,

    //preprocessed values
    pub h_minus1: E::G2,
    pub e_gh: PairingOutput<E>,
}

impl<E: Pairing> PublicKey<E> {
    pub fn new(
        id: usize,
        bls_pk: E::G1,
        sk_li: E::G1,
        sk_li_minus0: E::G1,
        sk_li_by_z: Vec<E::G1>,
        sk_li_by_tau: E::G1,
    ) -> Self {
        PublicKey {
            id,
            bls_pk,
            sk_li,
            sk_li_minus0,
            sk_li_by_z,
            sk_li_by_tau,
        }
    }
}

impl<E: Pairing> SecretKey<E> {
    pub fn new<R: RngCore>(rng: &mut R) -> Self {
        SecretKey {
            sk: E::ScalarField::rand(rng),
        }
    }

    pub fn nullify(&mut self) {
        self.sk = E::ScalarField::one()
    }

    pub fn get_pk(&self, id: usize, params: &UniversalParams<E>, n: usize) -> PublicKey<E> {
        let sk_li_by_z = (0..n)
            .into_par_iter()
            .map(|j| {
                let li_by_z = if params.li_by_z.contains_key(&(id, j)) {
                    params.li_by_z[&(id, j)]
                } else {
                    params.li_by_z[&(j, id)]
                };

                li_by_z * self.sk
            })
            .collect::<Vec<_>>();

        let li = &params.l_i[id];

        let f = DensePolynomial::<E::ScalarField>::from_coefficients_vec(li.coeffs[1..].to_vec());
        let sk_times_f = &f * self.sk;
        let sk_li_by_tau = KZG10::commit_g1(params, &sk_times_f)
            .expect("commitment failed")
            .into();

        let mut f = li.mul(self.sk);
        let sk_li = KZG10::commit_g1(params, &f)
            .expect("commitment failed")
            .into();

        f.coeffs[0] = E::ScalarField::zero();
        let sk_li_minus0 = KZG10::commit_g1(params, &f)
            .expect("commitment failed")
            .into();

        PublicKey {
            id,
            bls_pk: E::G1::generator() * self.sk,
            sk_li,
            sk_li_minus0,
            sk_li_by_z,
            sk_li_by_tau,
        }
    }

    pub fn partial_decryption(&self, ct: &Ciphertext<E>) -> E::G2 {
        ct.gamma_g2 * self.sk // kind of a bls signature on gamma_g2
    }
}

// gamma_g2 is the tag
pub fn partial_decryption<E: Pairing>(gamma_g2: E::G2, sk: E::ScalarField) -> E::G2 {
    gamma_g2 * sk // kind of a bls signature on gamma_g2
}

impl<E: Pairing> AggregateKey<E> {
    pub fn new(pk: Vec<PublicKey<E>>, params: &UniversalParams<E>) -> Self {
        let n = pk.len();
        let h_minus1 = params.powers_of_h[0] * (-E::ScalarField::one());
        let z_g2 = params.powers_of_h[n] + h_minus1;

        // gather sk_li from all public keys
        let mut ask = E::G1::zero();
        for pki in pk.iter() {
            ask += pki.sk_li;
        }

        let mut agg_sk_li_by_z = vec![];
        for i in 0..n {
            let mut agg_sk_li_by_zi = E::G1::zero();
            for pkj in pk.iter() {
                agg_sk_li_by_zi += pkj.sk_li_by_z[i];
            }
            agg_sk_li_by_z.push(agg_sk_li_by_zi);
        }

        AggregateKey {
            pk,
            agg_sk_li_by_z,
            ask,
            z_g2,
            h_minus1,
            e_gh: E::pairing(params.powers_of_g[0], params.powers_of_h[0]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type E = ark_bls12_381::Bls12_381;

    #[test]
    fn test_setup() {
        let mut rng = ark_std::test_rng();
        let n = 4;
        let params = KZG10::<E>::setup(n, &mut rng).unwrap();

        let mut sk: Vec<SecretKey<E>> = Vec::new();
        let mut pk: Vec<PublicKey<E>> = Vec::new();

        for i in 0..n {
            sk.push(SecretKey::<E>::new(&mut rng));
            pk.push(sk[i].get_pk(0, &params, n))
        }

        let _ak = AggregateKey::<E>::new(pk, &params);
    }
}
