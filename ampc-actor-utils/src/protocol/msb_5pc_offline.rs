use ampc_secret_sharing::{
    RingElement, IntRing2k, shares::{
        bit::Bit,
        primefield::PrimeElement,
        share::{AdditiveShare, AdditiveSharePrime},
    }
};
use num_traits::PrimInt;
use rand::Rng;
use eyre::{bail, Error, Result};
use rand_distr::{Standard, Distribution};

use crate::protocol::test_utils::{create_single_sharing_additive_prime_4party, 
    create_single_sharing_additive_4party, 
};


#[derive(Clone, Debug)]
pub struct CorrelatedBoolPrimeShare<P: PrimInt> {
    // Boolean additive share over F_2 over the 4 parties.
    // Useful in the bitlt() protocol, for masking shares before sending to dealer: boolean -> primefield conversion step 
    pub bit_share: AdditiveShare<Bit>,

    // Additive prime-field share of the same underlying boolean value
    // useful for the bitlt() protocol, for unmasking after dealer: boolean -> primefield conversion step
    pub prime_share: AdditiveSharePrime<PrimeElement<P>>,
}

#[derive(Clone, Debug)]
pub struct PrimeBeaverTripleShare<P: PrimInt> {
    // c = a * b in the primefield
    // this is required in the bitlt() protocol, unmasking step 
    // masking bit * primeshare 
    // above step will rely on beaver triples 
    pub a: AdditiveSharePrime<PrimeElement<P>>,
    pub b: AdditiveSharePrime<PrimeElement<P>>,
    pub c: AdditiveSharePrime<PrimeElement<P>>, // c = a * b in F_p
}

#[derive(Clone, Debug)]
pub struct OfflineRandomSharesAdditive4<T: IntRing2k, P: PrimInt> {
    // Additive SS of random ring element r shared over Z_{2^k}.
    pub r: AdditiveShare<T>,

    // Boolean decomposition of r, e.g. r_{k-1}, ..., r_0.
    // Each bit is shared as an additive share over F_2, i.e. boolean shares.
    pub r_bits: Vec<AdditiveShare<Bit>>,

    // Random boolean value shared over a larger ring
    pub b_bit_ring: AdditiveShare<T>,

    // Vector of struct that holds a single instance of beaver triples
    // each struct holds the shares of (a, b, c) as seen by a single party
    pub prime_beaver_triples: Vec<PrimeBeaverTripleShare<P>>,

    // Correlated boolean values shared both over F_2 and F_p.
    // vector of struct; each struct holds a boolean share and a prime share
    // both shares correspond to the same underlying boolean value, just secret shared over different fields
    pub correlated_bool_prime: Vec<CorrelatedBoolPrimeShare<P>>,

    // Public prime-field values:
    // open(correlated_bool_prime[idx] - PrimeBeaverTripleShare.b[idx])
    // optional: do this later
    //pub bool_minus_bv_b: Vec<PrimeElement<P>>,
}

// helper function: given a tuple of 4 additive shares
// each party can pick its own share based on its role index 
fn additive_share_for_role<T: IntRing2k>(
    shares: (
        AdditiveShare<T>,
        AdditiveShare<T>,
        AdditiveShare<T>,
        AdditiveShare<T>,
    ),
    role_idx: usize,
) -> Result<AdditiveShare<T>, Error> {
    match role_idx {
        0 => Ok(shares.0),
        1 => Ok(shares.1),
        2 => Ok(shares.2),
        3 => Ok(shares.3),
        _ => bail!("Cannot pick additive share for role {}", role_idx),
    }
}


// helper function: given a tuple of 4 additive prime shares
// each party can pick its own share based on its role index 
fn additive_prime_share_for_role<P: PrimInt>(
    shares: (
        AdditiveSharePrime<PrimeElement<P>>,
        AdditiveSharePrime<PrimeElement<P>>,
        AdditiveSharePrime<PrimeElement<P>>,
        AdditiveSharePrime<PrimeElement<P>>,
    ),
    role_idx: usize,
) -> Result<AdditiveSharePrime<PrimeElement<P>>, Error> {
    match role_idx {
        0 => Ok(shares.0),
        1 => Ok(shares.1),
        2 => Ok(shares.2),
        3 => Ok(shares.3),
        _ => bail!("Cannot pick additive prime share for role {}", role_idx),
    }
}

pub fn generate_offline_random_shares_additive<T: IntRing2k, P: PrimInt>(
    role_idx: usize, // using usize here for simplicity, Role is tied to session (overkill)
    rng: &mut impl Rng,
    prime_modulus: P
) -> Result<Option<OfflineRandomSharesAdditive4<T, P>>, Error>
    where 
        T: IntRing2k,
        P: PrimInt,
        Standard: Distribution<T>
    {
        // sample a ring element over the ring, by sampling bits 
        let r_bits: Vec<bool> = (0..T::K).map(|_| rng.gen_bool(0.5)).collect();

        // secret share the bits as boolean xor shares 
        // <(first_share, second_share, third_share, fourth_share), ....., > 
            let r_bit_shares = r_bits
            .iter().map(|overall_bit| {
            let first_share = rng.gen_bool(0.5);
            let second_share = rng.gen_bool(0.5);
            let third_share = rng.gen_bool(0.5);
            let first_second_third_xor = first_share ^ second_share ^ third_share; 
            let fourth_share = !(*overall_bit == first_second_third_xor);

            //(AdditiveShare::new(RingElement(Bit::new(first_share))), AdditiveShare::new(RingElement(Bit::new(second_share))), AdditiveShare::new(RingElement(Bit::new(third_share))), AdditiveShare::new(RingElement(Bit::new(fourth_share))))
            (first_share, second_share, third_share, fourth_share)
        })
        .collect::<Vec<_>>();

        // aggregate bits to compute the ring element r 
        let r_value = r_bits
            .iter()
            .rev()
            .enumerate()
            .fold(T::zero(), |acc, (i, bit)| {
                let multiplier = if i == 0 {
                    T::one()
                } else {
                (T::one() + T::one()).wrapping_shl((i - 1) as u32)
                };
                acc + (T::from(*bit) * multiplier)
            });

        // secret share the ring element using additive sharing -> 4 shares 
        let r_value_shares = create_single_sharing_additive_4party(rng, r_value);

        // sample a boolean value and secret share over the larger ring
        let b_bit = rng.gen_bool(0.5);
        let b_bit_shares = create_single_sharing_additive_4party(rng, T::from(b_bit));

        // vector of beaver triples <((shares of a), (shares of b), (shares of c = a * b))...>
        let prime_beaver_triples = (0..T::K)
            .map(|_| {
                let a = PrimeElement::<P>::rand(rng, prime_modulus);
                let b: PrimeElement<P> = PrimeElement::<P>::rand(rng, prime_modulus);
                let c = a * b; // this is the multiplication in the prime field

                (
                create_single_sharing_additive_prime_4party(
                    rng,
                    a.get_value(),
                    prime_modulus,
                ),
                create_single_sharing_additive_prime_4party(
                    rng,
                    b.get_value(),
                    prime_modulus,
                ),
                create_single_sharing_additive_prime_4party(
                    rng,
                    c.get_value(),
                    prime_modulus,
                ),
            )

            })
            .collect::<Vec<_>>();    
 
        // vector of correlated shares Vec<((boolean shareso of bit), (prime shares of bit)), ...>
        let correlated_bool_prime = (0..T::K)
                .map(|_| {
                let bit_value = rng.gen_bool(0.5);
                let prime_value = if bit_value { P::one() } else { P::zero() };
                
                // determine the boolean shares for the bit value 
                let first_share = rng.gen_bool(0.5);
                let second_share = rng.gen_bool(0.5);
                let third_share = rng.gen_bool(0.5);
                let first_second_third_xor = first_share ^ second_share ^ third_share; 
                let fourth_share = !(bit_value == first_second_third_xor);
                (
                    // secret share the boolean value
                    (first_share, second_share, third_share, fourth_share),
                    // secret share the same underlying boolean value as a prime field element, 4 additive shares 
                    create_single_sharing_additive_prime_4party(
                        rng,
                        prime_value,
                        prime_modulus,
                    ),
                )
        })
        .collect::<Vec<_>>();

        // we need to assign the struct for each of the 4 parties, Parties 0, 1, 2, 3
        // note that dealer (party with Role 4) does not receive any randomness 

        if role_idx == 4 {
            return Ok(None);
        }

        if role_idx > 4 {
            bail!("Cannot deal with role index outside [0, 4]");
        }

        let offline = OfflineRandomSharesAdditive4 {
            r: additive_share_for_role(r_value_shares, role_idx)?,

            r_bits: r_bit_shares
                .iter()
                .map(|(s0, s1, s2, s3)| {
                let my_bit_share = match role_idx {
                    0 => s0,
                    1 => s1,
                    2 => s2,
                    3 => s3,
                    _ => unreachable!(),
                };
                Ok(AdditiveShare::new(RingElement(Bit::new(*my_bit_share))))

                })
                .collect::<Result<Vec<_>, Error>>()?,

            b_bit_ring: additive_share_for_role(b_bit_shares, role_idx)?,

            prime_beaver_triples: prime_beaver_triples
                .into_iter()
                .map(|(a_shares, b_shares, c_shares)| {
                    Ok(PrimeBeaverTripleShare {
                        a: additive_prime_share_for_role(a_shares, role_idx)?,
                        b: additive_prime_share_for_role(b_shares, role_idx)?,
                        c: additive_prime_share_for_role(c_shares, role_idx)?,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?,

            correlated_bool_prime: correlated_bool_prime
                .into_iter()
                .map(|((s0, s1, s2, s3), prime_shares)| {
                    let my_bit_share = match role_idx {
                        0 => s0,
                        1 => s1,
                        2 => s2,
                        3 => s3,
                        _ => unreachable!(),
                    };

                    Ok(CorrelatedBoolPrimeShare {
                        bit_share: AdditiveShare::new(RingElement(Bit::new(my_bit_share))),
                        prime_share: additive_prime_share_for_role(prime_shares, role_idx)?,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()?,
            };

        Ok(Some(offline))

    }




    mod tests {
        use aes_prng::AesRng;
        use eyre::{bail, Error, Result};
        use rand::SeedableRng;
        use num_traits::{PrimInt, Zero, One};
        use ampc_secret_sharing::{
            RingElement, IntRing2k, Role, shares::{
            bit::Bit,
            primefield::PrimeElement,
            share::{self, AdditiveShare, AdditiveSharePrime},
            }
        };
        use crate::protocol::msb_5pc_offline::generate_offline_random_shares_additive;


    #[test]
    fn test_generate_offline_random_shares_additive() -> Result<(), Error> {
        // pick the prime modulus, based on ring size
        let prime_modulus = 29u16;
        let base_rng = AesRng::from_entropy();

        // this is awkward since the function generates all the randomnesss; 
        // and each party samples their own part of randomness from bulk
        // we need to clone and make sure the same "state" is used for each of the instances
        // now, each party generates same bulk and then picks their relevant shares ... 
        // g3:: is this reasonable? should we change the way we write this?
        let mut rng0 = base_rng.clone();
        let mut rng1 = base_rng.clone();
        let mut rng2 = base_rng.clone();
        let mut rng3 = base_rng.clone();


        // Parties 0, 1, 2, 3 generate their shares using the same bulk randomness generation function
        let p0 = generate_offline_random_shares_additive::<u16, u16>(
        0usize,
            &mut rng0,
            prime_modulus,
        )?
        .unwrap();

        let p1 = generate_offline_random_shares_additive::<u16, u16>(
            1usize,
            &mut rng1,
            prime_modulus,
        )?
        .unwrap();

        let p2 = generate_offline_random_shares_additive::<u16, u16>(
            2usize,
            &mut rng2,
            prime_modulus,
        )?
        .unwrap();

        let p3 = generate_offline_random_shares_additive::<u16, u16>(
            3usize,
            &mut rng3,
            prime_modulus,
        )?
        .unwrap();

        // Pick Party 0: check the number of shares in the vectors, should match the log (ring size)
        assert_eq!(p0.r_bits.len(), u16::K);
        assert_eq!(p0.prime_beaver_triples.len(), u16::K);
        assert_eq!(p0.correlated_bool_prime.len(), u16::K);

        // open the ring element r
         let opened_r = 
            (p0.r
            + p1.r
            + p2.r
            + p3.r).get_value();

        // open of shares of each bit of the ring element
        let opened_r_bits = (0..u16::K)
            .map(|idx| {
                    // additiveshare -> RingElement(Bit) -> Bit -> bool
                    let opened = p0.r_bits[idx].get_value().convert().convert()
                    ^ p1.r_bits[idx].get_value().convert().convert()
                    ^ p2.r_bits[idx].get_value().convert().convert()
                    ^ p3.r_bits[idx].get_value().convert().convert();

                    opened
                    //Ok(p0.r_bits[idx] ^ p1.r_bits[idx] ^ p2.r_bits[idx] ^ p3.r_bits[idx])
            })
            .collect::<Vec<_>>();

        let r_bits_value = opened_r_bits
            .iter()
            .rev()
            .enumerate()
            .fold(0u16, |acc, (i, bit)| {
                let multiplier = if i == 0 {
                    1u16
                } else {
                (u16::one() + u16::one()).wrapping_shl((i - 1) as u32)
                };
                acc + (u16::from(*bit) * multiplier)
            });


        assert_eq!(opened_r.convert(), r_bits_value);
        // println!("{:?}", opened_r_bits);
        // println!("Opened r: {}", opened_r.convert());

        let opened_b_bit_ring = p0.b_bit_ring.get_value()
            + p1.b_bit_ring.get_value()
            + p2.b_bit_ring.get_value()         
            + p3.b_bit_ring.get_value();
           
        assert!(opened_b_bit_ring.convert() == 0 || opened_b_bit_ring.convert() == 1);

        for idx in 0..u16::K {
            let a = 
                (p0.prime_beaver_triples[idx].a
                + p1.prime_beaver_triples[idx].a
                + p2.prime_beaver_triples[idx].a
                + p3.prime_beaver_triples[idx].a).get_value();
                
            

            let b = 
                (p0.prime_beaver_triples[idx].b
                + p1.prime_beaver_triples[idx].b
                + p2.prime_beaver_triples[idx].b
                + p3.prime_beaver_triples[idx].b).get_value();

            let c = 
                (p0.prime_beaver_triples[idx].c
                + p1.prime_beaver_triples[idx].c
                + p2.prime_beaver_triples[idx].c
                + p3.prime_beaver_triples[idx].c).get_value();

            assert_eq!(a * b, c);
            // println!("Opened Beaver triple {}: a = {}, b = {}, c = {}", idx, a.get_value(), b.get_value(), c.get_value());

            let opened_bool = 
                p0.correlated_bool_prime[idx].bit_share.get_value().convert().convert()
                ^ p1.correlated_bool_prime[idx].bit_share.get_value().convert().convert()
                ^ p2.correlated_bool_prime[idx].bit_share.get_value().convert().convert()
                ^ p3.correlated_bool_prime[idx].bit_share.get_value().convert().convert();

            let opened_prime = 
                (p0.correlated_bool_prime[idx].prime_share
                + p1.correlated_bool_prime[idx].prime_share
                + p2.correlated_bool_prime[idx].prime_share
                + p3.correlated_bool_prime[idx].prime_share).get_value();

            assert_eq!(opened_prime.get_value(),
                if opened_bool { 1u16 } else { 0u16 }
            );

            // println!("Opened correlated prime {}: bool = {}, prime = {}", idx, opened_bool, opened_prime.get_value());

        }

        let mut rng4 = base_rng.clone();
        let p4 = generate_offline_random_shares_additive::<u16, u16>(
            4usize,
            &mut rng4,
            prime_modulus,
        )?;

        assert!(p4.is_none());

        Ok(())
    }

}

