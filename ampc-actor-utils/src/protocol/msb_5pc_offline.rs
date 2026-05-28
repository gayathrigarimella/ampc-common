use ampc_secret_sharing::{
    shares::{
        bit::Bit,
        primefield::PrimeElement,
        share::{AdditiveShare, AdditiveSharePrime},
    },
    IntRing2k,
};
use eyre::{bail, Error, Result};
use num_traits::PrimInt;
use rand::Rng;
use rand_distr::{Distribution, Standard};

use crate::protocol::test_utils::{
    create_single_sharing_additive, create_single_sharing_additive_prime,
};

#[derive(Clone, Debug)]
pub struct CorrelatedBoolPrimeShare<P: PrimInt> {
    // Boolean mask for parties 1/2.
    // Useful in the bitlt() protocol, for masking shares before sending to dealer: boolean -> primefield conversion step
    pub bit_mask: Bit,
    // Additive prime-field share of the XOR of the above two masks.
    // useful for the bitlt() protocol, for unmasking after dealer: boolean -> primefield conversion step
    pub prime_share: AdditiveSharePrime<PrimeElement<P>>,
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

    // Correlated boolean values shared both over F_2 and F_p.
    // vector of struct; each struct holds a boolean share and a prime share
    // None if not party 1/2
    pub correlated_bool_prime: Option<Vec<CorrelatedBoolPrimeShare<P>>>,
}

// helper function: given a tuple of 4 additive shares
// each party can pick its own share based on its role index
fn get_additive_share_for_role<T: IntRing2k>(
    shares: &[AdditiveShare<T>],
    role_idx: usize,
) -> Result<AdditiveShare<T>, Error> {
    match role_idx {
        0 => Ok(shares[0]),
        1 => Ok(shares[1]),
        2 => Ok(shares[2]),
        3 => Ok(shares[3]),
        _ => bail!("Cannot pick additive share for role {}", role_idx),
    }
}

// helper function: given a tuple of 4 additive prime shares
// each party can pick its own share based on its role index
fn get_additive_prime_share_for_role<P: PrimInt>(
    shares: &[AdditiveSharePrime<PrimeElement<P>>],
    role_idx: usize,
) -> Result<AdditiveSharePrime<PrimeElement<P>>, Error> {
    match role_idx {
        0 => Ok(shares[0]),
        1 => Ok(shares[1]),
        2 => Ok(shares[2]),
        3 => Ok(shares[3]),
        _ => bail!("Cannot pick additive prime share for role {}", role_idx),
    }
}

pub fn generate_offline_random_shares_additive<T: IntRing2k, P: PrimInt>(
    rng: &mut impl Rng,
    prime_modulus: P,
) -> Result<Vec<Option<OfflineRandomSharesAdditive4<T, P>>>, Error>
where
    T: IntRing2k,
    P: PrimInt,
    Standard: Distribution<T>,
{
    // sample a ring element over the ring, by sampling bits
    let r_bits: Vec<bool> = (0..T::K).map(|_| rng.gen_bool(0.5)).collect();

    // secret share the bits as boolean xor shares
    // <(first_share, second_share, third_share, fourth_share), ....., >
    let r_bit_shares = r_bits
        .iter()
        .map(|overall_bit| create_single_sharing_additive::<_, Bit>(rng, Bit::new(*overall_bit), 4))
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
    let r_value_shares = create_single_sharing_additive(rng, r_value, 4);

    // sample a boolean value and secret share over the larger ring
    let b_bit = rng.gen_bool(0.5);
    let b_bit_shares = create_single_sharing_additive(rng, T::from(b_bit), 4);

    // vector of correlated shares Vec<((boolean shareso of bit), (prime shares of bit)), ...>
    let correlated_bool_prime = (0..T::K)
        .map(|_| {
            let bit_value_p1 = rng.gen_bool(0.5);
            let bit_value_p2 = rng.gen_bool(0.5);
            let prime_value = if bit_value_p1 ^ bit_value_p2 {
                P::one()
            } else {
                P::zero()
            };
            (
                // secret share the boolean value
                (bit_value_p1, bit_value_p2),
                // secret share the same underlying boolean value as a prime field element, 4 additive shares
                create_single_sharing_additive_prime(rng, prime_value, prime_modulus, 2),
            )
        })
        .collect::<Vec<_>>();

    let (correlated_p0, correlated_p1): (Vec<_>, Vec<_>) = correlated_bool_prime
        .into_iter()
        .map(|((p1_share, p2_share), prime_shares)| {
            (
                CorrelatedBoolPrimeShare {
                    bit_mask: Bit::new(p1_share),
                    prime_share: get_additive_prime_share_for_role(&prime_shares, 0).unwrap(),
                },
                CorrelatedBoolPrimeShare {
                    bit_mask: Bit::new(p2_share),
                    prime_share: get_additive_prime_share_for_role(&prime_shares, 1).unwrap(),
                },
            )
        })
        .unzip();

    // we need to assign the struct for each of the 4 parties, Parties 0, 1, 2, 3
    // note that dealer (party with Role 4) does not receive any randomness
    let mut shares: Vec<Option<OfflineRandomSharesAdditive4<T, P>>> = Vec::with_capacity(5);
    (0..4).for_each(|party_idx| {
        let correlated_shares: Option<Vec<CorrelatedBoolPrimeShare<P>>> = if party_idx == 0 {
            Some(correlated_p0.clone())
        } else if party_idx == 1 {
            Some(correlated_p1.clone())
        } else {
            None
        };
        let offline = OfflineRandomSharesAdditive4 {
            r: get_additive_share_for_role(&r_value_shares, party_idx).unwrap(),

            r_bits: r_bit_shares
                .iter()
                .map(|shares| get_additive_share_for_role(shares, party_idx).unwrap())
                .collect(),

            b_bit_ring: get_additive_share_for_role(&b_bit_shares, party_idx).unwrap(),

            correlated_bool_prime: correlated_shares,
        };
        shares.push(Some(offline));
    });

    // For the dealer share
    shares.push(None);

    Ok(shares)
}

#[cfg(test)]
mod tests {
    use crate::protocol::msb_5pc_offline::generate_offline_random_shares_additive;
    use aes_prng::AesRng;
    use ampc_secret_sharing::IntRing2k;
    use eyre::{Error, Result};
    use num_traits::One;
    use rand::SeedableRng;

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

        let offline_shares =
            generate_offline_random_shares_additive::<u16, u16>(&mut rng0, prime_modulus)?;

        // Parties 0, 1, 2, 3 generate their shares using the same bulk randomness generation function
        let p0 = offline_shares[0].as_ref().unwrap();

        let p1 = offline_shares[1].as_ref().unwrap();

        let p2 = offline_shares[2].as_ref().unwrap();

        let p3 = offline_shares[3].as_ref().unwrap();

        // Pick Party 0: check the number of shares in the vectors, should match the log (ring size)
        assert_eq!(p0.r_bits.len(), u16::K);
        assert_eq!(p0.correlated_bool_prime.as_ref().unwrap().len(), u16::K);

        // open the ring element r
        let opened_r = (p0.r + p1.r + p2.r + p3.r).get_value();

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
            let opened_bool = p0.correlated_bool_prime.as_ref().unwrap()[idx]
                .bit_mask
                .convert()
                ^ p1.correlated_bool_prime.as_ref().unwrap()[idx]
                    .bit_mask
                    .convert();

            let opened_prime = p0.correlated_bool_prime.as_ref().unwrap()[idx]
                .prime_share
                .get_value()
                + p1.correlated_bool_prime.as_ref().unwrap()[idx]
                    .prime_share
                    .get_value();

            assert_eq!(
                opened_prime.get_value(),
                if opened_bool { 1u16 } else { 0u16 }
            );

            // println!("Opened correlated prime {}: bool = {}, prime = {}", idx, opened_bool, opened_prime.get_value());
        }

        let p4 = offline_shares[4].as_ref();

        assert!(p4.is_none());

        Ok(())
    }
}
