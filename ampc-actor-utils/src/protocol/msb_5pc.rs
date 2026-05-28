use aes_prng::AesRng;
use ampc_secret_sharing::{
    shares::{
        bit::Bit,
        primefield::PrimeElement,
        share::{AdditiveShare, AdditiveSharePrime},
    },
    IntRing2k, RingElement,
};
use eyre::{Error, Result};
use num_traits::{One, PrimInt, Zero};
use rand::{Rng, SeedableRng};
use std::ops::{Neg, SubAssign};

use crate::protocol::{
    msb_5pc_helpers::{
        bin_to_primefield16_4party, open_additive_share_4party, primefield16_to_bin_one_hot,
        send_binary_shares_to_dealer, send_prime16_shares_to_dealer,
        setup_shared_seed_dealer_model_4party,
    },
    msb_5pc_offline::OfflineRandomSharesAdditive4,
};
use crate::{
    execution::session::{Session, SessionHandles},
    network::value::NetworkInt,
    protocol::{prf::PrfRng, Prf, PrfSeed},
};

pub async fn extract_msb_rand_additive<T: IntRing2k + NetworkInt, K: PrimInt>(
    session: &mut Session,
    x: AdditiveShare<T>,
    offline: &OfflineRandomSharesAdditive4<T, K>,
    prime_modulus: K,
) -> Result<AdditiveShare<T>, Error> {
    let mut rng = AesRng::from_random_seed();
    // TODO
    // let prime_modulus_lower_bound = 2 * T::K + 1;
    // get_next_prime(prime_modulus_lower_bound)

    // step 1: [r']_k = [r]_k - [r_bit]_1 ^ 2^{k - 1}
    // convert RingElement<Bit> -> Bit -> Bool -> (via from) T
    let v_t: T = T::from(offline.r_bits[0].get_value().convert().convert());
    // safely left-shift by T::K - 1 == bit width - 1 using wrapping_shl
    let scaled_msb_self = RingElement(v_t.wrapping_shl((T::K - 1) as u32));

    let r_prime_self: RingElement<T> = offline.r.get_value() - scaled_msb_self;
    let r_prime_share = AdditiveShare::new(r_prime_self);

    // step 2: c' = (x + r) mod 2^{k - 1}

    // mask input 'x:AdditiveShare<T>' with pre-generated random ring element 'r:AdditiveShare<T>'
    let c_share: AdditiveShare<T> = x + offline.r;
    let c: T = open_additive_share_4party::<T>(session, &[c_share]).await?[0];
    let mask: T = T::one()
        .wrapping_shl((T::K - 1) as u32)
        .wrapping_sub(&T::one());
    let c_prime: T = c & mask;

    // step 3: compute bitLT using c_prime and replicated bits r_bits[7], ..., r_bits[1]
    // sample a prf
    let prf_seed = PrfSeed::from([rng.gen::<u8>(); 16]);
    // TODO: compute bitlt using additive shares and prf seed -> output is additive share of bitLT
    let bit_lt_share_add2 = bitlt(
        session,
        offline.r_bits.clone().into_iter().skip(1).collect(),
        c_prime,
        offline.r_bits.len() - 1,
        prf_seed,
        prime_modulus,
    )
    .await?;

    // step 4: [a']_k = 2^{k-1} [u]_1 + c' - [r']_k, [d]_k = [a]_k - [a']_k

    // 4a. computing scaled 2^{k - 1} * [u]_1
    // convert RingElement<Bit> -> Bit -> Bool -> (via from) T
    let v_t: T = T::from(bit_lt_share_add2.get_value().convert().convert());
    // safely left-shift by T::K - 1 == bit width - 1 using wrapping_shl
    let scaled_bit_lt_self = RingElement(v_t.wrapping_shl((T::K - 1) as u32));

    let scaled_bit_lt = AdditiveShare::new(scaled_bit_lt_self);
    let mut x_prime = scaled_bit_lt;
    x_prime.add_assign_const_role(c_prime, session.own_role());
    x_prime.sub_assign(r_prime_share);

    let d_share = x - x_prime;

    // step 5: computing MSB using b_bit and d_share
    // 5a. scale b_bit by 2^{k - 1}
    let two_pow_k_minus_1: T = T::one().wrapping_shl((T::K - 1) as u32);
    let mut b_msb_share = offline.b_bit_ring;
    b_msb_share = b_msb_share * two_pow_k_minus_1;
    let e_share = d_share + b_msb_share;
    // e_share: ReplicatedShare<T>
    let e_open: T = open_additive_share_4party::<T>(session, &[e_share]).await?[0];
    // MSB as bool
    let e_msb_bool: bool = ((e_open >> (T::K - 1)) & T::one()) == T::one();

    let msb = if e_msb_bool {
        let mut neg_b_bit = -offline.b_bit_ring;
        neg_b_bit.add_assign_const_role(T::one(), session.own_role());
        neg_b_bit
    } else {
        offline.b_bit_ring
    };
    Ok(msb)
}

pub async fn bitlt<T: IntRing2k + NetworkInt, K: PrimInt>(
    session: &mut Session,
    shares: Vec<AdditiveShare<Bit>>,
    public_value: T,
    public_value_bits: usize,
    prf_seed: PrfSeed,
    prime_modulus: K,
) -> Result<AdditiveShare<Bit>> {
    // Scale the public value to avoid leakage to dealer if the private and public values are equal.
    // I.e., scaled = 2 * public_value + 1
    let scaled_public_value_bits: Vec<bool> = (0..public_value_bits)
        .rev()
        .map(|i| ((public_value >> i) & T::one()) == T::one())
        .chain(std::iter::once(true))
        .collect();

    let mut scaled_shares = shares.clone();
    let mut rng_rand_bits = if session.own_role().index() == 0 || session.own_role().index() == 1 {
        // Set up shared PRF between parties 1 and 2
        let shared_seed =
            setup_shared_seed_dealer_model_4party(&mut session.network_session, prf_seed).await?;
        let mut rng = PrfRng::from_seed(Prf::expand_seed(shared_seed));
        // Scale private value to avoid leakage to dealer if the private and public values are equal
        // I.e., scaled = 2 * shares
        scaled_shares.push(AdditiveShare::new(RingElement(Bit::zero())));
        assert_eq!(scaled_public_value_bits.len(), scaled_shares.len());

        // XOR shares by the scaled public value for comparison
        scaled_shares
            .iter_mut()
            .zip(scaled_public_value_bits.iter())
            .for_each(|(share, public_val)| {
                let public_val_bit = Bit::from(*public_val);
                share.add_assign_const_role(public_val_bit, session.own_role());
            });

        // Mask the share by adding random value generated by PRF
        let rand_bits: Vec<Bit> = scaled_shares
            .iter_mut()
            .map(|share| {
                let rand_bit = rng.gen::<Bit>();
                share.add_assign_const_role(rand_bit, session.own_role());
                rand_bit
            })
            .collect();

        Some((rng, rand_bits))
    } else {
        None
    };

    // Communication round 1: Send shares to dealer to convert to prime field
    let dealer_shares = send_binary_shares_to_dealer(session, &scaled_shares).await?;
    // Communication round 2: Receive prime field shares from dealer
    let mut prime_shares_received =
        bin_to_primefield16_4party(session, dealer_shares, prime_modulus.to_u16().unwrap()).await?;

    let (rand_shift, shifted_shares) = if let Some((rng, rand_bits)) = &mut rng_rand_bits {
        // Unmask prime shares
        rand_bits
            .iter()
            .zip(prime_shares_received.iter_mut())
            .for_each(|(bit, share)| {
                if bit.convert() {
                    *share = share.neg();
                    share.add_assign_const_role(
                        PrimeElement::<u16>::one(prime_modulus.to_u16().unwrap()),
                        session.own_role(),
                    );
                }
            });
        // Prefix sum
        let mut prefix_sum = Vec::with_capacity(prime_shares_received.len());
        let mut running_sum = AdditiveSharePrime::zero(prime_modulus.to_u16().unwrap());
        prime_shares_received.iter().for_each(|share| {
            running_sum += share;
            prefix_sum.push(running_sum);
        });

        // Pairwise sum
        let mut pairwise_sum = Vec::with_capacity(prime_shares_received.len());
        pairwise_sum.push(prefix_sum[0]);
        (1..prefix_sum.len()).for_each(|i| {
            pairwise_sum.push(prefix_sum[i - 1] + prefix_sum[i]);
        });

        // Subtract 1
        pairwise_sum.iter_mut().for_each(|share| {
            share.add_assign_const_role(
                PrimeElement::<u16>::one(prime_modulus.to_u16().unwrap()).neg(),
                session.own_role(),
            );
        });

        // Scale prime shares
        pairwise_sum.iter_mut().for_each(|share| {
            let scalar =
                PrimeElement::<u16>::rand_multiplicative(rng, prime_modulus.to_u16().unwrap());
            *share *= scalar;
        });

        // Shift shares
        let rand_shift = rng.gen_range(0..shares.len());
        let mut shifted_shares = Vec::with_capacity(shares.len());
        (0..pairwise_sum.len()).for_each(|i| {
            shifted_shares.push(pairwise_sum[(i + rand_shift) % pairwise_sum.len()]);
        });
        (Some(rand_shift), shifted_shares)
    } else {
        (None, vec![])
    };

    // Communication round 3: Send prime shares to dealer to convert to binary
    let dealer_values = send_prime16_shares_to_dealer(session, &shifted_shares).await?;
    // Communication round 4: Receive binary shares of one hot vector from dealer
    let one_hot_shifted_shares = primefield16_to_bin_one_hot(session, dealer_values).await?;

    if let Some(rand_shift) = rand_shift {
        let mut one_hot_shares = Vec::with_capacity(one_hot_shifted_shares.len());
        // Un-shift the one-hot vector shares
        (0..one_hot_shifted_shares.len()).for_each(|i| {
            if rand_shift <= i {
                one_hot_shares.push(one_hot_shifted_shares[i - rand_shift]);
            } else {
                one_hot_shares
                    .push(one_hot_shifted_shares[i + (one_hot_shifted_shares.len() - rand_shift)]);
            }
        });
        // Get the dot product against the public value
        let mut dot_product_share = AdditiveShare::<Bit>::zero();
        one_hot_shares
            .iter()
            .zip(scaled_public_value_bits.iter())
            .for_each(|(share, bit)| {
                dot_product_share += share * Bit::from(*bit);
            });

        // Add 1 because this is the opposite of what we want
        dot_product_share.add_assign_const_role(Bit::one(), session.own_role());
        Ok(dot_product_share)
    }
    // Return dummy zero share if dealer
    else {
        Ok(AdditiveShare::<Bit>::zero())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::msb_preprocessing::{
        add2_to_rep_binary, bitlt, extract_msb_rand_additive, offline_shares_for_role_additive2,
        open_additive_share, open_additive_share_bit, open_additive_share_u8, rep_to_add2,
    };
    use crate::protocol::test_utils::{
        create_array_sharing_additive, create_single_sharing_additive,
        create_single_sharing_replicated,
    };
    use crate::protocol::PrfSeed;
    use crate::{
        execution::{local::LocalRuntime, session::SessionHandles},
        protocol::binary::open_bin,
    };
    use aes_prng::AesRng;
    use ampc_secret_sharing::shares::bit::Bit;
    use ampc_secret_sharing::shares::share::AdditiveShare;
    use ampc_secret_sharing::shares::vecshare::VecShareAdditive;
    use ampc_secret_sharing::RingElement;
    use eyre::{bail, Error, Result};
    use rand::{Rng, SeedableRng};
    use rand_distr::{Distribution, Standard};
    use tokio::task::JoinSet;

    async fn test_extract_msb_rand_u32_additive() -> Result<()> {
        let modulus = 67;
        let mut rng = AesRng::from_random_seed();
        let offline_rng = AesRng::from_random_seed();
        let len = 100usize;

        // Random cleartext values + expected MSB bits
        let ints: Vec<u32> = (0..len).map(|_| rng.gen::<u32>()).collect();
        //let ints: Vec<u8> = vec![241u8, 128u8, 34u8, 255u8, 11u8];

        let expected: Vec<u32> = ints.iter().map(|x| (*x >> 31) & 1).collect();

        println!(
            "Cleartext values: {:?} Expected Values: {:?}",
            ints, expected
        );
        // Secret-share inputs across 3 parties
        let shares = create_array_sharing_additive(&mut rng, &ints);
        let sessions = LocalRuntime::mock_sessions_with_channel().await?;
        let mut jobs = JoinSet::new();

        for (i, session) in sessions.into_iter().enumerate() {
            let session = session.clone();
            let shares_i = VecShareAdditive::new_vec(shares.of_party(i).clone());
            let mut offline_rng = offline_rng.clone();

            jobs.spawn(async move {
                let mut session = session.lock().await;

                // pick up the pre-generated randomness
                let offline =
                    offline_shares_for_role_additive2(&session.own_role(), &mut offline_rng)?;

                // Run extract_msb_rand for each shared input
                let mut out = Vec::with_capacity(shares_i.len());
                for x in shares_i.shares().iter().cloned() {
                    out.push(
                        extract_msb_rand_additive::<u32, u16>(&mut session, x, &offline, modulus)
                            .await?,
                    );
                }

                // Open result bits
                open_additive_share::<u32, u16>(&mut session, &out).await
            });
        }

        let opened = jobs
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 3);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[0], expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_extract_msb_rand_additive() -> Result<()> {
        test_extract_msb_rand_u32_additive().await
    }

    async fn test_rep_to_add2_u8() -> Result<()>
    where
        Standard: Distribution<u8>,
    {
        let mut rng = AesRng::from_entropy();
        let sessions = LocalRuntime::mock_sessions_with_channel().await?;
        let mut jobs = JoinSet::new();
        let value = rng.gen::<u8>();
        let expected = RingElement(value);
        let shares = create_single_sharing_replicated::<AesRng, u8>(&mut rng, value);

        for session in sessions.into_iter() {
            let session = session.clone();

            jobs.spawn(async move {
                let mut session = session.lock().await;
                let shares_i = match session.own_role().index() {
                    0 => shares.0,
                    1 => shares.1,
                    2 => shares.2,
                    _ => {
                        bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]")
                    }
                };

                let out = rep_to_add2::<u8>(&mut session, shares_i).await?;

                // Open result bits
                open_additive_share_u8(&mut session, &out).await
            });
        }

        let opened = jobs
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 3);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[0], expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_rep_to_add2() -> Result<()> {
        test_rep_to_add2_u8().await
    }

    async fn test_add2_to_rep_binary() -> Result<()> {
        let mut rng = AesRng::from_entropy();
        let sessions = LocalRuntime::mock_sessions_with_channel().await?;
        let mut jobs = JoinSet::new();

        let value = Bit::new(rng.gen::<bool>());
        let expected = value;

        // Two-party additive sharing of the bit; dealer/party 2 gets zero.
        let shares = create_single_sharing_additive::<AesRng, Bit>(&mut rng, value, 2);

        for session in sessions.into_iter() {
            let session = session.clone();
            let shares = shares.clone();
            jobs.spawn(async move {
                let mut session = session.lock().await;
                let share_i = match session.own_role().index() {
                    0 => shares[0],
                    1 => shares[1],
                    2 => AdditiveShare::zero(),
                    _ => {
                        bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]")
                    }
                };

                let out = add2_to_rep_binary(&mut session, share_i).await?;

                // Open replicated bit share
                let opened = open_bin(&mut session, std::slice::from_ref(&out)).await?;
                Ok::<Bit, Error>(opened[0])
            });
        }

        let opened = jobs
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 3);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[0], expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_add2_to_rep() -> Result<()> {
        test_add2_to_rep_binary().await
    }

    async fn test_bitlt_u8() -> Result<()>
    where
        Standard: Distribution<u8>,
    {
        let modulus = 19;
        let mut rng = AesRng::from_entropy();
        let sessions = LocalRuntime::mock_sessions_with_channel().await?;
        let mut jobs = JoinSet::new();
        let private_values: Vec<Bit> = (0..8).map(|_| rng.gen::<Bit>()).collect();
        let private_value = private_values
            .iter()
            .rev()
            .enumerate()
            .fold(0_u8, |acc, (index, elem)| {
                acc + (elem.convert() as u8) * (2_u8.pow(index as u32))
            });
        let shares: (Vec<AdditiveShare<Bit>>, Vec<AdditiveShare<Bit>>) = private_values
            .iter()
            .map(|value| {
                let shares = create_single_sharing_additive::<AesRng, Bit>(&mut rng, *value, 2);
                (shares[0], shares[1])
            })
            .unzip();

        let public_value = rng.gen::<u8>();
        let expected = public_value < private_value;

        for session in sessions.into_iter() {
            let session = session.clone();
            let shares = shares.clone();
            jobs.spawn(async move {
                let mut rng = AesRng::from_entropy();
                let mut session = session.lock().await;
                let shares_i = match session.own_role().index() {
                    0 => shares.0,
                    1 => shares.1,
                    2 => vec![AdditiveShare::<Bit>::zero(); 8],
                    _ => {
                        bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]")
                    }
                };
                let prf_seed = PrfSeed::from([rng.gen::<u8>(); 16]);

                let out = bitlt(
                    &mut session,
                    shares_i.clone(),
                    public_value,
                    8,
                    prf_seed,
                    modulus,
                )
                .await?;

                // Open result bits
                open_additive_share_bit(&mut session, &out).await
            });
        }

        let opened = jobs
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 3);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[0].convert().convert(), expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_bitlt() -> Result<()> {
        test_bitlt_u8().await
    }

    async fn test_bitlt_u32() -> Result<()>
    where
        Standard: Distribution<u8>,
    {
        let modulus = 67;
        let mut rng = AesRng::from_entropy();
        let sessions = LocalRuntime::mock_sessions_with_channel().await?;
        let mut jobs = JoinSet::new();
        let private_values: Vec<Bit> = (0..32).map(|_| rng.gen::<Bit>()).collect();
        let private_value = private_values
            .iter()
            .rev()
            .enumerate()
            .fold(0_u32, |acc, (index, elem)| {
                acc + (elem.convert() as u32) * (2_u32.pow(index as u32))
            });

        let shares: (Vec<AdditiveShare<Bit>>, Vec<AdditiveShare<Bit>>) = private_values
            .iter()
            .map(|value| {
                let shares = create_single_sharing_additive::<AesRng, Bit>(&mut rng, *value, 2);
                (shares[0], shares[1])
            })
            .unzip();

        let public_value = rng.gen::<u32>();
        let expected = public_value < private_value;

        for session in sessions.into_iter() {
            let session = session.clone();
            let shares = shares.clone();
            jobs.spawn(async move {
                let mut rng = AesRng::from_entropy();
                let mut session = session.lock().await;
                let shares_i = match session.own_role().index() {
                    0 => shares.0,
                    1 => shares.1,
                    2 => vec![AdditiveShare::<Bit>::zero(); 8],
                    _ => {
                        bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]")
                    }
                };
                let prf_seed = PrfSeed::from([rng.gen::<u8>(); 16]);

                let out = bitlt(
                    &mut session,
                    shares_i.clone(),
                    public_value,
                    32,
                    prf_seed,
                    modulus,
                )
                .await?;

                // Open result bits
                open_additive_share_bit(&mut session, &out).await
            });
        }

        let opened = jobs
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 3);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[0].convert().convert(), expected);

        Ok(())
    }

    #[tokio::test]
    async fn test_bitlt_2() -> Result<()> {
        test_bitlt_u32().await
    }
}
