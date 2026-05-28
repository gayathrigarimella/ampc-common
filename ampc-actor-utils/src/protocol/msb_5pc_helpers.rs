use crate::{
    execution::{
        player::Role,
        session::{NetworkSession, Session},
    },
    network::value::{NetworkInt, NetworkPrimeInt, NetworkValue},
    protocol::{
        test_utils::{create_single_sharing_additive, create_single_sharing_additive_prime},
        PrfSeed,
    },
};
use aes_prng::AesRng;
use ampc_secret_sharing::shares::{bit::Bit, share::AdditiveSharePrime};
use ampc_secret_sharing::{shares::primefield::PrimeElement, RingElement};
use ampc_secret_sharing::{shares::share::AdditiveShare, IntRing2k};
use eyre::{bail, eyre, Error, Result};
use itertools::multiunzip;
use num_traits::{One, Zero};
use rand::{Rng, SeedableRng};
use std::result::Result::Ok;
use tracing::instrument;

#[instrument(level = "trace", target = "searcher::network", skip_all)]
pub async fn open_additive_share_4party<T: IntRing2k + NetworkInt>(
    session: &mut Session,
    shares: &[AdditiveShare<T>],
) -> Result<Vec<T>, Error> {
    //let own_role = session.own_role().index();
    let network = &mut session.network_session;
    let own_role = network.own_role.index();
    let message = if shares.len() == 1 {
        T::new_network_element(shares[0].value)
    } else {
        T::new_network_vec(
            shares
                .iter()
                .map(|additive_share| additive_share.value)
                .collect(),
        )
    };

    for role_idx in 0..4 {
        if role_idx != own_role {
            network
                .send_to_role(Role::new(role_idx), message.clone())
                .await?;
        }
    }

    let mut received_shares = Vec::with_capacity(3);
    for role_idx in 0..4 {
        if role_idx != own_role {
            let vals = network
                .receive_from_role(Role::new(role_idx))
                .await
                .and_then(|v| T::into_vec(v))
                .map_err(|e| eyre!("failed to receive shares from role {}: {:?}", role_idx, e))?;
            received_shares.push(vals);
        }
    }

    shares
        .iter()
        .enumerate()
        .map(|(idx, share)| {
            let mut acc = share.value;
            for other_shares in &received_shares {
                acc += other_shares[idx];
            }
            Ok(acc.convert())
        })
        .collect()
}

pub async fn open_additive_share_prime_4party<T: NetworkPrimeInt>(
    session: &mut Session,
    shares: &[AdditiveSharePrime<PrimeElement<T>>],
) -> Result<Vec<PrimeElement<T>>, Error> {
    let network = &mut session.network_session;
    let own_role = network.own_role.index();

    let message = if shares.len() == 1 {
        T::new_network_prime_element(shares[0].value)
    } else {
        T::new_network_prime_vec(
            shares
                .iter()
                .map(|additive_share| additive_share.value)
                .collect(),
        )
    };

    for role_idx in 0..4 {
        if role_idx != own_role {
            network
                .send_to_role(Role::new(role_idx), message.clone())
                .await?;
        }
    }

    let mut received_shares = Vec::with_capacity(3);

    for role_idx in 0..4 {
        if role_idx != own_role {
            let vals = network
                .receive_from_role(Role::new(role_idx))
                .await
                .and_then(|v| T::into_prime_vec(v))
                .map_err(|e| {
                    eyre!(
                        "failed to receive prime shares from role {}: {:?}",
                        role_idx,
                        e
                    )
                })?;
            received_shares.push(vals);
        }
    }

    shares
        .iter()
        .enumerate()
        .map(|(idx, share)| {
            let mut acc = share.value;
            for other_shares in &received_shares {
                acc = acc + other_shares[idx];
            }
            Ok(acc)
        })
        .collect()
}

/// Setup a shared seed across first two parties in dealer model.
/// Each party (of 0, 1, 2, 3) sends their seed to the other and receives from each other.
/// The final shared seed is the XOR of both seeds.
pub async fn setup_shared_seed_dealer_model_4party(
    session: &mut NetworkSession,
    my_seed: PrfSeed,
) -> Result<PrfSeed> {
    let my_msg = NetworkValue::PrfKey(my_seed);

    let decode = |msg| match msg {
        Ok(NetworkValue::PrfKey(seed)) => Ok(seed),
        _ => Err(eyre!("Could not deserialize PrfKey")),
    };

    let shared_seed = match session.own_role.index() {
        0 | 1 | 2 | 3 => {
            let mut current_seed = my_seed;
            for role_idx in 0..4 {
                if role_idx != session.own_role.index() {
                    session
                        .send_to_role(Role::new(role_idx), my_msg.clone())
                        .await?;
                    let other_seed = decode(session.receive_from_role(Role::new(role_idx)).await)?;
                    current_seed = std::array::from_fn(|i| current_seed[i] ^ other_seed[i]);
                }
            }
            current_seed
        }
        _ => {
            bail!("Cannot deal with roles that have index outside of the set [0, 1, 2, 3]")
        }
    };

    Ok(shared_seed)
}

pub async fn bin_to_primefield16_4party(
    session: &mut Session,
    values: Vec<RingElement<Bit>>,
    modulus: u16,
) -> Result<Vec<AdditiveSharePrime<PrimeElement<u16>>>, Error> {
    let network = &mut session.network_session;
    let shares = match network.own_role.index() {
        0 | 1 | 2 | 3 => {
            let share_from_dealer = network
                .receive_from_role(Role::new(4))
                .await
                .map_err(|e| eyre!("Error in receiving in open_bin operation: {}", e))?;
            if values.len() == 1 {
                match share_from_dealer {
                    NetworkValue::PrimeElement16(message) => {
                        Ok(vec![AdditiveSharePrime::new(message)])
                    }
                    _ => Err(eyre!("Wrong value type is received in open_bin operation")),
                }
            } else {
                match NetworkValue::vec_from_network(share_from_dealer) {
                    Ok(v) => {
                        if matches!(v[0], NetworkValue::PrimeElement16(_)) {
                            Ok(v.into_iter()
                                .map(|x| match x {
                                    NetworkValue::PrimeElement16(message) => {
                                        AdditiveSharePrime::new(message)
                                    }
                                    _ => unreachable!(),
                                })
                                .collect())
                        } else {
                            Err(eyre!("Wrong value type is received in open_bin operation"))
                        }
                    }
                    Err(e) => Err(eyre!("Error in receiving in open_bin operation: {}", e)),
                }
            }?
        }

        4 => {
            let mut rng = AesRng::from_entropy();
            let (shares_0, shares_1, shares_2, shares_3): (
                Vec<AdditiveSharePrime<PrimeElement<u16>>>,
                Vec<AdditiveSharePrime<PrimeElement<u16>>>,
                Vec<AdditiveSharePrime<PrimeElement<u16>>>,
                Vec<AdditiveSharePrime<PrimeElement<u16>>>,
            ) = multiunzip(values.iter().map(|value| {
                let bit_as_mod19 =
                    PrimeElement::<u16>::new(u8::from(value.convert()) as u16, modulus);
                let shares = create_single_sharing_additive_prime(
                    &mut rng,
                    bit_as_mod19.get_value(),
                    modulus,
                    4,
                );
                (shares[0], shares[1], shares[2], shares[3])
            }));
            for role_idx in 0..4 {
                let shares = match role_idx {
                    0 => shares_0.clone(),
                    1 => shares_1.clone(),
                    2 => shares_2.clone(),
                    3 => shares_3.clone(),
                    _ => unreachable!(),
                };
                let message = if shares.len() == 1 {
                    NetworkValue::PrimeElement16(shares[0].value)
                } else {
                    let values = shares
                        .iter()
                        .map(|x| NetworkValue::PrimeElement16(x.value))
                        .collect::<Vec<_>>();
                    NetworkValue::vec_to_network(values)
                };
                network.send_to_role(Role::new(role_idx), message).await?;
            }
            vec![]
        }
        _ => bail!("Cannot deal with roles that have index outside of the set [0, 1, 2, 3, 4]"),
    };
    Ok(shares)
}

pub async fn primefield16_to_bin_one_hot(
    session: &mut Session,
    values: Vec<PrimeElement<u16>>,
) -> Result<Vec<AdditiveShare<Bit>>, Error> {
    let network = &mut session.network_session;
    let shares = match network.own_role.index() {
        0 | 1 | 2 | 3 => {
            let share_from_dealer = network
                .receive_from_role(Role::new(4))
                .await
                .map_err(|e| eyre!("Error in receiving in open_bin operation: {}", e))?;
            if values.len() == 1 {
                match share_from_dealer {
                    NetworkValue::RingElementBit(message) => Ok(vec![AdditiveShare::new(message)]),
                    _ => Err(eyre!("Wrong value type is received in open_bin operation")),
                }
            } else {
                match NetworkValue::vec_from_network(share_from_dealer) {
                    Ok(v) => {
                        if matches!(v[0], NetworkValue::RingElementBit(_)) {
                            Ok(v.into_iter()
                                .map(|x| match x {
                                    NetworkValue::RingElementBit(message) => {
                                        AdditiveShare::new(message)
                                    }
                                    _ => unreachable!(),
                                })
                                .collect())
                        } else {
                            Err(eyre!("Wrong value type is received in open_bin operation"))
                        }
                    }
                    Err(e) => Err(eyre!("Error in receiving in open_bin operation: {}", e)),
                }
            }?
        }
        4 => {
            let mut rng = AesRng::from_entropy();
            let (shares_0, shares_1, shares_2, shares_3): (
                Vec<AdditiveShare<Bit>>,
                Vec<AdditiveShare<Bit>>,
                Vec<AdditiveShare<Bit>>,
                Vec<AdditiveShare<Bit>>,
            ) = multiunzip(values.iter().map(|value| {
                let shares = if value.is_zero() {
                    create_single_sharing_additive(&mut rng, Bit::one(), 4)
                } else {
                    create_single_sharing_additive(&mut rng, Bit::zero(), 4)
                };
                (shares[0], shares[1], shares[2], shares[3])
            }));
            for role_idx in 0..4 {
                let shares = match role_idx {
                    0 => shares_0.clone(),
                    1 => shares_1.clone(),
                    2 => shares_2.clone(),
                    3 => shares_3.clone(),
                    _ => unreachable!(),
                };
                let message = if shares.len() == 1 {
                    NetworkValue::RingElementBit(shares[0].value)
                } else {
                    let values = shares
                        .iter()
                        .map(|x| NetworkValue::RingElementBit(x.value))
                        .collect::<Vec<_>>();
                    NetworkValue::vec_to_network(values)
                };
                network.send_to_role(Role::new(role_idx), message).await?;
            }
            vec![]
        }
        _ => bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]"),
    };
    Ok(shares)
}

#[instrument(level = "trace", target = "searcher::network", skip_all)]
pub async fn send_binary_shares_to_dealer(
    session: &mut Session,
    shares: &Vec<AdditiveShare<Bit>>,
) -> Result<Vec<RingElement<Bit>>, Error> {
    let network = &mut session.network_session;
    let message = if shares.len() == 1 {
        NetworkValue::RingElementBit(shares[0].value)
    } else {
        // TODO: could be optimized by packing bits
        let bits = shares
            .iter()
            .map(|x| NetworkValue::RingElementBit(x.value))
            .collect::<Vec<_>>();
        NetworkValue::vec_to_network(bits)
    };

    let values_received = match network.own_role.index() {
        0 => {
            network.send_prev(message.clone()).await?;
            vec![]
        }
        1 => {
            network.send_next(message.clone()).await?;
            vec![]
        }
        2 => {
            let share_from_previous = network
                .receive_prev()
                .await
                .map_err(|e| eyre!("Error in receiving in open_bin operation: {}", e))?;
            let values_from_previous = if shares.len() == 1 {
                match share_from_previous {
                    NetworkValue::RingElementBit(message) => Ok(vec![message]),
                    _ => Err(eyre!("Wrong value type is received in open_bin operation")),
                }
            } else {
                match NetworkValue::vec_from_network(share_from_previous) {
                    Ok(v) => {
                        if matches!(v[0], NetworkValue::RingElementBit(_)) {
                            Ok(v.into_iter()
                                .map(|x| match x {
                                    NetworkValue::RingElementBit(message) => message,
                                    _ => unreachable!(),
                                })
                                .collect())
                        } else {
                            Err(eyre!("Wrong value type is received in open_bin operation"))
                        }
                    }
                    Err(e) => Err(eyre!("Error in receiving in open_bin operation: {}", e)),
                }
            }?;
            let share_from_next = network
                .receive_next()
                .await
                .map_err(|e| eyre!("Error in receiving in open_bin operation: {}", e))?;
            let values_from_next = if shares.len() == 1 {
                match share_from_next {
                    NetworkValue::RingElementBit(message) => Ok(vec![message]),
                    _ => Err(eyre!("Wrong value type is received in open_bin operation")),
                }
            } else {
                match NetworkValue::vec_from_network(share_from_next) {
                    Ok(v) => {
                        if matches!(v[0], NetworkValue::RingElementBit(_)) {
                            Ok(v.into_iter()
                                .map(|x| match x {
                                    NetworkValue::RingElementBit(message) => message,
                                    _ => unreachable!(),
                                })
                                .collect())
                        } else {
                            Err(eyre!("Wrong value type is received in open_bin operation"))
                        }
                    }
                    Err(e) => Err(eyre!("Error in receiving in open_bin operation: {}", e)),
                }
            }?;

            values_from_previous
                .iter()
                .zip(values_from_next.iter())
                .map(|(prev, next)| *prev ^ next)
                .collect()
        }
        _ => {
            bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]")
        }
    };
    Ok(values_received)
}

#[instrument(level = "trace", target = "searcher::network", skip_all)]
pub async fn send_prime16_shares_to_dealer(
    session: &mut Session,
    shares: &Vec<AdditiveSharePrime<PrimeElement<u16>>>,
) -> Result<Vec<PrimeElement<u16>>, Error> {
    let network = &mut session.network_session;
    let message = if shares.len() == 1 {
        NetworkValue::PrimeElement16(shares[0].value)
    } else {
        // TODO: could be optimized by packing bits
        let bits = shares
            .iter()
            .map(|x| NetworkValue::PrimeElement16(x.value))
            .collect::<Vec<_>>();
        NetworkValue::vec_to_network(bits)
    };
    let values_received = match network.own_role.index() {
        0 => {
            network.send_prev(message.clone()).await?;
            vec![]
        }
        1 => {
            network.send_next(message.clone()).await?;
            vec![]
        }
        2 => {
            let share_from_previous = network
                .receive_prev()
                .await
                .map_err(|e| eyre!("Error in receiving in open_bin operation: {}", e))?;
            let values_from_previous = if shares.len() == 1 {
                match share_from_previous {
                    NetworkValue::PrimeElement16(message) => Ok(vec![message]),
                    _ => Err(eyre!("Wrong value type is received in open_bin operation")),
                }
            } else {
                match NetworkValue::vec_from_network(share_from_previous) {
                    Ok(v) => {
                        if matches!(v[0], NetworkValue::PrimeElement16(_)) {
                            Ok(v.into_iter()
                                .map(|x| match x {
                                    NetworkValue::PrimeElement16(message) => message,
                                    _ => unreachable!(),
                                })
                                .collect())
                        } else {
                            Err(eyre!("Wrong value type is received in open_bin operation"))
                        }
                    }
                    Err(e) => Err(eyre!("Error in receiving in open_bin operation: {}", e)),
                }
            }?;
            let share_from_next = network
                .receive_next()
                .await
                .map_err(|e| eyre!("Error in receiving in open_bin operation: {}", e))?;
            let values_from_next = if shares.len() == 1 {
                match share_from_next {
                    NetworkValue::PrimeElement16(message) => Ok(vec![message]),
                    _ => Err(eyre!("Wrong value type is received in open_bin operation")),
                }
            } else {
                match NetworkValue::vec_from_network(share_from_next) {
                    Ok(v) => {
                        if matches!(v[0], NetworkValue::PrimeElement16(_)) {
                            Ok(v.into_iter()
                                .map(|x| match x {
                                    NetworkValue::PrimeElement16(message) => message,
                                    _ => unreachable!(),
                                })
                                .collect())
                        } else {
                            Err(eyre!("Wrong value type is received in open_bin operation"))
                        }
                    }
                    Err(e) => Err(eyre!("Error in receiving in open_bin operation: {}", e)),
                }
            }?;
            values_from_previous
                .iter()
                .zip(values_from_next.iter())
                .map(|(prev, next)| *prev + *next)
                .collect()
        }
        _ => {
            bail!("Cannot deal with roles that have index outside of the set [0, 1, 2]")
        }
    };
    Ok(values_received)
}

#[cfg(test)]
mod tests {
    use crate::protocol::msb_5pc_helpers::open_additive_share_prime_4party;
    use crate::{
        execution::local::LocalRuntime,
        protocol::{
            msb_5pc_helpers::open_additive_share_4party,
            test_utils::{
                create_array_sharing_additive_4party, create_array_sharing_additive_prime_4party,
                create_single_sharing_additive, create_single_sharing_additive_prime,
            },
        },
    };
    use aes_prng::AesRng;
    use ampc_secret_sharing::shares::share::AdditiveShare;
    use ampc_secret_sharing::shares::{primefield::PrimeElement, share::AdditiveSharePrime};
    use eyre::{bail, Error, Result};
    use rand::{Rng, SeedableRng};
    use tokio::task::JoinSet;

    #[test]
    fn test_create_single_sharing_additive_local_reconstruction() {
        let mut rng = AesRng::from_entropy();
        let value = rng.gen::<u32>();

        let shares = create_single_sharing_additive::<AesRng, u32>(&mut rng, value, 4);

        let opened = shares[0].get_value()
            + shares[1].get_value()
            + shares[2].get_value()
            + shares[3].get_value();

        assert_eq!(opened.convert(), value);
    }

    #[test]
    fn test_create_array_sharing_additive_local_reconstruction() {
        let mut rng = AesRng::from_entropy();
        let values: Vec<u32> = (0..10).map(|_| rng.gen::<u32>()).collect();

        let shares = create_array_sharing_additive_4party::<AesRng, u32>(&mut rng, &values);

        for (idx, expected) in values.iter().enumerate() {
            let opened = shares.of_party(0)[idx].get_value()
                + shares.of_party(1)[idx].get_value()
                + shares.of_party(2)[idx].get_value()
                + shares.of_party(3)[idx].get_value();

            assert_eq!(opened.convert(), *expected);
        }
    }

    #[tokio::test]
    async fn test_create_single_sharing_additive_4party() -> Result<(), Error> {
        let mut rng = AesRng::from_entropy();
        let expected = rng.gen::<u32>();
        let shares = create_single_sharing_additive::<AesRng, u32>(&mut rng, expected, 4);
        let sessions = LocalRuntime::mock_sessions_with_channel_n(5).await?;
        let mut join_set = JoinSet::new();
        for i in 0..4 {
            let shares = shares.clone();
            let session = sessions[i].clone();
            join_set.spawn(async move {
                let mut session = session.lock().await;
                let own_role_idx = session.network_session.own_role.index();
                let share_i = match own_role_idx {
                    0 => Ok::<AdditiveShare<u32>, Error>(shares[0]),
                    1 => Ok::<AdditiveShare<u32>, Error>(shares[1]),
                    2 => Ok::<AdditiveShare<u32>, Error>(shares[2]),
                    3 => Ok::<AdditiveShare<u32>, Error>(shares[3]),
                    _ => bail!("Invalid role"),
                }?;

                open_additive_share_4party(&mut session, &[share_i]).await
            });
        }
        let opened = join_set
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 4);
        assert_eq!(opened[0][0], opened[1][0]);
        assert_eq!(opened[1][0], opened[2][0]);
        assert_eq!(opened[2][0], opened[3][0]);
        assert_eq!(opened[0][0], expected);
        Ok(())
    }

    #[tokio::test]

    async fn test_create_array_sharing_additive_4party() -> Result<(), Error> {
        let mut rng = AesRng::from_entropy();
        let values: Vec<u32> = (0..20).map(|_| rng.gen::<u32>()).collect();
        let shares = create_array_sharing_additive_4party::<AesRng, u32>(&mut rng, &values);

        let sessions = LocalRuntime::mock_sessions_with_channel_n(5).await?;
        let mut join_set = JoinSet::new();

        for idx in 0..4 {
            let session = sessions[idx].clone();
            let shares_i = shares.of_party(idx).clone();
            join_set.spawn(async move {
                let mut session = session.lock().await;
                open_additive_share_4party(&mut session, &shares_i).await
            });
        }
        let opened = join_set
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 4);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[2], opened[3]);

        for (idx, opened_i) in opened[0].iter().enumerate() {
            assert_eq!(opened_i, &values[idx]);
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_create_single_sharing_additive_prime_4party() -> Result<(), Error> {
        let mut rng = AesRng::from_entropy();

        let modulus = 19u16;
        let expected = rng.gen_range(0..modulus);

        let shares =
            create_single_sharing_additive_prime::<AesRng, u16>(&mut rng, expected, modulus, 4);

        let sessions = LocalRuntime::mock_sessions_with_channel_n(5).await?;
        let mut join_set = JoinSet::new();

        for i in 0..4 {
            let session = sessions[i].clone();
            let shares = shares.clone();
            join_set.spawn(async move {
                let mut session = session.lock().await;
                let own_role_idx = session.network_session.own_role.index();
                let share_i = match own_role_idx {
                    0 => Ok::<AdditiveSharePrime<PrimeElement<u16>>, Error>(shares[0]),
                    1 => Ok::<AdditiveSharePrime<PrimeElement<u16>>, Error>(shares[1]),
                    2 => Ok::<AdditiveSharePrime<PrimeElement<u16>>, Error>(shares[2]),
                    3 => Ok::<AdditiveSharePrime<PrimeElement<u16>>, Error>(shares[3]),
                    _ => bail!("Invalid role"),
                }?;

                open_additive_share_prime_4party(&mut session, &[share_i]).await
            });
        }

        let opened = join_set
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        let expected_prime = PrimeElement::<u16>::new(expected, modulus);

        assert_eq!(opened.len(), 4);
        assert_eq!(opened[0][0], opened[1][0]);
        assert_eq!(opened[1][0], opened[2][0]);
        assert_eq!(opened[2][0], opened[3][0]);
        assert_eq!(opened[0][0], expected_prime);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_array_sharing_additive_prime_4party() -> Result<(), Error> {
        let mut rng = AesRng::from_entropy();
        let modulus = 29u32;
        let values: Vec<u32> = (0..20).map(|_| rng.gen_range(0..modulus)).collect();
        let shares =
            create_array_sharing_additive_prime_4party::<AesRng, u32>(&mut rng, &values, modulus);

        let sessions = LocalRuntime::mock_sessions_with_channel_n(5).await?;
        let mut join_set = JoinSet::new();

        for idx in 0..4 {
            let session = sessions[idx].clone();
            let shares_i = shares.of_party(idx).clone();
            join_set.spawn(async move {
                let mut session = session.lock().await;
                open_additive_share_prime_4party(&mut session, &shares_i).await
            });
        }
        let opened = join_set
            .join_all()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(opened.len(), 4);
        assert_eq!(opened[0], opened[1]);
        assert_eq!(opened[1], opened[2]);
        assert_eq!(opened[2], opened[3]);

        for (idx, opened_i) in opened[0].iter().enumerate() {
            assert_eq!(opened_i.get_value(), values[idx]);
            println!(
                "opened_i: {}, expected: {}",
                opened_i.get_value(),
                values[idx]
            );
        }

        Ok(())
    }
}
