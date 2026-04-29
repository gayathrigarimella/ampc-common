use crate::{
    execution::{
        local::LocalRuntime, player::Role, session::{Session, SessionHandles}
    },
    network::value::NetworkInt,
    protocol::test_utils::create_single_sharing_additive_4party
};
use ampc_secret_sharing::{
    shares::share::AdditiveShare,
    IntRing2k, RingElement
};
use eyre::{bail, eyre, Error, Result};
use tracing::instrument;
use num_traits::PrimInt;



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
                .send_to_role(Role::new(role_idx), message.clone()).await?;
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

#[cfg(test)]

mod tests {
    use aes_prng::AesRng;
    use ampc_secret_sharing::shares::share::AdditiveShare;
    use num_traits::zero;
    use rand::{Rng, SeedableRng};
    use tokio::task::JoinSet;
    use crate::{execution::local::LocalRuntime, protocol::{msb_5pc::open_additive_share_4party, test_utils::create_single_sharing_additive_4party}};
    use crate::execution::player::Role;
    use eyre::{bail, eyre, Error, Result};

    #[test]
    fn test_create_single_sharing_additive_local_reconstruction() {
        let mut rng = AesRng::from_entropy();
        let value = rng.gen::<u32>();

        let shares = create_single_sharing_additive_4party::<AesRng, u32>(&mut rng, value);

        let opened = shares.0.get_value()
            + shares.1.get_value()
            + shares.2.get_value()
            + shares.3.get_value();

        assert_eq!(opened.convert(), value);
    }

    #[tokio::test]
    async fn test_create_single_sharing_additive_4party() -> Result<(), Error> {

        let mut rng = AesRng::from_entropy();
        let expected = rng.gen::<u32>();
        let shares = create_single_sharing_additive_4party::<AesRng, u32>(&mut rng, expected);
        let sessions = LocalRuntime::mock_sessions_with_channel_n(5).await?;
        let mut join_set = JoinSet::new();
        for i in 0..4 {
            let session = sessions[i].clone();
            join_set.spawn(async move {
                let mut session = session.lock().await;
                let own_role_idx = session.network_session.own_role.index();
                let share_i = match own_role_idx {
                    0 => Ok::<AdditiveShare<u32>, Error>(shares.0),
                    1 => Ok::<AdditiveShare<u32>, Error>(shares.1),
                    2 => Ok::<AdditiveShare<u32>, Error>(shares.2),
                    3 => Ok::<AdditiveShare<u32>, Error>(shares.3),
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

}