use ampc_secret_sharing::shares::{primefield::PrimeElement, share::AdditiveSharePrime};
use ampc_secret_sharing::{shares::share::AdditiveShare, IntRing2k, ReplicatedShare, RingElement};
use num_traits::{PrimInt, Zero};
use rand::{Rng, RngCore};
use rand_distr::{Distribution, Standard};

pub fn create_single_sharing_additive<R: RngCore, T: IntRing2k>(
    rng: &mut R,
    input: T,
    num_parties: usize,
) -> Vec<AdditiveShare<T>>
where
    Standard: Distribution<T>,
{
    let mut shares: Vec<AdditiveShare<T>> = Vec::with_capacity(num_parties);
    let mut running_sum = RingElement::<T>::zero();
    (0..num_parties - 1).for_each(|_| {
        let rand_share = RingElement(rng.gen::<T>());
        shares.push(AdditiveShare::new(rand_share));
        running_sum += rand_share;
    });
    let last_share = RingElement(input) - running_sum;
    shares.push(AdditiveShare::new(last_share));
    shares
}

pub fn create_single_sharing_additive_prime<R, T>(
    rng: &mut R,
    input: T,
    modulus: T,
    num_parties: usize,
) -> Vec<AdditiveSharePrime<PrimeElement<T>>>
where
    R: rand::RngCore,
    T: PrimInt,
{
    let mut shares: Vec<AdditiveSharePrime<PrimeElement<T>>> = Vec::with_capacity(num_parties);
    let mut running_sum = PrimeElement::zero(modulus);
    (0..num_parties - 1).for_each(|_| {
        let rand_share = PrimeElement::rand(rng, modulus);
        shares.push(AdditiveSharePrime::new(rand_share));
        running_sum += rand_share;
    });
    let last_share = PrimeElement::new(input, modulus) - running_sum;
    shares.push(AdditiveSharePrime::new(last_share));
    shares
}

pub fn create_single_sharing_replicated<R: RngCore, T: IntRing2k>(
    rng: &mut R,
    input: T,
) -> (ReplicatedShare<T>, ReplicatedShare<T>, ReplicatedShare<T>)
where
    Standard: Distribution<T>,
{
    let a = RingElement(rng.gen::<T>());
    let b = RingElement(rng.gen::<T>());
    let c = RingElement(input) - a - b;

    let share1 = ReplicatedShare::new(a, c);
    let share2 = ReplicatedShare::new(b, a);
    let share3 = ReplicatedShare::new(c, b);
    (share1, share2, share3)
}
pub struct LocalShares1DReplicated<T: IntRing2k> {
    pub p0: Vec<ReplicatedShare<T>>,
    pub p1: Vec<ReplicatedShare<T>>,
    pub p2: Vec<ReplicatedShare<T>>,
}

impl<T: IntRing2k> LocalShares1DReplicated<T> {
    pub fn of_party(&self, party_id: usize) -> &Vec<ReplicatedShare<T>> {
        match party_id {
            0 => &self.p0,
            1 => &self.p1,
            2 => &self.p2,
            _ => panic!("Invalid party id"),
        }
    }
}

pub struct LocalShares1DAdditive<T: IntRing2k> {
    pub p0: Vec<AdditiveShare<T>>,
    pub p1: Vec<AdditiveShare<T>>,
    pub p2: Vec<AdditiveShare<T>>,
}

impl<T: IntRing2k> LocalShares1DAdditive<T> {
    pub fn of_party(&self, party_id: usize) -> &Vec<AdditiveShare<T>> {
        match party_id {
            0 => &self.p0,
            1 => &self.p1,
            2 => &self.p2,
            _ => panic!("Invalid party id"),
        }
    }
}

pub struct LocalShares1DAdditive4Party<T: IntRing2k> {
    pub p0: Vec<AdditiveShare<T>>,
    pub p1: Vec<AdditiveShare<T>>,
    pub p2: Vec<AdditiveShare<T>>,
    pub p3: Vec<AdditiveShare<T>>,
}

impl<T: IntRing2k> LocalShares1DAdditive4Party<T> {
    pub fn of_party(&self, party_id: usize) -> &Vec<AdditiveShare<T>> {
        match party_id {
            0 => &self.p0,
            1 => &self.p1,
            2 => &self.p2,
            3 => &self.p3,
            _ => panic!("Invalid party id"),
        }
    }
}

pub struct LocalShares1DAdditivePrime4Party<T: PrimInt> {
    pub p0: Vec<AdditiveSharePrime<PrimeElement<T>>>,
    pub p1: Vec<AdditiveSharePrime<PrimeElement<T>>>,
    pub p2: Vec<AdditiveSharePrime<PrimeElement<T>>>,
    pub p3: Vec<AdditiveSharePrime<PrimeElement<T>>>,
}

impl<T: PrimInt> LocalShares1DAdditivePrime4Party<T> {
    pub fn of_party(&self, party_id: usize) -> &Vec<AdditiveSharePrime<PrimeElement<T>>> {
        match party_id {
            0 => &self.p0,
            1 => &self.p1,
            2 => &self.p2,
            3 => &self.p3,
            _ => panic!("Invalid party id"),
        }
    }
}

pub fn create_array_sharing_replicated<R: RngCore, T: IntRing2k>(
    rng: &mut R,
    input: &Vec<T>,
) -> LocalShares1DReplicated<T>
where
    Standard: Distribution<T>,
{
    let mut player0 = Vec::new();
    let mut player1 = Vec::new();
    let mut player2 = Vec::new();

    for entry in input {
        let (a, b, c) = create_single_sharing_replicated(rng, *entry);
        player0.push(a);
        player1.push(b);
        player2.push(c);
    }
    LocalShares1DReplicated {
        p0: player0,
        p1: player1,
        p2: player2,
    }
}

pub fn create_array_sharing_additive<R: RngCore, T: IntRing2k>(
    rng: &mut R,
    input: &Vec<T>,
) -> LocalShares1DAdditive<T>
where
    Standard: Distribution<T>,
{
    let mut player0 = Vec::new();
    let mut player1 = Vec::new();
    let mut player2 = Vec::new();

    for entry in input {
        let sharing = create_single_sharing_additive(rng, *entry, 3);
        player0.push(sharing[0]);
        player1.push(sharing[1]);
        player2.push(AdditiveShare::zero());
    }
    LocalShares1DAdditive {
        p0: player0,
        p1: player1,
        p2: player2,
    }
}

pub fn create_array_sharing_additive_4party<R: RngCore, T: IntRing2k>(
    rng: &mut R,
    input: &Vec<T>,
) -> LocalShares1DAdditive4Party<T>
where
    Standard: Distribution<T>,
{
    let mut player0 = Vec::new();
    let mut player1 = Vec::new();
    let mut player2 = Vec::new();
    let mut player3 = Vec::new();

    for entry in input {
        let shares = create_single_sharing_additive(rng, *entry, 4);
        player0.push(shares[0]);
        player1.push(shares[1]);
        player2.push(shares[2]);
        player3.push(shares[3]);
    }
    LocalShares1DAdditive4Party {
        p0: player0,
        p1: player1,
        p2: player2,
        p3: player3,
    }
}

pub fn create_array_sharing_additive_prime_4party<R: RngCore, T: PrimInt>(
    rng: &mut R,
    input: &Vec<T>,
    modulus: T,
) -> LocalShares1DAdditivePrime4Party<T>
where
    R: rand::RngCore,
    T: PrimInt,
{
    let mut player0 = Vec::new();
    let mut player1 = Vec::new();
    let mut player2 = Vec::new();
    let mut player3 = Vec::new();

    for entry in input {
        let shares = create_single_sharing_additive_prime(rng, *entry, modulus, 4);
        player0.push(shares[0]);
        player1.push(shares[1]);
        player2.push(shares[2]);
        player3.push(shares[3]);
    }
    LocalShares1DAdditivePrime4Party {
        p0: player0,
        p1: player1,
        p2: player2,
        p3: player3,
    }
}
