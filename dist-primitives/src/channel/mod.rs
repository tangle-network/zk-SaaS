use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use mpc_net::MpcNet;

pub trait MpcSerNet: MpcNet {
    #[inline]
    fn broadcast<T: CanonicalDeserialize + CanonicalSerialize>(
        out: &T,
    ) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = Self::broadcast_bytes(&bytes_out);
        bytes_in
            .into_iter()
            .map(|b| T::deserialize_compressed(&b[..]).unwrap())
            .collect()
    }

    #[inline]
    fn send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(
        out: &T,
    ) -> Option<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        Self::send_bytes_to_king(&bytes_out).map(|bytes_in| {
            bytes_in
                .into_iter()
                .map(|b| T::deserialize_compressed(&b[..]).unwrap())
                .collect()
        })
    }

    #[inline]
    fn recv_from_king<T: CanonicalDeserialize + CanonicalSerialize>(
        out: Option<Vec<T>>,
    ) -> T {
        let bytes_in = Self::recv_bytes_from_king(out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out
                })
                .collect()
        }));
        T::deserialize_compressed(&bytes_in[..]).unwrap()
    }
}

impl<N: MpcNet> MpcSerNet for N {}
