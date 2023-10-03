use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;

use mpc_net::MpcNet;

#[async_trait]
pub trait MpcSerNet: MpcNet {
    async fn broadcast<T: CanonicalDeserialize + CanonicalSerialize + Send>(
        &mut self,
        out: &T,
    ) -> Vec<T> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.broadcast_bytes(&bytes_out).await;
        bytes_in
            .into_iter()
            .map(|b| T::deserialize_compressed(&b[..]).unwrap())
            .collect()
    }

    async fn send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        out: &T,
    ) -> Option<Vec<T>> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        self.send_bytes_to_king(&bytes_out).await.map(|bytes_in| {
            bytes_in
                .into_iter()
                .map(|b| T::deserialize_compressed(&b[..]).unwrap())
                .collect()
        })
    }

    async fn recv_from_king<
        T: CanonicalDeserialize + CanonicalSerialize + Send,
    >(
        &mut self,
        out: Option<Vec<T>>,
    ) -> T {
        let bytes = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out
                })
                .collect()
        });

        let bytes_in = self.recv_bytes_from_king(bytes).await;
        T::deserialize_compressed(&bytes_in[..]).unwrap()
    }
}

impl<N: MpcNet> MpcSerNet for N {}
