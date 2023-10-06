use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;

use mpc_net::{MpcNet, MpcNetError};

#[async_trait]
pub trait MpcSerNet: MpcNet {
    async fn broadcast<T: CanonicalDeserialize + CanonicalSerialize + Send>(
        &mut self,
        out: &T,
    ) -> Result<Vec<T>, MpcNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.broadcast_bytes(&bytes_out).await?;
        let results: Vec<Result<T, MpcNetError>> = bytes_in
            .into_iter()
            .map(|b| {
                T::deserialize_compressed(&b[..])
                    .map_err(|err| MpcNetError::Generic(err.to_string()))
            })
            .collect();

        let mut ret = Vec::new();
        for result in results {
            ret.push(result?);
        }

        Ok(ret)
    }

    async fn send_to_king<T: CanonicalDeserialize + CanonicalSerialize>(
        &mut self,
        out: &T,
    ) -> Result<Option<Vec<T>>, MpcNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self.send_bytes_to_king(&bytes_out).await?;

        if let Some(bytes_in) = bytes_in {
            let results: Vec<Result<T, MpcNetError>> = bytes_in
                .into_iter()
                .map(|b| {
                    T::deserialize_compressed(&b[..])
                        .map_err(|err| MpcNetError::Generic(err.to_string()))
                })
                .collect();

            let mut ret = Vec::new();
            for result in results {
                ret.push(result?);
            }

            Ok(Some(ret))
        } else {
            Ok(None)
        }
    }

    async fn recv_from_king<
        T: CanonicalDeserialize + CanonicalSerialize + Send,
    >(
        &mut self,
        out: Option<Vec<T>>,
    ) -> Result<T, MpcNetError> {
        let bytes = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out
                })
                .collect()
        });

        let bytes_in = self.recv_bytes_from_king(bytes).await?;
        Ok(T::deserialize_compressed(&bytes_in[..])?)
    }
}

impl<N: MpcNet> MpcSerNet for N {}
