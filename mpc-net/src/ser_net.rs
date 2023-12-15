use crate::{
    ClientSendOrKingReceiveResult, MpcNet, MpcNetError, MultiplexedStreamID,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use async_trait::async_trait;
use std::time::Duration;

#[async_trait]
pub trait MpcSerNet: MpcNet {
    async fn client_send_or_king_receive_serialized<
        T: CanonicalDeserialize + CanonicalSerialize,
    >(
        &self,
        out: &T,
        sid: MultiplexedStreamID,
        threshold: usize,
    ) -> Result<Option<Vec<T>>, MpcNetError> {
        let mut bytes_out = Vec::new();
        out.serialize_compressed(&mut bytes_out).unwrap();
        let bytes_in = self
            .client_send_or_king_receive(
                &bytes_out,
                sid,
                self.calculate_timeout(),
            )
            .await?;

        if let Some(result) = bytes_in {
            match result {
                ClientSendOrKingReceiveResult::Full(bytes_in) => {
                    let results: Vec<Result<T, MpcNetError>> = bytes_in
                        .into_iter()
                        .map(|b| {
                            T::deserialize_compressed(&b[..]).map_err(|err| {
                                MpcNetError::Generic(err.to_string())
                            })
                        })
                        .collect();

                    let mut ret = Vec::new();
                    for result in results {
                        ret.push(result?);
                    }

                    Ok(Some(ret))
                }

                ClientSendOrKingReceiveResult::Partial(received_results) => {
                    if received_results.len() < threshold {
                        return Err(MpcNetError::Protocol {
                            err: format!(
                                "Timeout: only {} responses received",
                                received_results.len()
                            ),
                            party: 0,
                        });
                    }

                    // TODO: recovery protocol
                    Ok(None) // TODO: real return value
                }
            }
        } else {
            Ok(None)
        }
    }

    async fn client_receive_or_king_send_serialized<
        T: CanonicalDeserialize + CanonicalSerialize + Send,
    >(
        &self,
        out: Option<Vec<T>>,
        sid: MultiplexedStreamID,
    ) -> Result<T, MpcNetError> {
        let bytes = out.map(|outs| {
            outs.iter()
                .map(|out| {
                    let mut bytes_out = Vec::new();
                    out.serialize_compressed(&mut bytes_out).unwrap();
                    bytes_out.into()
                })
                .collect()
        });

        let bytes_in = self.client_receive_or_king_send(bytes, sid).await?;
        Ok(T::deserialize_compressed(&bytes_in[..])?)
    }

    fn calculate_timeout(&self) -> Duration {
        // For now, assume a fixed timeout of 30 seconds
        Duration::from_secs(30)
    }
}

impl<N: MpcNet> MpcSerNet for N {}
