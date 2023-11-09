pub mod multi;
pub mod prod;

use async_trait::async_trait;
use auto_impl::auto_impl;
use futures::stream::FuturesOrdered;
use futures::TryStreamExt;
pub use multi::LocalTestNet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use tokio_util::bytes::Bytes;

#[derive(Clone, Debug)]
pub enum MpcNetError {
    Generic(String),
    Protocol { err: String, party: u32 },
    NotConnected,
    BadInput { err: &'static str },
}

impl<T: ToString> From<T> for MpcNetError {
    fn from(e: T) -> Self {
        MpcNetError::Generic(e.to_string())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, Copy)]
pub enum MultiplexedStreamID {
    Zero = 0,
    One = 1,
    Two = 2,
}

#[async_trait]
#[auto_impl(&, &mut, Arc)]
pub trait MpcNet: Send + Sync {
    /// Am I the first party?

    fn is_king(&self) -> bool {
        self.party_id() == 0
    }
    /// How many parties are there?
    fn n_parties(&self) -> usize;
    /// What is my party number (0 to n-1)?
    fn party_id(&self) -> u32;
    /// Is the network layer initalized?
    fn is_init(&self) -> bool;
    async fn recv_from(
        &self,
        id: u32,
        sid: MultiplexedStreamID,
    ) -> Result<Bytes, MpcNetError>;
    async fn send_to(
        &self,
        id: u32,
        bytes: Bytes,
        sid: MultiplexedStreamID,
    ) -> Result<(), MpcNetError>;
    /// All parties send bytes to the king. The king receives all the bytes
    async fn client_send_or_king_receive(
        &self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Bytes>>, MpcNetError> {
        let bytes_out = Bytes::copy_from_slice(bytes);
        let own_id = self.party_id();

        let r = if self.is_king() {
            let mut r = FuturesOrdered::new();

            for id in 0..self.n_parties() as u32 {
                let bytes_out: Bytes = bytes_out.clone();
                r.push_back(Box::pin(async move {
                    let bytes_in = if id == own_id {
                        bytes_out
                    } else {
                        self.recv_from(id, sid).await?
                    };

                    Ok::<_, MpcNetError>((id, bytes_in))
                }));
            }

            let mut ret: HashMap<u32, Bytes> = r.try_collect().await?;
            ret.entry(0).or_insert_with(|| bytes_out.clone());

            let mut sorted_ret = Vec::new();
            for x in 0..self.n_parties() {
                sorted_ret.push(ret.remove(&(x as u32)).unwrap());
            }

            Ok(Some(sorted_ret))
        } else {
            self.send_to(0, bytes_out, sid).await?;
            Ok(None)
        };
        r
    }
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    async fn client_receive_or_king_send(
        &self,
        bytes_out: Option<Vec<Bytes>>,
        sid: MultiplexedStreamID,
    ) -> Result<Bytes, MpcNetError> {
        let own_id = self.party_id();

        if let Some(bytes_out) = bytes_out {
            if !self.is_king() {
                return Err(MpcNetError::BadInput {
                    err: "recv_from_king called with bytes_out when not king",
                });
            }

            let m = bytes_out[0].len();

            for id in (0..self.n_parties()).filter(|p| *p != own_id as usize) {
                if bytes_out[id].len() != m {
                    return Err(MpcNetError::Protocol {
                        err: format!("Peer {} sent wrong number of bytes", id),
                        party: id as u32,
                    });
                }

                self.send_to(id as u32, bytes_out[id].clone(), sid).await?;
            }

            Ok(bytes_out[own_id as usize].clone())
        } else {
            if self.is_king() {
                return Err(MpcNetError::BadInput {
                    err: "recv_from_king called with no bytes_out when king",
                });
            }

            self.recv_from(0, sid).await
        }
    }

    /// Everyone sends bytes to the king, who receives those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`
    /// proceeds.
    async fn king_compute(
        &self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<Bytes>) -> Vec<Bytes> + Send,
    ) -> Result<Bytes, MpcNetError> {
        let king_response =
            self.client_send_or_king_receive(bytes, sid).await?.map(f);
        self.client_receive_or_king_send(king_response, sid).await
    }
}
