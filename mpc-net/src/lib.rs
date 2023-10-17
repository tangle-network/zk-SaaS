pub mod multi;
pub mod prod;

use async_trait::async_trait;
use auto_impl::auto_impl;
pub use multi::LocalTestNet;
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

#[derive(Clone, Debug, PartialEq, Eq, Hash, Copy)]
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
    /// All parties send bytes to the king. The king receives all the bytes
    async fn send_bytes_to_king(
        &self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Bytes>>, MpcNetError>;
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    async fn recv_bytes_from_king(
        &self,
        bytes: Option<Vec<Bytes>>,
        sid: MultiplexedStreamID,
    ) -> Result<Bytes, MpcNetError>;

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
        let king_response = self.send_bytes_to_king(bytes, sid).await?.map(f);
        self.recv_bytes_from_king(king_response, sid).await
    }
}
