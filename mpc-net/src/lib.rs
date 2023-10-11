pub mod multi;
pub mod prod;

use async_trait::async_trait;
use auto_impl::auto_impl;
pub use multi::LocalTestNet;
use std::fmt::Debug;

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub broadcasts: usize,
    pub to_king: usize,
    pub from_king: usize,
}

#[derive(Clone, Debug)]
pub enum MpcNetError {
    Generic(String),
    Protocol { err: String, party: u32 },
    NotConnected,
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
#[auto_impl(&mut)]
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
    /// Uninitialized the network layer, closing all connections.
    fn deinit(&mut self);
    /// Set statistics to zero.
    fn reset_stats(&mut self);
    /// Get statistics.
    fn stats(&self) -> &Stats;
    /// All parties send bytes to each other.
    async fn broadcast_bytes(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Vec<Vec<u8>>, MpcNetError>;
    /// All parties send bytes to the king.
    async fn send_bytes_to_king(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Vec<u8>>>, MpcNetError>;
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    async fn recv_bytes_from_king(
        &mut self,
        bytes: Option<Vec<Vec<u8>>>,
        sid: MultiplexedStreamID,
    ) -> Result<Vec<u8>, MpcNetError>;

    /// Everyone sends bytes to the king, who receives those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`
    /// proceeds.

    async fn king_compute(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
        f: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>> + Send,
    ) -> Result<Vec<u8>, MpcNetError> {
        let king_response = self.send_bytes_to_king(bytes, sid).await?.map(f);
        self.recv_bytes_from_king(king_response, sid).await
    }
}
