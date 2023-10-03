pub mod multi;

use async_trait::async_trait;
use auto_impl::auto_impl;
pub use multi::MpcMultiNet;

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub bytes_sent: usize,
    pub bytes_recv: usize,
    pub broadcasts: usize,
    pub to_king: usize,
    pub from_king: usize,
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
    fn party_id(&self) -> usize;
    /// Initializes the networking
    async fn init(&mut self);
    /// Is the network layer initalized?
    fn is_init(&self) -> bool;
    /// Uninitialized the network layer, closing all connections.
    fn deinit(&mut self);
    /// Set statistics to zero.
    fn reset_stats(&mut self);
    /// Get statistics.
    fn stats(&self) -> &Stats;
    /// All parties send bytes to each other.
    async fn broadcast_bytes(&mut self, bytes: &[u8]) -> Vec<Vec<u8>>;
    /// All parties send bytes to the king.
    async fn send_bytes_to_king(
        &mut self,
        bytes: &[u8],
    ) -> Option<Vec<Vec<u8>>>;
    /// All parties recv bytes from the king.
    /// Provide bytes iff you're the king!
    async fn recv_bytes_from_king(
        &mut self,
        bytes: Option<Vec<Vec<u8>>>,
    ) -> Vec<u8>;

    /// Everyone sends bytes to the king, who recieves those bytes, runs a computation on them, and
    /// redistributes the resulting bytes.
    ///
    /// The king's computation is given by a function, `f`
    /// proceeds.

    async fn king_compute(
        &mut self,
        bytes: &[u8],
        f: impl Fn(Vec<Vec<u8>>) -> Vec<Vec<u8>> + Send,
    ) -> Vec<u8> {
        let king_response = self.send_bytes_to_king(bytes).await.map(f);
        self.recv_bytes_from_king(king_response).await
    }
}
