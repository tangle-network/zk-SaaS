use log::debug;
use std::error::Error;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ark_std::{end_timer, start_timer};
use async_trait::async_trait;
use futures::stream::FuturesOrdered;
use futures::StreamExt;

use super::{MpcNet, Stats};

/// Macro for locking the FieldChannel singleton in the current scope.

#[derive(Debug)]
struct Peer {
    _id: usize,
    addr: SocketAddr,
    stream: Option<TcpStream>,
}

#[derive(Default, Debug)]
struct Connections {
    id: usize,
    peers: Vec<Peer>,
    stats: Stats,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            _id: 0,
            addr: "127.0.0.1:8000".parse().unwrap(),
            stream: None,
        }
    }
}

impl Connections {
    /// Given a path and the `id` of oneself, initialize the structure
    async fn init_from_path(&mut self, path: &str, id: usize) {
        let f = tokio::fs::read_to_string(path)
            .await
            .unwrap_or_else(|e| panic!("Could not read file {}: {}", path, e));
        for (peer_id, line) in f.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                let addr: SocketAddr = trimmed.parse().unwrap_or_else(|e| {
                    panic!("bad socket address: {}:\n{}", trimmed, e)
                });
                let peer = Peer {
                    _id: peer_id,
                    addr,
                    stream: None,
                };
                self.peers.push(peer);
            }
        }
        assert!(id < self.peers.len());
        self.id = id;
    }
    async fn connect_to_all(&mut self) {
        let timer = start_timer!(|| "Connecting");
        let n = self.peers.len();
        for from_id in 0..n {
            for to_id in (from_id + 1)..n {
                debug!("{} to {}", from_id, to_id);
                if self.id == from_id {
                    let to_addr = self.peers[to_id].addr;
                    debug!("Contacting {}", to_id);
                    let stream = loop {
                        let mut ms_waited = 0;
                        match TcpStream::connect(to_addr).await {
                            Ok(s) => break s,
                            Err(e) => match e.kind() {
                                std::io::ErrorKind::ConnectionRefused
                                | std::io::ErrorKind::ConnectionReset => {
                                    ms_waited += 10;
                                    tokio::time::sleep(
                                        std::time::Duration::from_millis(10),
                                    )
                                    .await;
                                    if ms_waited % 3_000 == 0 {
                                        debug!("Still waiting");
                                    } else if ms_waited > 30_000 {
                                        panic!("Could not find peer in 30s");
                                    }
                                }
                                _ => {
                                    panic!(
                                        "Error during FieldChannel::new: {}",
                                        e
                                    );
                                }
                            },
                        }
                    };
                    self.peers[to_id].stream = Some(stream);
                } else if self.id == to_id {
                    debug!("Awaiting {}", from_id);
                    let listener = TcpListener::bind(self.peers[self.id].addr)
                        .await
                        .unwrap();
                    let (stream, _addr) = listener.accept().await.unwrap();
                    self.peers[from_id].stream = Some(stream);
                }
            }
            // Sender for next round waits for note from this sender to prevent race on receipt.
            if from_id + 1 < n {
                if self.id == from_id {
                    self.peers[self.id + 1]
                        .stream
                        .as_mut()
                        .unwrap()
                        .write_all(&[0u8])
                        .await
                        .unwrap();
                } else if self.id == from_id + 1 {
                    self.peers[self.id - 1]
                        .stream
                        .as_mut()
                        .unwrap()
                        .read_exact(&mut [0u8])
                        .await
                        .unwrap();
                }
            }
        }
        // Do a round with the king, to be sure everyone is ready
        let from_all = self.send_to_king(&[self.id as u8]).await;
        self.recv_from_king(from_all).await;
        for id in 0..n {
            if id != self.id {
                assert!(self.peers[id].stream.is_some());
            }
        }
        end_timer!(timer);
    }
    fn am_king(&self) -> bool {
        self.id == 0
    }
    async fn broadcast(&mut self, bytes_out: &[u8]) -> Vec<Vec<u8>> {
        let timer = start_timer!(|| format!("Broadcast {}", bytes_out.len()));
        let m = bytes_out.len();
        let own_id = self.id;
        self.stats.bytes_sent += (self.peers.len() - 1) * m;
        self.stats.bytes_recv += (self.peers.len() - 1) * m;
        self.stats.broadcasts += 1;

        let mut r = FuturesOrdered::default();
        for (id, peer) in self.peers.iter_mut().enumerate() {
            r.push_back(Box::pin(async move {
                let mut bytes_in = vec![0u8; m];

                match id {
                    id if id < own_id => {
                        let stream = peer.stream.as_mut().unwrap();
                        stream.read_exact(&mut bytes_in[..]).await.unwrap();
                        stream.write_all(bytes_out).await.unwrap();
                    }
                    id if id == own_id => {
                        bytes_in.copy_from_slice(bytes_out);
                    }
                    _ => {
                        let stream = peer.stream.as_mut().unwrap();
                        stream.write_all(bytes_out).await.unwrap();
                        stream.read_exact(&mut bytes_in[..]).await.unwrap();
                    }
                }

                bytes_in
            }));
        }

        let r = r.collect().await;
        end_timer!(timer);
        r
    }
    async fn send_to_king(&mut self, bytes_out: &[u8]) -> Option<Vec<Vec<u8>>> {
        let timer = start_timer!(|| format!("To king {}", bytes_out.len()));
        let m = bytes_out.len();
        let own_id = self.id;
        self.stats.to_king += 1;
        let r = if self.am_king() {
            self.stats.bytes_recv += (self.peers.len() - 1) * m;
            let mut r = FuturesOrdered::new();
            for (id, peer) in self.peers.iter_mut().enumerate() {
                r.push_back(Box::pin(async move {
                    let mut bytes_in = vec![0u8; m];
                    if id == own_id {
                        bytes_in.copy_from_slice(bytes_out);
                    } else {
                        let stream = peer.stream.as_mut().unwrap();
                        stream.read_exact(&mut bytes_in[..]).await.unwrap();
                    };
                    bytes_in
                }));
            }
            Some(r.collect().await)
        } else {
            self.stats.bytes_sent += m;
            self.peers[0]
                .stream
                .as_mut()
                .unwrap()
                .write_all(bytes_out)
                .await
                .unwrap();
            None
        };
        end_timer!(timer);
        r
    }

    async fn recv_from_king(
        &mut self,
        bytes_out: Option<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        let own_id = self.id;
        self.stats.from_king += 1;
        if self.am_king() {
            let bytes_out = bytes_out.unwrap();
            let m = bytes_out[0].len();
            let timer = start_timer!(|| format!("From king {}", m));
            let bytes_size = (m as u64).to_le_bytes();
            self.stats.bytes_sent += (self.peers.len() - 1) * (m + 8);

            for (id, peer) in
                self.peers.iter_mut().enumerate().filter(|p| p.0 != own_id)
            {
                let stream = peer.stream.as_mut().unwrap();
                assert_eq!(bytes_out[id].len(), m);
                stream.write_all(&bytes_size).await.unwrap();
                stream.write_all(&bytes_out[id]).await.unwrap();
            }

            end_timer!(timer);
            bytes_out[own_id].clone()
        } else {
            let stream = self.peers[0].stream.as_mut().unwrap();
            let mut bytes_size = [0u8; 8];
            stream.read_exact(&mut bytes_size).await.unwrap();
            let m = u64::from_le_bytes(bytes_size) as usize;
            self.stats.bytes_recv += m;
            let mut bytes_in = vec![0u8; m];
            stream.read_exact(&mut bytes_in).await.unwrap();
            bytes_in
        }
    }
    fn uninit(&mut self) {
        for p in &mut self.peers {
            p.stream = None;
        }
    }
}

pub struct MpcMultiNet {
    connections: Connections,
}

impl MpcMultiNet {
    pub async fn new_local_testnet(
        n_parties: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let mut connections = Connections::default();
        for party_id in 0..n_parties {
            let addr = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
            connections.peers.push(Peer {
                _id: party_id,
                addr,
                stream: None,
            });
        }
        Ok(Self { connections })
    }

    pub async fn new_from_path(
        path: &str,
        party_id: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let mut connections = Connections::default();
        connections.init_from_path(path, party_id).await;
        Ok(Self { connections })
    }
}

#[async_trait]
impl MpcNet for MpcMultiNet {
    fn n_parties(&self) -> usize {
        self.connections.peers.len()
    }

    fn party_id(&self) -> usize {
        self.connections.id
    }

    async fn init(&mut self) {
        self.connections.connect_to_all().await;
    }

    fn is_init(&self) -> bool {
        self.connections
            .peers
            .first()
            .map(|p| p.stream.is_some())
            .unwrap_or(false)
    }

    fn deinit(&mut self) {
        self.connections.uninit()
    }

    fn reset_stats(&mut self) {
        self.connections.stats = Stats::default();
    }

    fn stats(&self) -> &Stats {
        &self.connections.stats
    }

    async fn broadcast_bytes(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.connections.broadcast(bytes).await
    }

    async fn send_bytes_to_king(
        &mut self,
        bytes: &[u8],
    ) -> Option<Vec<Vec<u8>>> {
        self.connections.send_to_king(bytes).await
    }

    async fn recv_bytes_from_king(
        &mut self,
        bytes: Option<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        self.connections.recv_from_king(bytes).await
    }
}
