use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ark_std::{end_timer, start_timer};
use async_trait::async_trait;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::StreamExt;
use parking_lot::Mutex;

use super::{MpcNet, Stats};

#[derive(Debug)]
struct Peer {
    id: usize,
    addr: SocketAddr,
    stream: Option<TcpStream>,
}

impl Clone for Peer {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            addr: self.addr,
            stream: None,
        }
    }
}

#[derive(Default, Debug)]
pub struct Connections {
    id: usize,
    listener: Option<TcpListener>,
    peers: HashMap<usize, Peer>,
    stats: Stats,
}

impl Connections {
    async fn connect_to_all(&mut self) {
        let timer = start_timer!(|| "Connecting");
        let n_minus_1 = self.n_parties() - 1;
        let my_id = self.id;

        let peer_addrs = self.peers.iter().map(|p| (p.1.addr, *p.0)).collect::<HashMap<_, _>>();
        let peer_addrs_reversed = peer_addrs.clone().into_iter().map(|r| (r.1, r.0)).collect::<HashMap<_, _>>();

        let listener = self.listener.take().unwrap();
        let new_peers = Arc::new(Mutex::new(self.peers.clone()));
        let new_peers_server = new_peers.clone();
        let new_peers_client = new_peers.clone();

        // my_id = 0, n_minus_1 = 2
        // outbound_connections_i_will_make = 2
        // my_id = 1, n_minus_1 = 2
        // outbound_connections_i_will_make = 1
        // my_id = 2, n_minus_1 = 2
        // outbound_connections_i_will_make = 0
        let outbound_connections_i_will_make = n_minus_1 - my_id;
        let inbound_connections_i_will_make = my_id;

        let server_task = async move {
            for _ in 0..inbound_connections_i_will_make {
                let (stream, peer_addr) = listener.accept().await.unwrap();
                println!("{my_id} accepted connection from {peer_addr}");
                println!("Peer addrs: {:?}", peer_addrs);
                let peer_id = peer_addrs.get(&peer_addr).copied().unwrap();
                new_peers_server.lock().get_mut(&peer_id).unwrap().stream = Some(stream);
                println!("{my_id} connected to peer {peer_id}")
            }
        };

        let client_task = async move {
            // Wait some time for the server tasks to boot up
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Listeners are all active, now, connect us to n-1 peers
            let mut conns_made = 0;
            for _ in 0..outbound_connections_i_will_make {
                // If I am 0, I will connect to 1 and 2
                // If I am 1, I will connect to 2
                // If I am 2, I will connect to no one (server will make the connections)
                let next_peer_to_connect_to = my_id + conns_made + 1;
                let peer_addr = peer_addrs_reversed.get(&next_peer_to_connect_to).unwrap();
                let stream = TcpStream::connect(peer_addr).await.unwrap();
                new_peers_client.lock().get_mut(&next_peer_to_connect_to).unwrap().stream = Some(stream);
                conns_made += 1;
                println!("{my_id} connected to peer {next_peer_to_connect_to}")
            }
        };

        println!("Awaiting on client and server task to finish");

        tokio::join!(server_task, client_task);
        self.peers = Arc::try_unwrap(new_peers).unwrap().into_inner();

        println!("All connected");

        // Do a round with the king, to be sure everyone is ready
        let from_all = self.send_to_king(&[self.id as u8]).await;
        self.recv_from_king(from_all).await;
        for peer in &self.peers {
            assert!(peer.1.stream.is_some());
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
        self.stats.bytes_sent += self.peers.len() * m;
        self.stats.bytes_recv += self.peers.len() * m;
        self.stats.broadcasts += 1;

        let mut r = FuturesOrdered::default();
        for (id, peer) in self.peers.iter_mut() {
            r.push_back(Box::pin(async move {
                let mut bytes_in = vec![0u8; m];

                match *id {
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
            self.stats.bytes_recv += self.peers.len() * m;
            let mut r = FuturesOrdered::new();
            for (id, peer) in self.peers.iter_mut(){
                r.push_back(Box::pin(async move {
                    let mut bytes_in = vec![0u8; m];
                    if *id == own_id {
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
            self.peers
                .get_mut(&0)
                .unwrap()
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
            self.stats.bytes_sent += self.peers.len() * (m + 8);

            for (id, peer) in
                self.peers.iter_mut().filter(|p| *p.0 != own_id)
            {
                let stream = peer.stream.as_mut().unwrap();
                assert_eq!(bytes_out[*id].len(), m);
                stream.write_all(&bytes_size).await.unwrap();
                stream.write_all(&bytes_out[*id]).await.unwrap();
            }

            end_timer!(timer);
            bytes_out[own_id].clone()
        } else {
            let stream = self.peers.get_mut(&0).unwrap().stream.as_mut().unwrap();
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
            p.1.stream = None;
        }
    }
}

pub struct LocalTestNet {
    nodes: HashMap<usize, Connections>,
}

impl LocalTestNet {
    pub async fn new_local_testnet(
        n_parties: usize,
    ) -> Result<Self, Box<dyn Error>> {
        // Step 1: Generate all the Listeners for each node
        let mut listeners = HashMap::new();
        let mut listen_addrs = HashMap::new();
        for party_id in 0..n_parties {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            listen_addrs.insert(party_id, listener.local_addr()?);
            listeners.insert(party_id, listener);
        }

        // Step 2: populate the nodes with peer metadata (do NOT init the connections yet)
        let mut nodes = HashMap::new();
        for (my_party_id, my_listener) in listeners.into_iter() {
            let mut connections = Connections {
                id: my_party_id,
                listener: Some(my_listener),
                peers: Default::default(),
                stats: Default::default(),
            };
            for peer_id in 0..n_parties {
                if peer_id != my_party_id {
                    let peer_addr = listen_addrs.get(&peer_id).copied().unwrap();
                    connections.peers.insert(peer_id, Peer {
                        id: peer_id,
                        addr: peer_addr,
                        stream: None,
                    });
                }
            }

            nodes.insert(my_party_id, connections);
        }

        // Step 3: Connect peers to each other
        println!("Now running init");
        let futures = FuturesUnordered::new();
        for (peer_id, mut connections) in nodes.into_iter() {
            futures.push(Box::pin(async move {
                connections.connect_to_all().await;
                (peer_id, connections)
            }));
        }

        let nodes = futures.collect().await;

        Ok(Self { nodes })
    }

    // For each node, run a function (a Future) provided by the parameter that accepts the node's Connection.
    // Then, run all these futures in a FuturesOrdered.
    pub async fn simulate_network_round<'a, 'b: 'a, F: Future<Output=K> + Send + Sync, K: Send + Sync + 'b>(
        &'a mut self,
        f: impl Fn(&'a mut Connections) -> F + Send + Sync + Clone,
    ) -> Vec<K> {
        let mut futures = FuturesOrdered::new();
        for (_, connections) in self.nodes.iter_mut() {
            let next_f = f.clone();
            futures.push_back(Box::pin(async move { next_f(connections).await }));
        }
        futures.collect().await
    }
}

#[async_trait]
impl MpcNet for Connections {
    fn n_parties(&self) -> usize {
        // We do not include ourself in the peers list, so add 1
        self.peers.len() + 1
    }

    fn party_id(&self) -> usize {
        self.id
    }

    fn is_init(&self) -> bool {
        self
            .peers
            .iter()
            .all(|r| r.1.stream.is_some())
    }

    fn deinit(&mut self) {
        self.uninit()
    }

    fn reset_stats(&mut self) {
        self.stats = Stats::default();
    }

    fn stats(&self) -> &Stats {
        &self.stats
    }

    async fn broadcast_bytes(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.broadcast(bytes).await
    }

    async fn send_bytes_to_king(
        &mut self,
        bytes: &[u8],
    ) -> Option<Vec<Vec<u8>>> {
        self.send_to_king(bytes).await
    }

    async fn recv_bytes_from_king(
        &mut self,
        bytes: Option<Vec<Vec<u8>>>,
    ) -> Vec<u8> {
        self.recv_from_king(bytes).await
    }
}
