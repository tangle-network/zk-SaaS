use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{MpcNetError, MultiplexedStreamID};
use ark_std::{end_timer, start_timer};
use async_smux::{MuxBuilder, MuxStream};
use async_trait::async_trait;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{SinkExt, StreamExt, TryStreamExt};
use parking_lot::Mutex;
use tokio_util::bytes::Bytes;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use super::{MpcNet, Stats};

pub type WrappedStream<T> = Framed<T, LengthDelimitedCodec>;

fn wrap_stream<T: AsyncRead + AsyncWrite>(
    stream: T,
) -> Framed<T, LengthDelimitedCodec> {
    LengthDelimitedCodec::builder()
        .big_endian()
        .length_field_type::<u32>()
        .new_framed(stream)
}

pub struct Peer {
    pub id: u32,
    pub listen_addr: SocketAddr,
    pub streams: Option<Vec<WrappedMuxStream<TcpStream>>>,
}

impl Debug for Peer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_struct("Peer");
        f.field("id", &self.id);
        f.field("listen_addr", &self.listen_addr);
        f.field("streams", &self.streams.is_some());
        f.finish()
    }
}

impl Clone for Peer {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            listen_addr: self.listen_addr,
            streams: None,
        }
    }
}

pub type WrappedMuxStream<T> = Framed<MuxStream<T>, LengthDelimitedCodec>;
pub const MULTIPLEXED_STREAMS: usize = 3;

/// Should be called immediately after making a connection to a peer.
pub async fn multiplex_stream<
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
>(
    channels: usize,
    is_server: bool,
    stream: T,
) -> Result<Vec<WrappedMuxStream<T>>, MpcNetError> {
    if is_server {
        let (_connector, mut acceptor, worker) =
            MuxBuilder::server().with_connection(stream).build();
        tokio::spawn(worker);
        let mut ret = Vec::new();
        for _ in 0..channels {
            ret.push(wrap_stream(acceptor.accept().await.ok_or_else(
                || {
                    MpcNetError::Generic(
                        "Error accepting connection".to_string(),
                    )
                },
            )?));
        }

        Ok(ret)
    } else {
        let (connector, _acceptor, worker) =
            MuxBuilder::client().with_connection(stream).build();
        tokio::spawn(worker);
        let mut ret = Vec::new();
        for _ in 0..channels {
            ret.push(wrap_stream(connector.connect()?));
        }

        Ok(ret)
    }
}

#[derive(Default, Debug)]
pub struct MpcNetConnection {
    pub id: u32,
    pub listener: Option<TcpListener>,
    pub peers: HashMap<u32, Peer>,
    pub stats: Stats,
}

impl MpcNetConnection {
    async fn connect_to_all(&mut self) -> Result<(), MpcNetError> {
        let timer = start_timer!(|| "Connecting");
        let n_minus_1 = self.n_parties() - 1;
        let my_id = self.id;

        let peer_addrs = self
            .peers
            .iter()
            .map(|p| (*p.0, p.1.listen_addr))
            .collect::<HashMap<_, _>>();

        let listener = self.listener.take().expect("TcpListener is None");
        let new_peers = Arc::new(Mutex::new(self.peers.clone()));
        let new_peers_server = new_peers.clone();
        let new_peers_client = new_peers.clone();

        // my_id = 0, n_minus_1 = 2
        // outbound_connections_i_will_make = 2
        // my_id = 1, n_minus_1 = 2
        // outbound_connections_i_will_make = 1
        // my_id = 2, n_minus_1 = 2
        // outbound_connections_i_will_make = 0
        let outbound_connections_i_will_make = n_minus_1 - (my_id as usize);
        let inbound_connections_i_will_make = my_id as usize;

        let server_task = async move {
            for _ in 0..inbound_connections_i_will_make {
                let (mut stream, _peer_addr) =
                    listener.accept().await.map_err(|err| {
                        MpcNetError::Generic(format!(
                            "Error accepting connection: {err:?}"
                        ))
                    })?;

                let peer_id = stream.read_u32().await?;
                // Now, multiplex the stream
                let muxed =
                    multiplex_stream(MULTIPLEXED_STREAMS, true, stream).await?;
                new_peers_server.lock().get_mut(&peer_id).unwrap().streams =
                    Some(muxed);
                println!("{my_id} connected to peer {peer_id}")
            }

            Ok::<_, MpcNetError>(())
        };

        let client_task = async move {
            // Wait some time for the server tasks to boot up
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Listeners are all active, now, connect us to n-1 peers
            for conns_made in 0..outbound_connections_i_will_make {
                // If I am 0, I will connect to 1 and 2
                // If I am 1, I will connect to 2
                // If I am 2, I will connect to no one (server will make the connections)
                let next_peer_to_connect_to = my_id + conns_made as u32 + 1;
                let peer_listen_addr =
                    peer_addrs.get(&next_peer_to_connect_to).unwrap();
                let mut stream =
                    TcpStream::connect(peer_listen_addr).await.map_err(|err| {
                        MpcNetError::Generic(format!(
                            "Error connecting to peer {next_peer_to_connect_to}: {err:?}"
                        ))
                    })?;
                stream.write_u32(my_id).await.unwrap();

                let muxed =
                    multiplex_stream(MULTIPLEXED_STREAMS, false, stream)
                        .await?;
                new_peers_client
                    .lock()
                    .get_mut(&next_peer_to_connect_to)
                    .unwrap()
                    .streams = Some(muxed);
                println!("{my_id} connected to peer {next_peer_to_connect_to}")
            }

            Ok::<_, MpcNetError>(())
        };

        println!("Awaiting on client and server task to finish");

        tokio::try_join!(server_task, client_task)?;
        self.peers = Arc::try_unwrap(new_peers).unwrap().into_inner();

        println!("All connected");

        // Every party will use this channel for genesis
        let genesis_round_channel = MultiplexedStreamID::One;

        // Do a round with the king, to be sure everyone is ready
        let from_all = self
            .send_to_king(&[self.id as u8], genesis_round_channel)
            .await?;
        self.recv_from_king(from_all, genesis_round_channel).await?;

        for peer in &self.peers {
            if peer.0 == &self.id {
                continue;
            }

            if peer.1.streams.is_none() {
                return Err(MpcNetError::Generic(format!(
                    "Peer {} has no stream",
                    peer.0
                )));
            }
        }

        println!("Done with recv_from_king");

        end_timer!(timer);
        Ok(())
    }

    fn am_king(&self) -> bool {
        self.id == 0
    }

    async fn broadcast(
        &mut self,
        bytes_out: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Vec<Vec<u8>>, MpcNetError> {
        let timer = start_timer!(|| format!("Broadcast {}", bytes_out.len()));
        let bytes_out: Bytes = bytes_out.to_vec().into();
        let m = bytes_out.len();
        let own_id = self.id;
        self.stats.bytes_sent += self.peers.len() * m;
        self.stats.bytes_recv += self.peers.len() * m;
        self.stats.broadcasts += 1;

        let mut r = FuturesOrdered::default();
        for (id, peer) in self.peers.iter_mut() {
            let bytes_out = bytes_out.clone();
            r.push_back(Box::pin(async move {
                // TODO: optimize this
                let bytes_in = match *id {
                    id if id < own_id => {
                        let ret =
                            recv_stream(peer.streams.as_mut(), sid).await?;
                        send_stream(peer.streams.as_mut(), bytes_out, sid)
                            .await?;
                        ret.to_vec()
                    }
                    id if id == own_id => bytes_out.to_vec(),
                    _ => {
                        send_stream(peer.streams.as_mut(), bytes_out, sid)
                            .await?;
                        recv_stream(peer.streams.as_mut(), sid).await?.to_vec()
                    }
                };

                Ok(bytes_in)
            }));
        }

        let r = r.try_collect::<Vec<Vec<u8>>>().await;
        end_timer!(timer);
        r
    }

    // If we are the king, we receive all the packets
    // If we are not the king, we send our packet to the king
    async fn send_to_king(
        &mut self,
        bytes_out: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Vec<u8>>>, MpcNetError> {
        let timer = start_timer!(|| format!("To king {}", bytes_out.len()));
        let bytes_out: Bytes = bytes_out.to_vec().into();
        let m = bytes_out.len();
        let own_id = self.id;
        self.stats.to_king += 1;
        let r = if self.am_king() {
            self.stats.bytes_recv += self.peers.len() * m;
            let mut r = FuturesOrdered::new();

            for (id, peer) in self.peers.iter_mut() {
                let bytes_out: Bytes = bytes_out.clone();
                r.push_back(Box::pin(async move {
                    // TODO: optimize this
                    let bytes_in = if *id == own_id {
                        bytes_out.to_vec()
                    } else {
                        recv_stream(peer.streams.as_mut(), sid).await?.to_vec()
                    };

                    Ok::<_, MpcNetError>(bytes_in)
                }));
            }

            Ok(Some(r.try_collect::<Vec<Vec<u8>>>().await?))
        } else {
            self.stats.bytes_sent += m;
            let stream = self.peers.get_mut(&0).unwrap().streams.as_mut();
            send_stream(stream, bytes_out, sid).await?;
            Ok(None)
        };
        end_timer!(timer);
        r
    }

    async fn recv_from_king(
        &mut self,
        bytes_out: Option<Vec<Vec<u8>>>,
        sid: MultiplexedStreamID,
    ) -> Result<Vec<u8>, MpcNetError> {
        let own_id = self.id;
        self.stats.from_king += 1;
        if self.am_king() {
            let bytes_out = bytes_out.unwrap();
            let m = bytes_out[0].len();
            let timer = start_timer!(|| format!("From king {}", m));
            self.stats.bytes_sent += self.peers.len() * (m + 8);

            for (id, peer) in self.peers.iter_mut().filter(|p| *p.0 != own_id) {
                if bytes_out[*id as usize].len() != m {
                    return Err(MpcNetError::Protocol {
                        err: format!("Peer {} sent wrong number of bytes", id),
                        party: *id,
                    });
                }

                send_stream(
                    peer.streams.as_mut(),
                    bytes_out[*id as usize].clone().into(),
                    sid,
                )
                .await?;
            }

            end_timer!(timer);
            Ok(bytes_out[own_id as usize].clone())
        } else {
            let stream = self.peers.get_mut(&0).unwrap().streams.as_mut();
            let ret = recv_stream(stream, sid).await?;
            self.stats.bytes_recv += ret.len();
            Ok(ret.into())
        }
    }

    fn uninit(&mut self) {
        for p in &mut self.peers {
            p.1.streams = None;
        }
    }
}

pub struct LocalTestNet {
    nodes: HashMap<usize, MpcNetConnection>,
}

impl LocalTestNet {
    pub async fn new_local_testnet(
        n_parties: usize,
    ) -> Result<Self, MpcNetError> {
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
            let mut connections = MpcNetConnection {
                id: my_party_id as u32,
                listener: Some(my_listener),
                peers: Default::default(),
                stats: Default::default(),
            };
            for peer_id in 0..n_parties {
                // NOTE: this is the listen addr
                let peer_addr = listen_addrs.get(&peer_id).copied().unwrap();
                connections.peers.insert(
                    peer_id as u32,
                    Peer {
                        id: peer_id as u32,
                        listen_addr: peer_addr,
                        streams: None,
                    },
                );
            }

            nodes.insert(my_party_id, connections);
        }

        // Step 3: Connect peers to each other
        println!("Now running init");
        let futures = FuturesUnordered::new();
        for (peer_id, mut connections) in nodes.into_iter() {
            futures.push(Box::pin(async move {
                connections.connect_to_all().await?;
                Ok::<_, MpcNetError>((peer_id, connections))
            }));
        }

        let nodes = futures.try_collect().await?;

        Ok(Self { nodes })
    }

    // For each node, run a function (a Future) provided by the parameter that accepts the node's Connection.
    // Then, run all these futures in a FuturesOrdered.
    pub async fn simulate_network_round<
        F: Future<Output = K> + Send,
        K: Send + Sync + 'static,
    >(
        self,
        f: impl Fn(MpcNetConnection) -> F + Send + Sync + Clone + 'static,
    ) -> Vec<K> {
        let mut futures = FuturesOrdered::new();
        for (_, connections) in self.nodes.into_iter() {
            let next_f = f.clone();
            futures.push_back(Box::pin(async move {
                let task = async move { next_f(connections).await };
                let handle = tokio::task::spawn(task);
                handle.await.unwrap()
            }));
        }
        futures.collect().await
    }
}

#[async_trait]
impl MpcNet for MpcNetConnection {
    fn n_parties(&self) -> usize {
        self.peers.len()
    }

    fn party_id(&self) -> u32 {
        self.id
    }

    fn is_init(&self) -> bool {
        self.peers.iter().all(|r| r.1.streams.is_some())
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

    async fn broadcast_bytes(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Vec<Vec<u8>>, MpcNetError> {
        self.broadcast(bytes, sid).await
    }

    async fn send_bytes_to_king(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Vec<u8>>>, MpcNetError> {
        self.send_to_king(bytes, sid).await
    }

    async fn recv_bytes_from_king(
        &mut self,
        bytes: Option<Vec<Vec<u8>>>,
        sid: MultiplexedStreamID,
    ) -> Result<Vec<u8>, MpcNetError> {
        self.recv_from_king(bytes, sid).await
    }
}

async fn send_stream<T: AsyncRead + AsyncWrite + Unpin>(
    stream: Option<&mut Vec<WrappedStream<T>>>,
    bytes: Bytes,
    sid: MultiplexedStreamID,
) -> Result<(), MpcNetError> {
    if let Some(stream) = stream.and_then(|r| r.get_mut(sid as usize)) {
        Ok(stream.send(bytes).await?)
    } else {
        Err(MpcNetError::Generic("Stream is None".to_string()))
    }
}

async fn recv_stream<T: AsyncRead + AsyncWrite + Unpin>(
    stream: Option<&mut Vec<WrappedStream<T>>>,
    sid: MultiplexedStreamID,
) -> Result<Bytes, MpcNetError> {
    if let Some(stream) = stream.and_then(|r| r.get_mut(sid as usize)) {
        Ok(stream
            .next()
            .await
            .ok_or_else(|| MpcNetError::Generic("Stream died".to_string()))??
            .freeze())
    } else {
        Err(MpcNetError::Generic("Stream is None".to_string()))
    }
}
