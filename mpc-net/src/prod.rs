use crate::multi::{
    multiplex_stream, MpcNetConnection, Peer, WrappedMuxStream,
    MULTIPLEXED_STREAMS,
};
use crate::{MpcNet, MpcNetError, MultiplexedStreamID, Stats};
use async_trait::async_trait;
use futures::SinkExt;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::bytes::Bytes;

pub struct ProdNet {
    /// The king will have a connection to each party, and each party will have a connection to the king.
    /// Thus, if this node is a king, there will be n_parties connections below. If this node is not a king,
    /// then, where will be only a single connection to the thing with ID 0
    connections: MpcNetConnection,
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub enum ProtocolPacket {
    Syn,
    SynAck,
    Packet(Vec<u8>),
}

impl ProdNet {
    /// Returns when all the parties have connected.
    pub async fn new_king<T: ToSocketAddrs>(
        bind_addr: SocketAddr,
        n_peers: usize,
    ) -> Result<Self, MpcNetError> {
        let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await?;

        let mut connections = MpcNetConnection {
            id: 0,
            listener: None,
            peers: Default::default(),
            stats: Default::default(),
        };

        for _ in 0..n_peers {
            let (mut stream, _) = tcp_listener.accept().await?;
            let peer_addr = stream.peer_addr()?;
            let peer_id = stream.read_u32().await?;
            // Now, multiplex the stream
            let muxed =
                multiplex_stream(MULTIPLEXED_STREAMS, true, stream).await?;
            connections.peers.insert(
                peer_id,
                Peer {
                    id: peer_id,
                    listen_addr: peer_addr,
                    streams: Some(muxed),
                },
            );
        }

        // Broadcast to each peer a SYN packet
        for conn in connections.peers.values_mut() {
            send_packet(
                conn.streams.as_mut(),
                MultiplexedStreamID::Zero,
                ProtocolPacket::Syn,
            )
            .await?;
        }

        // Wait for n_parties count of SynAck packets
        for conn in connections.peers.values_mut() {
            let packet =
                recv_packet(conn.streams.as_mut(), MultiplexedStreamID::Zero)
                    .await?;
            if packet != ProtocolPacket::SynAck {
                return Err(MpcNetError::Protocol {
                    err: "Did not receive SynAck".to_string(),
                    party: conn.id,
                });
            }
        }

        Ok(Self { connections })
    }

    pub async fn new_peer(
        id: u32,
        king: SocketAddr,
    ) -> Result<Self, MpcNetError> {
        let mut stream = TcpStream::connect(king).await?;
        stream.write_u32(id).await?;
        let muxed =
            multiplex_stream(MULTIPLEXED_STREAMS, false, stream).await?;
        let mut connections = MpcNetConnection {
            id,
            listener: None,
            peers: Default::default(),
            stats: Default::default(),
        };
        connections.peers.insert(
            0,
            Peer {
                id: 0,
                listen_addr: king,
                streams: Some(muxed),
            },
        );

        // Wait for a Syn packet
        let packet = recv_packet(
            connections.peers.get_mut(&0).unwrap().streams.as_mut(),
            MultiplexedStreamID::Zero,
        )
        .await?;
        if packet != ProtocolPacket::Syn {
            return Err(MpcNetError::Protocol {
                err: "Did not receive Syn".to_string(),
                party: 0,
            });
        }

        // Send a SynAck packet to party_id=0
        send_packet(
            connections.peers.get_mut(&0).unwrap().streams.as_mut(),
            MultiplexedStreamID::Zero,
            ProtocolPacket::SynAck,
        )
        .await?;

        Ok(Self { connections })
    }
}

#[async_trait]
impl MpcNet for ProdNet {
    fn n_parties(&self) -> usize {
        self.connections.n_parties()
    }

    fn party_id(&self) -> u32 {
        self.connections.party_id()
    }

    fn is_init(&self) -> bool {
        self.connections.is_init()
    }

    fn deinit(&mut self) {
        self.connections.deinit()
    }

    fn reset_stats(&mut self) {
        self.connections.reset_stats()
    }

    fn stats(&self) -> &Stats {
        self.connections.stats()
    }

    async fn broadcast_bytes(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Vec<Vec<u8>>, MpcNetError> {
        self.connections.broadcast_bytes(bytes, sid).await
    }

    async fn send_bytes_to_king(
        &mut self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Vec<u8>>>, MpcNetError> {
        self.connections.send_bytes_to_king(bytes, sid).await
    }

    async fn recv_bytes_from_king(
        &mut self,
        bytes: Option<Vec<Vec<u8>>>,
        sid: MultiplexedStreamID,
    ) -> Result<Vec<u8>, MpcNetError> {
        self.connections.recv_bytes_from_king(bytes, sid).await
    }
}

async fn send_packet(
    streams: Option<&mut Vec<WrappedMuxStream<TcpStream>>>,
    sid: MultiplexedStreamID,
    packet: ProtocolPacket,
) -> Result<(), MpcNetError> {
    let stream = streams.ok_or(MpcNetError::NotConnected)?;
    let stream = stream
        .get_mut(sid as usize)
        .ok_or(MpcNetError::NotConnected)?;
    let packet = bincode2::serialize(&packet)?;
    stream.send(Bytes::from(packet)).await?;
    Ok(())
}

async fn recv_packet(
    streams: Option<&mut Vec<WrappedMuxStream<TcpStream>>>,
    sid: MultiplexedStreamID,
) -> Result<ProtocolPacket, MpcNetError> {
    let stream = streams.ok_or(MpcNetError::NotConnected)?;
    let stream = stream
        .get_mut(sid as usize)
        .ok_or(MpcNetError::NotConnected)?;
    let packet = stream.next().await.ok_or(MpcNetError::NotConnected)??;
    let packet = bincode2::deserialize(&packet)?;
    Ok(packet)
}
