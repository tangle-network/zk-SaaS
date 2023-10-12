use crate::multi::{
    multiplex_stream, MpcNetConnection, Peer, WrappedMuxStream,
    MULTIPLEXED_STREAMS,
};
use crate::{MpcNet, MpcNetError, MultiplexedStreamID, Stats};
use async_trait::async_trait;
use futures::SinkExt;
use futures::StreamExt;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_util::bytes::Bytes;

pub trait CertToDer {
    fn serialize_certificate_to_der(&self) -> Result<Vec<u8>, MpcNetError>;
    fn serialize_private_key_to_der(&self) -> Result<Vec<u8>, MpcNetError>;
}

#[derive(Clone)]
pub struct RustlsCertificate {
    cert: rustls::Certificate,
    private_key: rustls::PrivateKey,
}

impl CertToDer for RustlsCertificate {
    fn serialize_certificate_to_der(&self) -> Result<Vec<u8>, MpcNetError> {
        Ok(self.cert.0.clone())
    }

    fn serialize_private_key_to_der(&self) -> Result<Vec<u8>, MpcNetError> {
        Ok(self.private_key.0.clone())
    }
}

pub fn create_server_mutual_tls_acceptor<T: CertToDer>(
    client_certs: RootCertStore,
    server_certificate: T,
) -> Result<TlsAcceptor, MpcNetError> {
    let client_auth = AllowAnyAuthenticatedClient::new(client_certs);
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(Arc::new(client_auth))
        .with_single_cert(
            vec![rustls::Certificate(
                server_certificate.serialize_certificate_to_der()?,
            )],
            rustls::PrivateKey(
                server_certificate.serialize_private_key_to_der()?,
            ),
        )
        .unwrap();
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

pub fn create_client_mutual_tls_connector<T: CertToDer>(
    server_certs: RootCertStore,
    client_certificate: T,
) -> Result<tokio_rustls::TlsConnector, MpcNetError> {
    let client_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(server_certs)
        .with_client_auth_cert(
            vec![rustls::Certificate(
                client_certificate.serialize_certificate_to_der()?,
            )],
            rustls::PrivateKey(
                client_certificate.serialize_private_key_to_der()?,
            ),
        )
        .unwrap();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

pub struct ProdNet {
    /// The king will have a connection to each party, and each party will have a connection to the king.
    /// Thus, if this node is a king, there will be n_parties connections below. If this node is not a king,
    /// then, where will be only a single connection to the thing with ID 0
    connections: MpcNetConnection<TlsStream<TcpStream>>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub enum ProtocolPacket {
    Syn,
    SynAck,
    Packet(Vec<u8>),
}

impl ProdNet {
    /// Returns when all the parties have connected.
    pub async fn new_king<T: ToSocketAddrs, R: CertToDer>(
        bind_addr: T,
        identity: R,
        client_certs: RootCertStore,
    ) -> Result<Self, MpcNetError> {
        let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let n_peers = client_certs.len();
        let tls_acceptor =
            create_server_mutual_tls_acceptor(client_certs, identity)?;

        let mut connections = MpcNetConnection {
            id: 0,
            listener: None,
            peers: Default::default(),
            stats: Default::default(),
        };

        for _ in 0..n_peers {
            let (stream, _) = tcp_listener.accept().await?;
            let peer_addr = stream.peer_addr()?;
            let mut stream =
                TlsStream::Server(tls_acceptor.accept(stream).await?);
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

    pub async fn new_peer<R: CertToDer>(
        id: u32,
        king: SocketAddr,
        identity: R,
        server_cert: RootCertStore,
    ) -> Result<Self, MpcNetError> {
        let stream = TcpStream::connect(king).await?;
        let tls_connector =
            create_client_mutual_tls_connector(server_cert, identity)?;
        let mut stream = TlsStream::Client(
            tls_connector
                .connect(rustls::ServerName::IpAddress(king.ip()), stream)
                .await?,
        );
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
    streams: Option<&mut Vec<WrappedMuxStream<TlsStream<TcpStream>>>>,
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
    streams: Option<&mut Vec<WrappedMuxStream<TlsStream<TcpStream>>>>,
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

#[cfg(test)]
mod test {
    use super::*;
    use futures::stream::FuturesUnordered;
    use futures::{TryFutureExt, TryStreamExt};
    use tokio::net::TcpListener;

    use rcgen::{Certificate, CertificateParams, RcgenError};

    impl CertToDer for Certificate {
        fn serialize_certificate_to_der(&self) -> Result<Vec<u8>, MpcNetError> {
            Ok(self.serialize_der().unwrap())
        }
        fn serialize_private_key_to_der(&self) -> Result<Vec<u8>, MpcNetError> {
            Ok(self.serialize_private_key_der())
        }
    }

    fn generate_self_signed_cert() -> Result<Certificate, RcgenError> {
        let params = CertificateParams::new(vec!["localhost".to_string()]);
        let cert = Certificate::from_params(params)?;
        Ok(cert)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_network_init() {
        const N_PEERS: usize = 4;
        let king_addr = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let server_identity = generate_self_signed_cert().unwrap();
        let server_identity = RustlsCertificate {
            cert: rustls::Certificate(server_identity.serialize_der().unwrap()),
            private_key: rustls::PrivateKey(
                server_identity.serialize_private_key_der(),
            ),
        };

        let mut server_cert = RootCertStore::empty();
        server_cert.add(&server_identity.cert).unwrap();

        let mut client_certs = RootCertStore::empty();
        let mut client_identities = Vec::new();
        for _ in 0..N_PEERS {
            let peer_identity = generate_self_signed_cert().unwrap();
            let peer_identity = RustlsCertificate {
                cert: rustls::Certificate(
                    peer_identity.serialize_der().unwrap(),
                ),
                private_key: rustls::PrivateKey(
                    peer_identity.serialize_private_key_der(),
                ),
            };
            client_certs.add(&peer_identity.cert).unwrap();
            client_identities.push(peer_identity);
        }

        let king = tokio::spawn(ProdNet::new_king(
            king_addr,
            server_identity.clone(),
            client_certs.clone(),
        ))
        .map_err(|err| MpcNetError::Generic(err.to_string()));
        let peers = FuturesUnordered::new();
        for (i, identity) in client_identities.into_iter().enumerate() {
            let peer = ProdNet::new_peer(
                i as u32,
                king_addr,
                identity,
                server_cert.clone(),
            );
            peers.push(Box::pin(peer));
        }

        let peers = peers.try_collect::<Vec<_>>();

        let (r_server, _) = tokio::try_join!(king, peers).unwrap();
        r_server.unwrap();
    }
}
