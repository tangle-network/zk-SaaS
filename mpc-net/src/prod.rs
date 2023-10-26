use crate::multi::{
    multiplex_stream, MpcNetConnection, Peer, WrappedMuxStream,
    MULTIPLEXED_STREAMS,
};
use crate::{MpcNet, MpcNetError, MultiplexedStreamID};
use async_trait::async_trait;
use futures::SinkExt;
use futures::StreamExt;
use rustls::server::AllowAnyAuthenticatedClient;
use rustls::{RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::Mutex;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tokio_util::bytes::Bytes;

pub trait CertToDer {
    fn serialize_certificate_to_der(&self) -> Result<Vec<u8>, MpcNetError>;
    fn serialize_private_key_to_der(&self) -> Result<Vec<u8>, MpcNetError>;
}

#[derive(Clone)]
pub struct RustlsCertificate {
    pub cert: rustls::Certificate,
    pub private_key: rustls::PrivateKey,
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
        .with_client_cert_verifier(client_auth.boxed())
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

pub trait HasPeerAddr {
    fn peer_addr(&self) -> Result<SocketAddr, MpcNetError>;
}

impl HasPeerAddr for TlsStream<TcpStream> {
    fn peer_addr(&self) -> Result<SocketAddr, MpcNetError> {
        self.get_ref()
            .0
            .peer_addr()
            .map_err(|err| MpcNetError::Generic(err.to_string()))
    }
}

pub trait IOStream:
    AsyncWrite + AsyncRead + HasPeerAddr + Unpin + Send + 'static
{
}
impl<T: AsyncWrite + AsyncRead + HasPeerAddr + Unpin + Send + 'static> IOStream
    for T
{
}

pub struct ProdNet<T: IOStream> {
    /// The king will have a connection to each party, and each party will have a connection to the king.
    /// Thus, if this node is a king, there will be n_parties connections below. If this node is not a king,
    /// then, where will be only a single connection to the thing with ID 0
    connections: MpcNetConnection<T>,
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
pub enum ProtocolPacket {
    Syn,
    SynAck,
    Packet(Vec<u8>),
}

impl ProdNet<TlsStream<TcpStream>> {
    /// Returns when all the parties have connected.
    pub async fn new_king_tls<V: ToSocketAddrs, R: CertToDer>(
        bind_addr: V,
        identity: R,
        root_cert_store: RootCertStore,
    ) -> Result<ProdNet<TlsStream<TcpStream>>, MpcNetError> {
        let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let n_peers = root_cert_store.roots.len();

        let tls_acceptor =
            create_server_mutual_tls_acceptor(root_cert_store, identity)?;

        let mut tls_conns = vec![];

        for _ in 0..n_peers {
            let (stream, _) = tcp_listener.accept().await?;
            let stream = TlsStream::Server(tls_acceptor.accept(stream).await?);
            tls_conns.push(stream);
        }

        let n_parties = n_peers + 1;

        ProdNet::new_from_pre_existing_connection(0, n_parties, tls_conns).await
    }

    pub async fn new_peer_tls<R: CertToDer, V: std::net::ToSocketAddrs>(
        id: u32,
        king: V,
        identity: R,
        server_cert: RootCertStore,
        n_parties: usize,
    ) -> Result<ProdNet<TlsStream<TcpStream>>, MpcNetError> {
        let king_addr: SocketAddr =
            king.to_socket_addrs()?
                .next()
                .ok_or(MpcNetError::BadInput {
                    err: "King socket addr invalid",
                })?;

        let stream = TcpStream::connect(king_addr).await?;
        let tls_connector =
            create_client_mutual_tls_connector(server_cert, identity)?;
        let stream = TlsStream::Client(
            tls_connector
                .connect(rustls::ServerName::IpAddress(king_addr.ip()), stream)
                .await?,
        );

        ProdNet::new_from_pre_existing_connection(id, n_parties, vec![stream])
            .await
    }
}

impl<T: IOStream> ProdNet<T> {
    /// Must pass a list of connections to all the peers if king, otherwise a single connection
    /// if a peer
    pub async fn new_from_pre_existing_connection(
        id: u32,
        n_parties: usize,
        mut ios: Vec<T>,
    ) -> Result<Self, MpcNetError> {
        if id != 0 {
            if ios.len() != 1 {
                return Err(MpcNetError::BadInput {
                    err: "Must pass a single connection to the king if you are a peer",
                });
            }
        }

        let mut connections = MpcNetConnection {
            id,
            listener: None,
            peers: Default::default(),
            n_parties,
        };

        if id == 0 {
            for mut stream in ios.into_iter() {
                let peer_id = stream.read_u32().await?;
                let peer_addr = stream.peer_addr()?;
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
        } else {
            let mut stream = ios.pop().expect("Should exist");
            let oeer_addr = stream.peer_addr()?;
            stream.write_u32(id).await?;
            let muxed =
                multiplex_stream(MULTIPLEXED_STREAMS, false, stream).await?;
            connections.peers.insert(
                0,
                Peer {
                    id: 0,
                    listen_addr: oeer_addr,
                    streams: Some(muxed),
                },
            );
        }

        let this = Self { connections };
        this.synchronize().await?;

        Ok(this)
    }

    /// Ensure all peers are connected to the king
    async fn synchronize(&self) -> Result<(), MpcNetError> {
        if self.is_king() {
            // Broadcast to each peer a SYN packet
            for conn in self.connections.peers.values() {
                send_packet(
                    conn.streams.as_ref(),
                    MultiplexedStreamID::Zero,
                    ProtocolPacket::Syn,
                )
                .await?;
            }

            // Wait for n_parties count of SynAck packets
            for conn in self.connections.peers.values() {
                let packet = recv_packet(
                    conn.streams.as_ref(),
                    MultiplexedStreamID::Zero,
                )
                .await?;
                if packet != ProtocolPacket::SynAck {
                    return Err(MpcNetError::Protocol {
                        err: "Did not receive SynAck".to_string(),
                        party: conn.id,
                    });
                }
            }
        } else {
            // Wait for a Syn packet
            let packet = recv_packet(
                self.connections.peers.get(&0).unwrap().streams.as_ref(),
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
                self.connections.peers.get(&0).unwrap().streams.as_ref(),
                MultiplexedStreamID::Zero,
                ProtocolPacket::SynAck,
            )
            .await?;
        }

        Ok(())
    }
}

#[async_trait]
impl<T: IOStream> MpcNet for ProdNet<T> {
    fn n_parties(&self) -> usize {
        self.connections.n_parties()
    }

    fn party_id(&self) -> u32 {
        self.connections.party_id()
    }

    fn is_init(&self) -> bool {
        self.connections.is_init()
    }

    async fn client_send_or_king_receive(
        &self,
        bytes: &[u8],
        sid: MultiplexedStreamID,
    ) -> Result<Option<Vec<Bytes>>, MpcNetError> {
        self.connections
            .client_send_or_king_receive(bytes, sid)
            .await
    }

    async fn client_receive_or_king_send(
        &self,
        bytes: Option<Vec<Bytes>>,
        sid: MultiplexedStreamID,
    ) -> Result<Bytes, MpcNetError> {
        self.connections
            .client_receive_or_king_send(bytes, sid)
            .await
    }
}

async fn send_packet<T: IOStream>(
    streams: Option<&Vec<Mutex<WrappedMuxStream<T>>>>,
    sid: MultiplexedStreamID,
    packet: ProtocolPacket,
) -> Result<(), MpcNetError> {
    let stream = streams.ok_or(MpcNetError::NotConnected)?;
    let stream = stream.get(sid as usize).ok_or(MpcNetError::NotConnected)?;
    let packet = bincode2::serialize(&packet)?;
    stream.lock().await.send(Bytes::from(packet)).await?;
    Ok(())
}

async fn recv_packet<T: IOStream>(
    streams: Option<&Vec<Mutex<WrappedMuxStream<T>>>>,
    sid: MultiplexedStreamID,
) -> Result<ProtocolPacket, MpcNetError> {
    let stream = streams.ok_or(MpcNetError::NotConnected)?;
    let stream = stream.get(sid as usize).ok_or(MpcNetError::NotConnected)?;
    let packet = stream
        .lock()
        .await
        .next()
        .await
        .ok_or(MpcNetError::NotConnected)??;
    let packet = bincode2::deserialize(&packet)?;
    Ok(packet)
}

#[cfg(test)]
mod test {
    use super::*;
    use futures::stream::{FuturesOrdered, FuturesUnordered};
    use futures::{TryFutureExt, TryStreamExt};
    use std::future::Future;
    use std::io::Error;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::net::TcpListener;

    use rcgen::{Certificate, RcgenError};
    use tokio::io::ReadBuf;

    impl CertToDer for Certificate {
        fn serialize_certificate_to_der(&self) -> Result<Vec<u8>, MpcNetError> {
            Ok(self.serialize_der().unwrap())
        }
        fn serialize_private_key_to_der(&self) -> Result<Vec<u8>, MpcNetError> {
            Ok(self.serialize_private_key_der())
        }
    }

    fn generate_self_signed_cert() -> Result<Certificate, RcgenError> {
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
    }

    struct LocalTestNetProd<T: IOStream> {
        nodes: Vec<ProdNet<T>>,
    }

    impl<T: IOStream> LocalTestNetProd<T> {
        pub async fn simulate_network_round<
            F: Future<Output = K> + Send,
            K: Send + Sync + 'static,
        >(
            self,
            f: impl Fn(ProdNet<T>) -> F + Send + Sync + Clone + 'static,
        ) -> Vec<K> {
            let mut futures = FuturesOrdered::new();
            for connections in self.nodes.into_iter() {
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

    struct ChannelIO {
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl HasPeerAddr for ChannelIO {
        fn peer_addr(&self) -> Result<SocketAddr, MpcNetError> {
            Ok(SocketAddr::from_str("127.0.0.1:12345").unwrap())
        }
    }

    impl AsyncWrite for ChannelIO {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, Error>> {
            let len = buf.len();
            self.tx.send(buf.into()).unwrap();
            Poll::Ready(Ok(len))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncRead for ChannelIO {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            match self.as_mut().rx.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    buf.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(None) => Poll::Ready(Err(Error::new(
                    std::io::ErrorKind::Other,
                    "Channel closed",
                ))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_network_init() {
        let _ = init_network(3).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_exchange_of_data_sum_all_ids() {
        const N_PEERS: usize = 4;
        let nodes = init_network(N_PEERS).await;
        let testnet = LocalTestNetProd { nodes };
        let expected_result: u32 = (0..=N_PEERS).map(|r| r as u32).sum();
        add_protocol_inner(testnet, expected_result, N_PEERS).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_exchange_of_data_sum_all_ids2() {
        const N_PEERS: usize = 4;
        let nodes = init_network_channels(N_PEERS).await;
        let testnet = LocalTestNetProd { nodes };
        let expected_result: u32 = (0..=N_PEERS).map(|r| r as u32).sum();
        add_protocol_inner(testnet, expected_result, N_PEERS).await;
    }

    async fn add_protocol_inner<T: IOStream>(
        testnet: LocalTestNetProd<T>,
        expected_result: u32,
        n_peers: usize,
    ) {
        let sums = testnet
            .simulate_network_round(move |net| async move {
                let my_id = net.party_id();
                let bytes = bincode2::serialize(&my_id).unwrap();
                if let Some(king_recv) = net
                    .client_send_or_king_receive(
                        &bytes,
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap()
                {
                    assert_eq!(my_id, 0);
                    // convert each bytes into a u32, and sum
                    let mut sum = 0;
                    for bytes in king_recv {
                        let id: u32 = bincode2::deserialize(&bytes).unwrap();
                        println!("King recv ID: {}", id);
                        sum += id;
                    }
                    // now, send the sum to each of the clients
                    let bytes = bincode2::serialize(&sum).unwrap();
                    let send = (0..(n_peers + 1))
                        .map(|_| bytes.clone().into())
                        .collect::<Vec<Bytes>>();
                    net.client_receive_or_king_send(
                        Some(send),
                        MultiplexedStreamID::Zero,
                    )
                    .await
                    .unwrap();
                    sum
                } else {
                    assert_ne!(my_id, 0);
                    let bytes = net
                        .client_receive_or_king_send(
                            None,
                            MultiplexedStreamID::Zero,
                        )
                        .await
                        .unwrap();
                    let sum: u32 = bincode2::deserialize(&bytes).unwrap();
                    sum
                }
            })
            .await;

        tokio::time::sleep(Duration::from_millis(200)).await;
        // Assert all values are the same inside the sums vector
        assert!(sums.iter().all(|sum| *sum == expected_result));
    }

    async fn init_network(
        n_peers: usize,
    ) -> Vec<ProdNet<TlsStream<TcpStream>>> {
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
        for _ in 0..n_peers {
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

        let king = tokio::spawn(ProdNet::<TlsStream<TcpStream>>::new_king_tls(
            king_addr,
            server_identity.clone(),
            client_certs.clone(),
        ))
        .map_err(|err| MpcNetError::Generic(err.to_string()));

        tokio::time::sleep(Duration::from_millis(200)).await;

        let peers = FuturesUnordered::new();
        for (i, identity) in client_identities.into_iter().enumerate() {
            let peer = ProdNet::new_peer_tls(
                (i + 1) as u32,
                king_addr,
                identity,
                server_cert.clone(),
                n_peers + 1,
            );
            peers.push(Box::pin(peer));
        }

        let peers = peers.try_collect::<Vec<_>>();

        let (r_server, mut r_clients) = tokio::try_join!(king, peers).unwrap();
        r_clients.push(r_server.unwrap());
        r_clients
    }

    async fn init_network_channels(n_peers: usize) -> Vec<ProdNet<ChannelIO>> {
        let n_parties = n_peers + 1;
        let mut king_conns = vec![];
        let mut peer_nets = vec![];

        for _ in 0..n_peers {
            let (to_peer, from_king) = tokio::sync::mpsc::unbounded_channel();
            let (to_king, from_peer) = tokio::sync::mpsc::unbounded_channel();
            let king = ChannelIO {
                tx: to_peer,
                rx: from_peer,
            };
            king_conns.push(king);
            let peer = ChannelIO {
                tx: to_king,
                rx: from_king,
            };
            peer_nets.push(peer);
        }

        let king = tokio::spawn(ProdNet::new_from_pre_existing_connection(
            0, n_parties, king_conns,
        ))
        .map_err(|err| MpcNetError::Generic(err.to_string()));

        let peer_nets_futures = FuturesUnordered::new();
        for (i, king_io) in peer_nets.into_iter().enumerate() {
            let peer_net = ProdNet::new_from_pre_existing_connection(
                (i + 1) as u32,
                n_parties,
                vec![king_io],
            );
            peer_nets_futures.push(Box::pin(peer_net));
        }

        let peers = peer_nets_futures.try_collect::<Vec<_>>();

        let (r_server, mut r_clients) = tokio::try_join!(king, peers).unwrap();
        r_clients.push(r_server.unwrap());
        r_clients
    }
}
