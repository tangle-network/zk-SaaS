use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use futures_util::sink::SinkExt;
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use mpc_net::multi::WrappedStream;

/// Type should correspond to the on-chain identifier of the registrant
pub type RegistantId = u64;

pub enum RegistryService {
    King {
        listener: Option<tokio::net::TcpListener>,
        registrants: Arc<Mutex<HashMap<RegistantId, Registrant>>>,
        jobs: Arc<Mutex<HashMap<[u8; 32], SocketAddr>>>
    },
    Client {
        king_registry_addr: SocketAddr,
        registrant_id: RegistantId,
        connection: Option<tokio::net::TcpStream>,
        cert_der: Vec<u8>
    }
}

pub struct Registrant {
    id: RegistantId,
    cert_der: Vec<u8>
}

use crate::Error;

impl RegistryService {
    pub async fn new_king(
        bind_addr: SocketAddr
    ) -> Result<Self, Error> {
        let listener = tokio::net::TcpListener::bind(bind_addr).await
            .map_err(|err| Error::RegistryCreateError { err: err.to_string() })?;
        let registrants = Arc::new(Mutex::new(HashMap::new()));
        let jobs = Arc::new(Mutex::new(HashMap::new()));
        Ok(RegistryService::King {
            listener: Some(listener),
            registrants,
            jobs
        })
    }

    pub async fn new_client<T: std::net::ToSocketAddrs>(
        king_registry_addr: T,
        registrant_id: RegistantId,
        cert_der: Vec<u8>
    ) -> Result<Self, Error> {
        let king_registry_addr: SocketAddr = king_registry_addr.to_socket_addrs()
            .map_err(|err| Error::RegistryCreateError { err: err.to_string() })?
            .next()
            .ok_or(Error::RegistryCreateError { err: "No address found".to_string() })?;

        let connection = tokio::net::TcpStream::connect(king_registry_addr).await
            .map_err(|err| Error::RegistryCreateError { err: err.to_string() })?;

        Ok(RegistryService::Client {
            king_registry_addr,
            registrant_id,
            cert_der,
            connection: Some(connection)
        })
    }

    pub async fn run_king(self) -> Result<(), Error> {
        match self {
            Self::King {
                listener,
                registrants,
                jobs
            } => {
                let listener = listener.expect("Should exist");
                while let Ok((stream, peer_addr)) = listener.accept().await {
                    println!("[Registry] Accepted connection from {peer_addr}");
                    handle_stream_as_king(stream, peer_addr, registrants.clone(), jobs.clone());
                }

                Err(Error::RegistryCreateError { err: "Listener closed".to_string() })
            }
            Self::Client {
                ..
            } => {
                Err(Error::RegistryCreateError { err: "Cannot run client as king".to_string() })
            }
        }
    }

    pub async fn client_register(&mut self) -> Result<(), Error> {
        match self {
            Self::King {
                ..
            } => {
                Err(Error::RegistryCreateError { err: "Cannot register as king".to_string() })
            }
            Self::Client {
                king_registry_addr: _,
                registrant_id,
                connection,
                cert_der
            } => {
                let conn = connection.as_mut().expect("Should exist");
                let mut wrapped_stream = mpc_net::multi::wrap_stream(conn);

                send_stream(&mut wrapped_stream, RegistryPacket::Register {
                    id: *registrant_id,
                    cert_der: cert_der.clone()
                }).await?;

                let response = recv_stream::<RegistryPacket, _>(&mut wrapped_stream).await?;

                if !matches!(&response, &RegistryPacket::RegisterResponse { success: true }) {
                    return Err(Error::RegistryCreateError { err: "Unexpected response".to_string() })
                }

                Ok(())
            }
        }
    }

    /// Returns Some if the job is already running, None if the job is pending
    /// If None, it is advised to run this function in a loop until the king is ready
    pub async fn get_job_port_as_client(&mut self, job_id: [u8; 32]) -> Result<Option<u16>, Error> {
        match self {
            Self::King {
                ..
            } => {
                Err(Error::RegistryCreateError { err: "Cannot get job port as king".to_string() })
            }
            Self::Client {
                king_registry_addr: _,
                registrant_id: _,
                connection,
                cert_der: _
            } => {
                let conn = connection.as_mut().expect("Should exist");
                let mut wrapped_stream = mpc_net::multi::wrap_stream(conn);

                send_stream(&mut wrapped_stream, RegistryPacket::GetJobAddress {
                    job_id
                }).await?;

                let response = recv_stream::<RegistryPacket, _>(&mut wrapped_stream).await?;

                if let RegistryPacket::GetJobAddressResponse { job_port } = response {
                    Ok(job_port)
                } else {
                    Err(Error::RegistryCreateError { err: "Unexpected response".to_string() })
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum RegistryPacket {
    Register {
        id: RegistantId,
        cert_der: Vec<u8>
    },
    RegisterResponse {
        success: bool
    },
    GetJobAddress {
        job_id: [u8; 32]
    },
    GetJobAddressResponse {
        // If None, pending (meaning the server hasn't started the job yet)
        // If Some, the port of the job is given (assumes no port translation)
        job_port: Option<u16>
    }
}

fn handle_stream_as_king(
    stream: TcpStream,
    peer_addr: SocketAddr,
    registrants: Arc<Mutex<HashMap<RegistantId, Registrant>>>,
    jobs: Arc<Mutex<HashMap<[u8; 32], SocketAddr>>>,
) {
    tokio::task::spawn(async move {
        let mut wrapped_stream = mpc_net::multi::wrap_stream(stream);
        let mut peer_id = None;
        while let Some(Ok(message)) = wrapped_stream.next().await {
            match bincode2::deserialize::<RegistryPacket>(&message) {
                Ok(packet) => {
                    match packet {
                        RegistryPacket::Register { id, cert_der } => {
                            println!("[Registry] Received registration for id {id}");
                            peer_id = Some(id);
                            let mut registrants = registrants.lock().await;
                            registrants.insert(id, Registrant { id, cert_der });
                            if let Err(err) = send_stream(&mut wrapped_stream, RegistryPacket::RegisterResponse { success: true }).await {
                                eprintln!("[Registry] Failed to send registration response: {err:?}");
                            }
                        },
                        RegistryPacket::GetJobAddress { job_id } => {
                            let mut jobs = jobs.lock().await;
                            let job_port = jobs.get(&job_id).map(|addr| addr.port());
                            if let Err(err) = send_stream(&mut wrapped_stream, RegistryPacket::GetJobAddressResponse { job_port }).await {
                                eprintln!("[Registry] Failed to send job address response: {err:?}");
                            }
                        }
                        _ => {
                            println!("[Registry] Received invalid packet");
                        }
                    }
                },
                Err(err) => {
                    println!("[Registry] Received invalid packet: {err}");
                }
            }
        }

        // Deregister peer
        if let Some(id) = peer_id {
            let mut registrants = registrants.lock().await;
            registrants.remove(&id);
        }

        eprintln!("[Registry] Connection closed to peer {peer_addr}")
    });
}


async fn send_stream<T: Serialize, R: AsyncRead + AsyncWrite + Unpin>(stream: &mut WrappedStream<R>, payload: T) -> Result<(), Error> {
    let serialized = bincode2::serialize(&payload)
        .map_err(|err| Error::RegistrySendError { err: err.to_string() })?;

    stream.send(serialized.into()).await
        .map_err(|err| Error::RegistrySendError { err: err.to_string() })
}

async fn recv_stream<T: DeserializeOwned, R: AsyncRead + AsyncWrite + Unpin>(stream: &mut WrappedStream<R>) -> Result<T, Error> {
    let message = stream.next().await
        .ok_or(Error::RegistryRecvError { err: "Stream closed".to_string() })?
        .map_err(|err| Error::RegistryRecvError { err: err.to_string() })?;

    let deserialized = bincode2::deserialize(&message)
        .map_err(|err| Error::RegistryRecvError { err: err.to_string() })?;

    Ok(deserialized)
}