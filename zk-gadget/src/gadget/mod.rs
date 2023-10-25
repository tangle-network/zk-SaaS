use std::net::SocketAddr;
use async_trait::async_trait;
use gadget::gadget::substrate::SubstrateGadgetModule;
use crate::Error;
use crate::gadget::registry::RegistantId;

pub mod registry;

/// Used as a module to place inside the SubstrateGadget
///
/// The zkGadget will need to create async protocols for each job it receives from the blockchain.
/// When it does so, since the clients may change, we will need to also update the TLS certs of
/// the king to match the new clients. As such, for each new async protocol we spawn, we will
/// also need to create a new [`ProdNet`] instance for the king and the clients
pub struct ZkGadget {
    registry: registry::RegistryService
}

impl ZkGadget {
    pub async fn new_king<T: tokio::net::ToSocketAddrs>(
        bind_addr: SocketAddr
    ) -> Result<Self, Error> {
        let registry = registry::RegistryService::new_king(bind_addr).await?;
        Ok(ZkGadget {
            registry
        })
    }

    pub async fn new_client<T: std::net::ToSocketAddrs>(
        king_registry_addr: T,
        registrant_id: RegistantId,
        cert_der: Vec<u8>
    ) -> Result<Self, Error> {
        let registry = registry::RegistryService::new_client(king_registry_addr, registrant_id, cert_der).await?;
        Ok(ZkGadget {
            registry
        })
    }
}

pub enum ZkProtocolError {}

#[async_trait]
impl SubstrateGadgetModule for ZkGadget {
    type Error = ZkProtocolError;
    type FinalityNotification = ();
    type BlockImportNotification = ();
    type ProtocolMessage = ();

    async fn get_next_protocol_message(&self) -> Option<Self::ProtocolMessage> {
        todo!()
    }

    async fn process_finality_notification(&self, notification: Self::FinalityNotification) -> Result<(), Self::Error> {
        todo!()
    }

    async fn process_block_import_notification(&self, notification: Self::BlockImportNotification) -> Result<(), Self::Error> {
        todo!()
    }

    async fn process_protocol_message(&self, message: Self::ProtocolMessage) -> Result<(), Self::Error> {
        todo!()
    }

    async fn process_error(&self, error: Self::Error) {
        todo!()
    }
}