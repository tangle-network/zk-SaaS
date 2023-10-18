// An example ProdNet that performs the simple task of adding up all transmitted IDs
use mpc_net::prod::{ProdNet, RustlsCertificate};
use mpc_net::{MpcNet, MultiplexedStreamID};
use rustls::{Certificate, PrivateKey, RootCertStore};
use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;
use structopt::StructOpt;
use tokio_util::bytes::Bytes;

#[derive(Debug, StructOpt)]
#[structopt(name = "Add IDs Example using ProdNet")]
struct Opt {
    /// This node's ID
    #[structopt(short, long)]
    id: u32,

    /// This node's certificate
    #[structopt(parse(from_os_str))]
    certificate: PathBuf,

    /// This node's private key
    #[structopt(parse(from_os_str))]
    private_key: PathBuf,

    /// The number of parties in the network, including the king
    #[structopt(short, long)]
    n_parties: usize,

    /// Bind address for the king (required for the king)
    #[structopt(short, long)]
    bind_addr: Option<String>,

    /// The address of the king (required for the clients)
    #[structopt(short, long)]
    king_addr: Option<String>,

    /// The king's certificate (required for the clients)
    #[structopt(parse(from_os_str), short, long)]
    king_cert: Option<PathBuf>,

    /// List of certificates for each of the clients. Certs in the supplied directory should end with .cert.der
    #[structopt(short, long)]
    client_cert_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opt = Opt::from_args();
    let n_parties = opts.n_parties;
    let my_id = opts.id;

    let net = if opts.id == 0 {
        load_king(opts).await?
    } else {
        load_client(opts).await?
    };

    println!("Loaded net for id {my_id}");

    // Run the network
    let expected_sum_result = (0..n_parties).map(|r| r as u32).sum::<u32>();

    let bytes = bincode2::serialize(&my_id).unwrap();
    let sum = if let Some(king_recv) = net
        .client_send_or_king_receive(&bytes, MultiplexedStreamID::Zero)
        .await
        .unwrap()
    {
        assert_eq!(my_id, 0);
        // convert each bytes into a u32, and sum
        let mut sum = 0;
        for bytes in king_recv {
            let id: u32 = bincode2::deserialize(&bytes).unwrap();
            println!("King RECV id {id}");
            sum += id;
        }
        println!("King sum: {sum}");
        // now, send the sum to each of the clients
        let bytes = bincode2::serialize(&sum).unwrap();
        let send = (0..n_parties)
            .map(|_| bytes.clone().into())
            .collect::<Vec<Bytes>>();
        net.client_receive_or_king_send(Some(send), MultiplexedStreamID::Zero)
            .await
            .unwrap();
        sum
    } else {
        assert_ne!(my_id, 0);
        let bytes = net
            .client_receive_or_king_send(None, MultiplexedStreamID::Zero)
            .await
            .unwrap();
        let sum: u32 = bincode2::deserialize(&bytes).unwrap();
        sum
    };

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(sum, expected_sum_result);
    Ok(())
}

async fn load_king(opts: Opt) -> Result<ProdNet, Box<dyn Error>> {
    if opts.client_cert_dir.is_none() {
        panic!("Must supply the client cert dir")
    }

    if opts.bind_addr.is_none() {
        panic!("Must supply the bind address for the king")
    }

    if opts.king_cert.is_some() {
        panic!("King should not have a king cert set - this is for clients")
    }

    let files_in_client_cert_dir =
        std::fs::read_dir(opts.client_cert_dir.unwrap())?;
    let mut client_certs = RootCertStore::empty();

    let private_key_king = load_private_key(&opts.private_key)?;
    let king_cert = get_certs(&opts.certificate)?[0].clone();

    for file in files_in_client_cert_dir {
        let file = file.unwrap();
        let path = file.path();
        let fname = file.file_name();
        let name = fname.to_str().unwrap();
        if name.ends_with(".cert.der") {
            load_cert(&path, &mut client_certs)?;
        }
    }

    println!("King loaded {} certs", client_certs.roots.len());

    let identity = RustlsCertificate {
        cert: king_cert,
        private_key: private_key_king,
    };

    ProdNet::new_king(opts.bind_addr.unwrap(), identity, client_certs)
        .await
        .map_err(|err| format!("Error creating king: {err:?}").into())
}

async fn load_client(opts: Opt) -> Result<ProdNet, Box<dyn Error>> {
    if opts.king_addr.is_none() {
        panic!("Must supply the king address for the clients")
    }

    if opts.king_cert.is_none() {
        panic!("Must supply the king cert for the clients")
    }

    let king_addr = opts.king_addr.unwrap();
    let client_identity = get_certs(&opts.certificate)?[0].clone();
    let private_key_client = load_private_key(&opts.private_key)?;

    // Add the king cert
    let mut king_store = RootCertStore::empty();
    let king_cert = get_certs(&opts.king_cert.unwrap())?[0].clone();
    king_store.add(&king_cert)?;

    let identity = RustlsCertificate {
        cert: client_identity,
        private_key: private_key_client,
    };

    ProdNet::new_peer(opts.id, king_addr, identity, king_store, opts.n_parties)
        .await
        .map_err(|err| format!("Error creating client: {err:?}").into())
}

/// Loads a certificate into a cert store
fn load_cert(
    path: &PathBuf,
    cert_store: &mut RootCertStore,
) -> Result<(), Box<dyn Error>> {
    let certs = get_certs(path)?;
    for cert in certs {
        cert_store.add(&cert)?;
    }

    Ok(())
}

fn get_certs(path: &PathBuf) -> Result<Vec<Certificate>, Box<dyn Error>> {
    let bytes = std::fs::read(path)?;
    //let certs = rustls_pemfile::certs(&mut reader)?;
    Ok(vec![Certificate(bytes)])
}

/// Loads a private key from the path
fn load_private_key(path: &PathBuf) -> Result<PrivateKey, Box<dyn Error>> {
    let private_key_bytes = std::fs::read(&path)?;
    Ok(PrivateKey(private_key_bytes))
}
