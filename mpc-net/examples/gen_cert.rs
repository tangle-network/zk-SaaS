use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Add IDs Example using ProdNet")]
struct Opt {
    #[structopt(parse(from_os_str))]
    output_cert: PathBuf,
    #[structopt(parse(from_os_str))]
    output_priv: PathBuf,
    #[structopt()]
    alt_name: String,
}

fn main() {
    let opts: Opt = Opt::from_args();

    let output_cert = &opts.output_cert;
    let output_priv = &opts.output_priv;

    let mut file_cert = File::create(output_cert).unwrap();
    let mut file_priv = File::create(output_priv).unwrap();

    let self_signed_cert =
        rcgen::generate_simple_self_signed(vec![opts.alt_name.clone()])
            .unwrap();
    let bytes_cert = self_signed_cert.serialize_der().unwrap();
    let bytes_priv = self_signed_cert.serialize_private_key_der();

    file_cert.write_all(&bytes_cert).unwrap();
    file_priv.write_all(&bytes_priv).unwrap();
    println!(
        "Generated certificate and private key for {}",
        opts.alt_name
    );
}
