pub mod channel;
pub mod dfft;
pub mod dmsm;
pub mod dpp;
pub mod utils;

use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, Clone, StructOpt)]
#[structopt(name = "example", about = "An example of StructOpt usage.")]
pub struct Opt {
    /// Id
    pub id: usize,

    /// Input file
    #[structopt(parse(from_os_str))]
    pub input: PathBuf,

    /// Packing factor
    pub l: usize,

    /// Threshold
    pub t: usize,

    /// FFT size
    pub m: usize,
}
