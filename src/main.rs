mod consts;
mod ed25519;
mod kex;
mod ssh;
mod sshkey;
mod utils;
mod x25519;

use anyhow::Result;
use clap::Parser;
use tokio::net::TcpStream;

use crate::sshkey::load;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true)]
    identity_file: std::path::PathBuf,
    #[arg(required = true)]
    host: String,
    #[arg(short, long, default_value_t = 22)]
    port: u16,
    #[arg(short, long, required = true)]
    login_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let privkey = load(&args.identity_file)?;
    let stream = TcpStream::connect(format!("{}:{}", args.host, args.port)).await?;
    let (read_half, write_half) = stream.into_split();
    let reader = tokio::io::BufReader::new(read_half);
    // let mut writer = tokio::io::BufWriter::new(write_half);
    let writer = write_half;
    let mut client = ssh::SshClient::new(reader, writer, args.login_name.clone(), privkey.clone());
    client.run().await?;

    Ok(())
}
