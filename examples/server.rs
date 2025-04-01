#[allow(dead_code,unused)]

use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, BufStream},
    net::{TcpListener, TcpStream, TcpSocket},
};
use socks5rs::{self, consts, error::Result, Command, DestAddr, Request};

const BIND_ADDRESS: &str = "[::]:1080";

#[tokio::main]
async fn main() -> io::Result<()> {
    let listener = TcpListener::bind(BIND_ADDRESS).await?;
    println!("listening on {}", BIND_ADDRESS);
    loop {
        let stream = listener.accept().await?.0;
        tokio::spawn(async move {
            // own the stream
            let mut stream = stream;
            let local_addr = stream.local_addr().unwrap();
            match handle_client_connection(&mut stream).await {
                Ok(()) => (),
                Err(e) => {
                    eprintln!("{e:?}");
                    _ = socks5rs::io::send_reply(&mut stream, Some(e), local_addr).await;
                },
            };
            _ = stream.shutdown().await;
        });
    }
}

async fn handle_client_connection(stream: &mut TcpStream) -> Result<()> {
    // With buffered I/O it's important to call `.flush()` on stream
    // after write operation to ensure the bytes reached to their destination.
    let mut stream = BufStream::new(stream);

    const BUFCAP: usize = socks5rs::consts::MTU;
    let mut buffer = [0_u8; BUFCAP];
    let mut n = stream.read(&mut buffer[..BUFCAP]).await?;
    let (_, _methods) = socks5rs::parse_client_methods(&buffer[..n])?;

    stream.write_all(&[ consts::SOCKS5, consts::Method::NoAuth as u8 ]).await?;
    stream.flush().await?;

    n = stream.read(&mut buffer[..BUFCAP]).await?;

    let (_, command) = socks5rs::parse_client_request(&buffer[..n])?;

    match command {
        Command::Connect(r) => handle_connect_command(stream.get_mut(), r).await,
        _ => Ok(()),
    }
}

async fn handle_connect_command<RW>(stream: &mut RW, req: Request) -> Result<()>
where
    RW: AsyncRead + AsyncWrite + Unpin + Send + Sync,
{
    let target = TcpSocket::new_v4()?;
    let mut s = match req.dest_addr {
        DestAddr::IP(addr) => target.connect(SocketAddr::new(addr, req.dest_port)).await?,
        // Skip domain names for simplicity
        _ => return Ok(()),
    };

    socks5rs::io::send_reply(stream, None, s.local_addr().unwrap()).await?;

    io::copy_bidirectional(stream, &mut s).await?;
    Ok(())
}
