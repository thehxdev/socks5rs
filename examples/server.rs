use {
    std::net::SocketAddr,
    tokio::{
        io::{self, AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, BufStream},
        net::{self, TcpListener, TcpStream, TcpSocket},
    },
    socks5rs::{self, common, error::Result, server},
};

use common::{
    DestAddr,
    Request,
    command::Command,
};

#[cfg(feature = "io-util")]
use server::send_reply;

const BUFFER_CAP: usize = 9000;
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
                    _ = send_reply(&mut stream, Some(e), local_addr).await;
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

    let mut buffer = [0_u8; BUFFER_CAP];
    let mut n = stream.read(&mut buffer[..BUFFER_CAP]).await?;
    let (_, _methods) = server::parse_client_methods(&buffer[..n])?;

    stream.write_all(&[ common::SOCKS5, common::method::NO_AUTH ]).await?;
    stream.flush().await?;

    n = stream.read(&mut buffer[..BUFFER_CAP]).await?;

    let (_, command) = server::parse_client_request(&buffer[..n])?;

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
    dbg!(&req.dest_addr);
    let mut s = match req.dest_addr {
        DestAddr::IP(addr) => target.connect(SocketAddr::new(addr, req.dest_port)).await?,
        DestAddr::FQDN(domain) => {
            let host = join_host_and_port(String::from_utf8(domain).unwrap().as_str(), req.dest_port);
            let addr = resolve_domain_name(host.as_str()).await?;
            target.connect(addr).await?
        },
    };

    send_reply(stream, None, s.local_addr().unwrap()).await?;

    io::copy_bidirectional(stream, &mut s).await?;
    Ok(())
}

async fn resolve_domain_name(host: &str) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = net::lookup_host(host).await?.collect();
    Ok(addrs[0])
}

fn join_host_and_port(host: &str, port: u16) -> String {
    let mut s = String::with_capacity(host.len() + 6);
    s.push_str(host);
    s.push(':');
    s.push_str(port.to_string().as_str());
    s
}

#[cfg(not(feature = "io-util"))]
async fn send_reply<W>(w: &mut W, reply: Option<socks5rs::error::Error>, addr: SocketAddr) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + Sync
{
    let reply = server::Reply::new(reply, addr);
    w.write_all(&reply).await?;
    w.flush().await?;
    Ok(())
}
