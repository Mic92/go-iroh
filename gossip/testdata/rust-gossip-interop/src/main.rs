use std::net::Ipv4Addr;

use bytes::Bytes;
use iroh::{endpoint::presets, protocol::Router, Endpoint};
use iroh_gossip::{api::Event, net::Gossip, TopicId, ALPN};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Serialize)]
#[serde(tag = "kind")]
enum Out {
    Ready { id: String, addrs: Vec<String> },
    NeighborUp { peer: String },
    Received { content: String },
}

#[derive(Deserialize)]
#[serde(tag = "cmd")]
enum In {
    Broadcast { content: String },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let topic = TopicId::from_bytes(*b"go-iroh rust gossip interop 001!");
    let endpoint = Endpoint::builder(presets::Minimal)
        .bind_addr((Ipv4Addr::LOCALHOST, 0))?
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(ALPN, gossip.clone())
        .spawn();

    let addrs = endpoint
        .bound_sockets()
        .into_iter()
        .filter(|addr| addr.is_ipv4())
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>();
    print_json(&Out::Ready {
        id: endpoint.id().to_string(),
        addrs,
    })?;

    let topic = gossip.subscribe(topic, Vec::new()).await?;
    let (sender, mut receiver) = topic.split();
    let events = tokio::spawn(async move {
        while let Some(event) = receiver.next().await {
            match event? {
                Event::NeighborUp(peer) => print_json(&Out::NeighborUp {
                    peer: peer.to_string(),
                })?,
                Event::Received(message) => print_json(&Out::Received {
                    content: String::from_utf8_lossy(&message.content).into_owned(),
                })?,
                Event::Lagged => {}
                Event::NeighborDown(_) => {}
            }
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<In>(&line)? {
            In::Broadcast { content } => {
                sender.broadcast(Bytes::from(content)).await?;
            }
        }
    }

    events.abort();
    router.shutdown().await?;
    Ok(())
}

fn print_json(value: &Out) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
