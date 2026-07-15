//! Glue between the peer-to-peer network and the node service.
//!
//! The transport ([`webc_net`]) handles authentication, framing, and flood
//! propagation between peers — including re-flooding a newly-seen frame to a
//! node's other peers before the node itself is involved. This module is the
//! thin consumer on top: it drains inbound gossip and feeds each transaction
//! into the local mempool. Locally submitted transactions are introduced to the
//! network on the other side, by [`crate::http::AppState::submit_transaction`].
//!
//! Because the transport already re-floods, the pump does not re-broadcast what
//! it receives; doing so would be redundant. It simply absorbs gossip into the
//! mempool so this node's future blocks can include it.

use tokio::sync::mpsc;
use webc_net::{InboundMessage, NetMessage};
use webc_storage::KvStore;

use crate::http::{now_ms, AppState};

/// Drains inbound gossip into the node's mempool until the network stops.
///
/// Takes an [`AppState`] (an `Arc`-backed clone of the running node) so it feeds
/// the same mempool the API serves. Runs until the inbound channel closes (every
/// network handle dropped). Each gossiped transaction is admitted through the
/// service's tolerant network path, which silently drops stale, duplicate, or
/// invalid transactions.
pub async fn run_gossip_pump<K>(state: AppState<K>, mut inbound: mpsc::Receiver<InboundMessage>)
where
    K: KvStore + Send + Sync + 'static,
{
    while let Some(message) = inbound.recv().await {
        match message.message {
            NetMessage::Transaction(tx) => {
                let _ = state.service().admit_network_transaction(*tx, now_ms());
            }
        }
    }
}
