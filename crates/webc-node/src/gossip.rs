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
use webc_storage::{KvStore, LocalTimestampMs};

use crate::http::{now_ms, AppState};
use crate::NodeHandle;

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
            // Consensus and state-sync artifacts are handled by the async
            // consensus driver (A-3), not this transaction-only pump. When the
            // node runs the driver, that path consumes them; here they are
            // absorbed (the transport still re-floods them to peers).
            NetMessage::Proposal(_)
            | NetMessage::Vote(_)
            | NetMessage::Certificate(_)
            | NetMessage::BlockRequest { .. }
            | NetMessage::BlockResponse(_)
            | NetMessage::TransactionV5(_)
            | NetMessage::ProposalV4(_)
            | NetMessage::BlockRequestV4 { .. }
            | NetMessage::BlockResponseV4(_) => {}
        }
    }
}

/// Drains protocol-2 V5 gossip into the single bounded node runtime.
///
/// The authenticated transport already re-flooded each newly seen frame. This
/// consumer therefore performs no broadcast: it awaits durable actor admission
/// and silently drops invalid, duplicate, saturated, or stopped-runtime input.
/// Legacy transactions and consensus artifacts belong to their versioned
/// drivers and are ignored here.
pub async fn run_v5_gossip_pump(runtime: NodeHandle, mut inbound: mpsc::Receiver<InboundMessage>) {
    while let Some(message) = inbound.recv().await {
        if let NetMessage::TransactionV5(transaction) = message.message {
            let _ = runtime
                .submit(*transaction, LocalTimestampMs::new(now_ms()))
                .await;
        }
    }
}
