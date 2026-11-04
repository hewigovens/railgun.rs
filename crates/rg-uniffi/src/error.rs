use rg_core::Error;

/// A flat error so a shell can branch on the cause. `rg_core::Error` wraps source errors that do not cross the boundary. The field is `reason` because `message` collides with Kotlin's `Throwable.message`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RailgunError {
    #[error("{reason}")]
    InvalidInput { reason: String },
    #[error("{reason}")]
    InsufficientFunds { reason: String },
    /// Enough of the token is there, but some of it is still waiting for POI.
    #[error("{reason}")]
    PendingPoi { reason: String },
    /// A broadcaster may still submit an earlier batch of this token: sync once it lands, or `forget_pending_broadcasts`.
    #[error("{reason}")]
    HeldByBroadcaster { reason: String },
    #[error("{reason}")]
    Network { reason: String },
    #[error("{reason}")]
    Refused { reason: String },
    #[error("{reason}")]
    Internal { reason: String },
}

impl RailgunError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        RailgunError::InvalidInput {
            reason: message.into(),
        }
    }
}

impl From<rg_keys::Error> for RailgunError {
    fn from(e: rg_keys::Error) -> Self {
        RailgunError::invalid(e.to_string())
    }
}

impl From<Error> for RailgunError {
    fn from(e: Error) -> Self {
        let reason = e.to_string();
        match e {
            Error::Keys(_)
            | Error::BadAddress(_)
            | Error::WrongChain(..)
            | Error::WrongNode(..)
            | Error::InsecureRpc
            | Error::NotOffered => RailgunError::InvalidInput { reason },
            Error::Tx(rg_core::TxError::InsufficientNote(_)) => {
                RailgunError::InsufficientFunds { reason }
            }
            Error::AwaitingPoi(_) => RailgunError::PendingPoi { reason },
            Error::HeldByBroadcaster => RailgunError::HeldByBroadcaster { reason },
            Error::Sync(rg_sync::Error::Rpc(_))
            | Error::Node(_)
            | Error::Download(..)
            | Error::Broadcaster(_) => RailgunError::Network { reason },
            Error::Sync(rg_sync::Error::Refused(_))
            | Error::NotProvable(..)
            | Error::UnknownRoot(..)
            | Error::NoSquid(_)
            | Error::Refused(_) => RailgunError::Refused { reason },
            _ => RailgunError::Internal { reason },
        }
    }
}
