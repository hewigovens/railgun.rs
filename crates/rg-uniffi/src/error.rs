use rg_core::Error;

/// A flat error so a shell can branch on the cause. `rg_core::Error` wraps source errors that do not cross the boundary. The field is `reason` because `message` collides with Kotlin's `Throwable.message`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RailgunError {
    #[error("{reason}")]
    InvalidInput { reason: String },
    #[error("{reason}")]
    InsufficientFunds { reason: String },
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
            Error::Keys(_) | Error::BadAddress(_) | Error::WrongChain(..) => {
                RailgunError::InvalidInput { reason }
            }
            Error::Tx(rg_core::TxError::InsufficientNote(_)) => {
                RailgunError::InsufficientFunds { reason }
            }
            Error::Sync(rg_sync::Error::Rpc(_)) | Error::Node(_) | Error::Download(..) => {
                RailgunError::Network { reason }
            }
            Error::Sync(rg_sync::Error::Refused(_))
            | Error::NotProvable(..)
            | Error::UnknownSeedRoot(_)
            | Error::NoSquid(_) => RailgunError::Refused { reason },
            _ => RailgunError::Internal { reason },
        }
    }
}
