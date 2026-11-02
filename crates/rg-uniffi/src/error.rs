use rg_core::Error;

/// A flat error so a shell can branch on the cause. `rg_core::Error` wraps source errors that do not cross the boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RailgunError {
    #[error("{message}")]
    InvalidInput { message: String },
    #[error("{message}")]
    InsufficientFunds { message: String },
    #[error("{message}")]
    Network { message: String },
    #[error("{message}")]
    Refused { message: String },
    #[error("{message}")]
    Internal { message: String },
}

impl RailgunError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        RailgunError::InvalidInput {
            message: message.into(),
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
        let message = e.to_string();
        match e {
            Error::Keys(_) => RailgunError::InvalidInput { message },
            Error::Tx(rg_core::TxError::InsufficientNote(_)) => {
                RailgunError::InsufficientFunds { message }
            }
            Error::Sync(rg_sync::Error::Rpc(_)) | Error::Node(_) | Error::Download(..) => {
                RailgunError::Network { message }
            }
            Error::NotProvable(..) | Error::UnknownSeedRoot(_) | Error::NoSquid(_) => {
                RailgunError::Refused { message }
            }
            _ => RailgunError::Internal { message },
        }
    }
}
