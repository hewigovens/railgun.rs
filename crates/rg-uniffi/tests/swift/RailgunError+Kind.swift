extension RailgunError {
    var isInvalidInput: Bool {
        if case .InvalidInput = self {
            true
        } else {
            false
        }
    }

    var isNetwork: Bool {
        if case .Network = self {
            true
        } else {
            false
        }
    }

    var isInsufficientFunds: Bool {
        if case .InsufficientFunds = self {
            true
        } else {
            false
        }
    }

    var isPendingPoi: Bool {
        if case .PendingPoi = self {
            true
        } else {
            false
        }
    }
}
