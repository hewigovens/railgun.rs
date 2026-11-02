import Foundation

extension Data {
    /// Zeroes the bytes in place, keeping the count.
    mutating func wipe() {
        resetBytes(in: startIndex ..< endIndex)
    }
}
