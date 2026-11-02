import Foundation

extension Data {
    /// Parses hex with an optional `0x` prefix and surrounding whitespace.
    init(hex: String) throws {
        let digits = Array(hex.trimmingCharacters(in: .whitespacesAndNewlines).replacingOccurrences(of: "0x", with: ""))
        guard digits.count.isMultiple(of: 2) else {
            throw HexError.oddLength
        }
        self.init(capacity: digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(digits[index ..< index + 2]), radix: 16) else {
                throw HexError.notHex
            }
            append(byte)
        }
    }
}

enum HexError: Error {
    case oddLength
    case notHex
}
