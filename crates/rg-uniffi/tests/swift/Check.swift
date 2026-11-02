import Foundation

enum Check {
    static func that(_ condition: Bool, _ message: String) {
        if !condition {
            fail(message)
        }
    }

    static func fail(_ message: String) -> Never {
        print("FAILED: \(message)")
        exit(1)
    }

    static func raises<Failure: Error>(
        _: Failure.Type,
        where matches: (Failure) -> Bool,
        _ message: String,
        _ body: () throws -> some Any
    ) throws {
        do {
            _ = try body()
        } catch let error as Failure where matches(error) {
            print("\(message): \(error)")
            return
        }
        fail("\(message) must throw")
    }
}
