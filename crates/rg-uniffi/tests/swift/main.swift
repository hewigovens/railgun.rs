import Foundation

do {
    try OfflineSmoke().run()
    try LiveSmoke(environment: ProcessInfo.processInfo.environment)?.run()
} catch {
    Check.fail("\(error)")
}
