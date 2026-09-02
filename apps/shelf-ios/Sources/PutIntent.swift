import AppIntents
import Foundation

/// App Intent / Shortcuts / Action Button: put the current intent string.
struct PutOnShelfIntent: AppIntent {
    static var title: LocalizedStringResource = "Put on Shelf"

    @Parameter(title: "Text")
    var text: String

    func perform() async throws -> some IntentResult {
        let home = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("shelf", isDirectory: true)
        ShelfMobile.putText(text, home: home)
        return .result()
    }
}
