import AppIntents

/// App Intent / Shortcuts / Action Button: put the current intent string.
struct PutOnShelfIntent: AppIntent {
    static var title: LocalizedStringResource = "Put on Shelf"

    @Parameter(title: "Text")
    var text: String

    func perform() async throws -> some IntentResult {
        // Call `shelf-mobile` `put_text` with the app container home.
        let _ = text
        return .result()
    }
}
