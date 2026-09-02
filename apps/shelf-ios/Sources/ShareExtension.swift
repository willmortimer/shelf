import Foundation

/// Share Sheet entry: put shared text into the local Shelf vault.
/// Wire this from a Share Extension target that links `libshelf_mobile.a`.
enum ShareExtension {
    static func putSharedText(_ text: String, home: URL) {
        ShelfMobile.putText(text, home: home)
    }
}
