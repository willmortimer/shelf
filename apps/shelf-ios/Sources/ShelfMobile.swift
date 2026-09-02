import Foundation

// Bridging: C ABI in crates/shelf-mobile/include/shelf_mobile.h
// (link libshelf_mobile.a). @_silgen_name binds the staticlib symbols.

@_silgen_name("shelf_mobile_open")
func shelf_mobile_open(
    _ home: UnsafePointer<CChar>,
    _ out: UnsafeMutablePointer<OpaquePointer?>
) -> Int32

@_silgen_name("shelf_mobile_close")
func shelf_mobile_close(_ session: OpaquePointer?)

@_silgen_name("shelf_mobile_put_text")
func shelf_mobile_put_text(_ session: OpaquePointer?, _ text: UnsafePointer<CChar>) -> Int32

@_silgen_name("shelf_mobile_sync_once")
func shelf_mobile_sync_once(_ session: OpaquePointer?) -> Int32

/// In-process vault calls used by Share Sheet and App Intents.
enum ShelfMobile {
    static func putText(_ text: String, home: URL) {
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        home.path.withCString { homePtr in
            var session: OpaquePointer?
            guard shelf_mobile_open(homePtr, &session) == 0, let handle = session else {
                return
            }
            defer { shelf_mobile_close(handle) }
            _ = text.withCString { textPtr in
                shelf_mobile_put_text(handle, textPtr)
            }
            _ = shelf_mobile_sync_once(handle)
        }
    }
}
