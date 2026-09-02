#ifndef SHELF_MOBILE_H
#define SHELF_MOBILE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Thin C ABI for crates/shelf-mobile (in-process iOS vault; no shelfd).
 *
 * Link libshelf_mobile.a produced by:
 *   cargo build -p shelf-mobile --release --target aarch64-apple-ios
 *
 * These functions never return wrap keys, epoch keys, or other secret
 * material. Failures are integer codes only.
 *
 * Error codes (int32_t):
 *   SHELF_OK            0   success
 *   SHELF_ERR_NULL     -1   required pointer was NULL
 *   SHELF_ERR_UTF8     -2   home path or text was not valid UTF-8
 *   SHELF_ERR_OPEN     -3   vault open/create failed (no file wrap on iOS)
 *   SHELF_ERR_SESSION  -4   session handle was NULL or already closed
 *   SHELF_ERR_PUT      -5   put_text failed
 *   SHELF_ERR_LATEST   -6   latest failed (empty vault or decrypt error)
 *   SHELF_ERR_BUFFER   -7   caller buffer too small; *out_len is required size
 *   SHELF_ERR_SYNC     -8   opportunistic mailbox sync failed
 */

#define SHELF_OK 0
#define SHELF_ERR_NULL (-1)
#define SHELF_ERR_UTF8 (-2)
#define SHELF_ERR_OPEN (-3)
#define SHELF_ERR_SESSION (-4)
#define SHELF_ERR_PUT (-5)
#define SHELF_ERR_LATEST (-6)
#define SHELF_ERR_BUFFER (-7)
#define SHELF_ERR_SYNC (-8)

typedef struct ShelfMobileSession ShelfMobileSession;

/* Open or create the vault under home_utf8. Out-param is NULL on failure. */
int32_t shelf_mobile_open(const char *home_utf8, ShelfMobileSession **out);

/* Drop a session opened by shelf_mobile_open. NULL is a no-op. */
void shelf_mobile_close(ShelfMobileSession *session);

/* Put UTF-8 text into the vault. */
int32_t shelf_mobile_put_text(ShelfMobileSession *session, const char *text_utf8);

/*
 * Copy the newest plaintext into buf (cap bytes). Always writes the required
 * size to *out_len when out_len is non-NULL. Returns SHELF_ERR_BUFFER when
 * buf is NULL or cap is smaller than the plaintext.
 */
int32_t shelf_mobile_latest(ShelfMobileSession *session, uint8_t *buf, size_t cap,
                            size_t *out_len);

/*
 * If config.toml has mailbox_url, GET/ACK/PUT signed replica frames via
 * MailboxClient. No-op success when mailbox_url is unset.
 */
int32_t shelf_mobile_sync_once(ShelfMobileSession *session);

#ifdef __cplusplus
}
#endif

#endif /* SHELF_MOBILE_H */
