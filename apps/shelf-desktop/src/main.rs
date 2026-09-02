//! `shelf-desktop` binary: small Slint client over `shelfd` IPC.

use shelf_client::{Client, GetTarget, ListedDevice, ListedItem, resolve_socket_path};
use shelf_core::ContentKind;
use shelf_desktop::{
    DEFAULT_SCRATCH_PAD, copy_clipboard, filter_file_lines, filter_lines, format_device_line,
    format_line, infer_capture_kind, paste_clipboard, settings_home_note,
};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

slint::slint! {
    import { Button, VerticalBox, LineEdit, TextEdit, TabWidget } from "std-widgets.slint";

    export component App inherits Window {
        title: "Shelf";
        min-width: 480px;
        min-height: 360px;
        in-out property <[string]> shelf-lines: [];
        in-out property <string> shelf-query: "";
        in-out property <[string]> transfer-lines: [];
        in-out property <[string]> device-lines: [];
        in-out property <string> scratch-text: "";
        in-out property <string> scratch-append: "";
        in-out property <string> capture-status: "";
        in-out property <string> socket-path: "";
        in-out property <string> home-note: "";
        callback pick(int);
        callback query-changed(string);
        callback capture();
        callback scratch-submit();
        TabWidget {
            Tab {
                title: "Shelf";
                VerticalBox {
                    padding: 8px;
                    spacing: 6px;
                    Text {
                        text: "Type to search. Click (or press Return on a match) to copy.";
                    }
                    LineEdit {
                        text <=> shelf-query;
                        placeholder-text: "Search kind or id";
                        edited => { query-changed(self.text); }
                        accepted => { pick(0); }
                    }
                    for line[i] in shelf-lines: Button {
                        text: line;
                        clicked => { pick(i); }
                    }
                }
            }
            Tab {
                title: "Capture";
                VerticalBox {
                    padding: 8px;
                    spacing: 8px;
                    Text {
                        text: "Put the current clipboard into Shelf (explicit, not surveillance).";
                        wrap: word-wrap;
                    }
                    Button {
                        text: "Capture clipboard";
                        clicked => { capture(); }
                    }
                    Text {
                        text: capture-status;
                        wrap: word-wrap;
                    }
                }
            }
            Tab {
                title: "Scratch";
                VerticalBox {
                    padding: 8px;
                    spacing: 6px;
                    TextEdit {
                        text: scratch-text;
                        read-only: true;
                        min-height: 140px;
                    }
                    LineEdit {
                        text <=> scratch-append;
                        placeholder-text: "Append to Scratch";
                        accepted => { scratch-submit(); }
                    }
                    Button {
                        text: "Append";
                        clicked => { scratch-submit(); }
                    }
                }
            }
            Tab {
                title: "Transfers";
                VerticalBox {
                    padding: 8px;
                    spacing: 6px;
                    Text { text: "File objects."; }
                    for line in transfer-lines: Text {
                        text: line;
                    }
                }
            }
            Tab {
                title: "Devices";
                VerticalBox {
                    padding: 8px;
                    spacing: 6px;
                    Text { text: "Vault members (list only)."; }
                    for line in device-lines: Text {
                        text: line;
                        wrap: word-wrap;
                    }
                }
            }
            Tab {
                title: "Settings";
                VerticalBox {
                    padding: 8px;
                    spacing: 8px;
                    Text { text: "Socket"; }
                    Text {
                        text: socket-path;
                        wrap: word-wrap;
                    }
                    Text {
                        text: home-note;
                        wrap: word-wrap;
                    }
                    Text {
                        text: "Bind your OS shortcut to shelf-desktop (no global hotkey crate).";
                        wrap: word-wrap;
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let socket = match resolve_socket_path(None, None) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("shelf-desktop: {err}");
            std::process::exit(1);
        }
    };
    let client = match Client::connect(&socket).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("shelf-desktop: {err}");
            eprintln!("Start shelfd, then run shelf-desktop again.");
            std::process::exit(1);
        }
    };
    let items = match client.ls().await {
        Ok(items) => items,
        Err(err) => {
            eprintln!("shelf-desktop: {err}");
            std::process::exit(1);
        }
    };
    let scratch = match client.scratch_get(DEFAULT_SCRATCH_PAD).await {
        Ok(text) => text,
        Err(err) => {
            eprintln!("shelf-desktop: scratch: {err}");
            String::new()
        }
    };
    let devices = match client.devices_list().await {
        Ok(devices) => devices,
        Err(err) => {
            eprintln!("shelf-desktop: devices: {err}");
            Vec::new()
        }
    };

    let all_lines: Vec<String> = listing_lines(&items);
    let ui = App::new().expect("app");
    let shelf_model = Rc::new(slint::VecModel::from(shared_strings(&visible_lines(
        &all_lines, "",
    ))));
    let transfer_model = Rc::new(slint::VecModel::from(shared_strings(&file_lines(
        &all_lines,
    ))));
    let device_model = Rc::new(slint::VecModel::from(shared_strings(&device_lines(
        &devices,
    ))));
    ui.set_shelf_lines(shelf_model.clone().into());
    ui.set_transfer_lines(transfer_model.clone().into());
    ui.set_device_lines(device_model.clone().into());
    ui.set_scratch_text(scratch.into());
    ui.set_socket_path(socket.display().to_string().into());
    ui.set_home_note(settings_home_note().into());

    let all = Rc::new(RefCell::new(all_lines));
    let all_q = all.clone();
    let model_q = shelf_model.clone();
    ui.on_query_changed(move |q| {
        apply_shelf_filter(&model_q, &all_q.borrow(), &q);
    });

    let ui_weak = ui.as_weak();
    let all_for_pick = all.clone();
    let socket_pick = socket.clone();
    ui.on_pick(move |index| {
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        let q = ui.get_shelf_query().to_string();
        let hits = filter_lines(&all_for_pick.borrow(), &q);
        let Some(&(orig, _)) = hits.get(usize::try_from(index).unwrap_or(0)) else {
            return;
        };
        let idx = u64::try_from(orig).unwrap_or(0).saturating_add(1);
        match ipc_get(&socket_pick, idx) {
            Ok(bytes) => {
                if let Err(err) = copy_clipboard(&bytes) {
                    eprintln!("shelf-desktop: {err}");
                }
            }
            Err(err) => eprintln!("shelf-desktop: {err}"),
        }
    });

    let ui_cap = ui.as_weak();
    let all_cap = all.clone();
    let shelf_cap = shelf_model;
    let xfer_cap = transfer_model;
    let socket_cap = socket.clone();
    ui.on_capture(move || {
        let Some(ui) = ui_cap.upgrade() else {
            return;
        };
        match capture_clipboard(&socket_cap) {
            Ok(id) => {
                ui.set_capture_status(format!("captured {id}").into());
                match ipc_ls(&socket_cap) {
                    Ok(items) => {
                        let lines = listing_lines(&items);
                        apply_shelf_filter(&shelf_cap, &lines, ui.get_shelf_query());
                        xfer_cap.set_vec(shared_strings(&file_lines(&lines)));
                        *all_cap.borrow_mut() = lines;
                    }
                    Err(err) => eprintln!("shelf-desktop: {err}"),
                }
            }
            Err(err) => {
                eprintln!("shelf-desktop: {err}");
                ui.set_capture_status(err.into());
            }
        }
    });

    let ui_scratch = ui.as_weak();
    let socket_scratch = socket;
    ui.on_scratch_submit(move || {
        let Some(ui) = ui_scratch.upgrade() else {
            return;
        };
        let text = ui.get_scratch_append().to_string();
        if text.is_empty() {
            return;
        }
        match ipc_scratch_append(&socket_scratch, &text) {
            Ok(pad) => {
                ui.set_scratch_text(pad.into());
                ui.set_scratch_append(slint::SharedString::new());
            }
            Err(err) => eprintln!("shelf-desktop: {err}"),
        }
    });

    eprintln!("Bind your OS shortcut (macOS: System Settings > Keyboard) to `shelf-desktop`.");
    ui.run().expect("run app");
}

fn listing_lines(items: &[ListedItem]) -> Vec<String> {
    items
        .iter()
        .map(|item| format_line(item.kind.as_wire_str(), &item.id.to_string()))
        .collect()
}

fn visible_lines(all: &[String], query: &str) -> Vec<String> {
    filter_lines(all, query)
        .into_iter()
        .map(|(_, line)| line)
        .collect()
}

fn file_lines(all: &[String]) -> Vec<String> {
    filter_file_lines(all)
        .into_iter()
        .map(|(_, line)| line)
        .collect()
}

fn device_lines(devices: &[ListedDevice]) -> Vec<String> {
    devices
        .iter()
        .map(|d| format_device_line(&d.device_id.to_string(), d.name.as_deref(), d.is_root))
        .collect()
}

fn shared_strings(lines: &[String]) -> Vec<slint::SharedString> {
    lines
        .iter()
        .map(|l| slint::SharedString::from(l.as_str()))
        .collect()
}

fn apply_shelf_filter(
    model: &slint::VecModel<slint::SharedString>,
    all: &[String],
    query: impl AsRef<str>,
) {
    model.set_vec(shared_strings(&visible_lines(all, query.as_ref())));
}

fn capture_clipboard(socket: &Path) -> Result<String, String> {
    let bytes = paste_clipboard()?;
    if bytes.is_empty() {
        return Err("clipboard is empty".into());
    }
    let kind = ContentKind::from_wire_str(infer_capture_kind(&bytes)).unwrap_or(ContentKind::Text);
    ipc_put(socket, &bytes, kind)
}

fn ipc_get(socket: &Path, index: u64) -> Result<Vec<u8>, String> {
    run_ipc(socket, move |rt, socket| {
        rt.block_on(async {
            let client = Client::connect(socket).await.map_err(|e| e.to_string())?;
            let obj = client
                .get(GetTarget::Index { index })
                .await
                .map_err(|e| e.to_string())?;
            Ok(obj.bytes)
        })
    })
}

fn ipc_ls(socket: &Path) -> Result<Vec<ListedItem>, String> {
    run_ipc(socket, |rt, socket| {
        rt.block_on(async {
            let client = Client::connect(socket).await.map_err(|e| e.to_string())?;
            client.ls().await.map_err(|e| e.to_string())
        })
    })
}

fn ipc_put(socket: &Path, bytes: &[u8], kind: ContentKind) -> Result<String, String> {
    let bytes = bytes.to_vec();
    run_ipc(socket, move |rt, socket| {
        rt.block_on(async {
            let client = Client::connect(socket).await.map_err(|e| e.to_string())?;
            let result = client
                .put(&bytes, kind, Some("clipboard"))
                .await
                .map_err(|e| e.to_string())?;
            Ok(result.id.to_string())
        })
    })
}

fn ipc_scratch_append(socket: &Path, text: &str) -> Result<String, String> {
    let text = text.to_owned();
    run_ipc(socket, move |rt, socket| {
        rt.block_on(async {
            let client = Client::connect(socket).await.map_err(|e| e.to_string())?;
            client
                .scratch_append(DEFAULT_SCRATCH_PAD, &text)
                .await
                .map_err(|e| e.to_string())
        })
    })
}

fn run_ipc<F, T>(socket: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(&tokio::runtime::Runtime, &Path) -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    let socket = PathBuf::from(socket);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        f(&rt, &socket)
    })
    .join()
    .unwrap_or_else(|_| Err("ipc thread panicked".into()))
}
