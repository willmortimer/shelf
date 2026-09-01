//! `shelf-desktop` binary: searchable recent-item palette.

use shelf_client::{Client, GetTarget, resolve_socket_path};
use shelf_desktop::format_line;
use std::rc::Rc;

slint::slint! {
    import { Button, VerticalBox } from "std-widgets.slint";

    export component Palette inherits Window {
        title: "Shelf";
        min-width: 420px;
        min-height: 280px;
        in-out property <[string]> lines: [];
        callback pick(int);
        VerticalBox {
            padding: 8px;
            spacing: 4px;
            Text {
                text: "Select an item to copy. Close when done.";
            }
            for line[i] in lines: Button {
                text: line;
                clicked => { pick(i); }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let socket = resolve_socket_path(None, None);
    let client = match Client::connect(&socket).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("shelf-desktop: {err}");
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
    let lines: Vec<slint::SharedString> = items
        .iter()
        .map(|item| {
            slint::SharedString::from(format_line(item.kind.as_wire_str(), &item.id.to_string()))
        })
        .collect();

    let ui = Palette::new().expect("palette");
    let model = Rc::new(slint::VecModel::from(lines));
    ui.set_lines(model.into());

    let ui_weak = ui.as_weak();
    ui.on_pick(move |index| {
        let idx = u64::try_from(index).unwrap_or(0).saturating_add(1);
        let socket = socket.clone();
        let result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio");
            rt.block_on(async {
                let client = Client::connect(&socket).await?;
                client.get(GetTarget::Index { index: idx }).await
            })
        })
        .join()
        .expect("join");
        match result {
            Ok(obj) => {
                if let Err(err) = copy_clipboard(&obj.bytes) {
                    eprintln!("shelf-desktop: {err}");
                }
                if let Some(ui) = ui_weak.upgrade() {
                    let _ = ui.hide();
                }
            }
            Err(err) => eprintln!("shelf-desktop: {err}"),
        }
    });

    ui.run().expect("run palette");
}

fn copy_clipboard(bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = if cfg!(target_os = "macos") {
        Command::new("pbcopy")
    } else if cfg!(target_os = "linux") {
        Command::new("wl-copy")
    } else {
        return Err("no clipboard tool on this platform".into());
    };
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::null());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bytes).map_err(|e| e.to_string())?;
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("clipboard copy failed".into())
    }
}
