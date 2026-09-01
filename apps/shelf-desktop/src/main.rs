//! `shelf-desktop` binary: searchable recent-item palette.

use shelf_client::{Client, GetTarget, resolve_socket_path};
use shelf_desktop::{copy_clipboard, filter_lines, format_line};
use std::rc::Rc;

slint::slint! {
    import { Button, VerticalBox, LineEdit } from "std-widgets.slint";

    export component Palette inherits Window {
        title: "Shelf";
        min-width: 480px;
        min-height: 320px;
        in-out property <[string]> lines: [];
        in-out property <string> query: "";
        callback pick(int);
        callback query-changed(string);
        VerticalBox {
            padding: 8px;
            spacing: 6px;
            Text {
                text: "Type to search. Click (or press Return on a match) to copy.";
            }
            LineEdit {
                text <=> query;
                placeholder-text: "Search kind or id";
                edited => { query-changed(self.text); }
                accepted => { pick(0); }
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
    let all_lines: Vec<String> = items
        .iter()
        .map(|item| format_line(item.kind.as_wire_str(), &item.id.to_string()))
        .collect();

    let ui = Palette::new().expect("palette");
    let visible = filter_lines(&all_lines, "");
    let model = Rc::new(slint::VecModel::from(
        visible
            .iter()
            .map(|(_, l)| slint::SharedString::from(l.as_str()))
            .collect::<Vec<_>>(),
    ));
    ui.set_lines(model.clone().into());

    let all = all_lines.clone();
    let model_q = model.clone();
    ui.on_query_changed(move |q| {
        let hits = filter_lines(&all, &q);
        model_q.set_vec(
            hits.iter()
                .map(|(_, l)| slint::SharedString::from(l.as_str()))
                .collect::<Vec<_>>(),
        );
    });

    let ui_weak = ui.as_weak();
    let all_for_pick = all_lines;
    ui.on_pick(move |index| {
        let q = ui_weak
            .upgrade()
            .map(|u| u.get_query().to_string())
            .unwrap_or_default();
        let hits = filter_lines(&all_for_pick, &q);
        let Some(&(orig, _)) = hits.get(usize::try_from(index).unwrap_or(0)) else {
            return;
        };
        let idx = u64::try_from(orig).unwrap_or(0).saturating_add(1);
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

    eprintln!("Bind your OS shortcut (macOS: System Settings > Keyboard) to `shelf-desktop`.");
    ui.run().expect("run palette");
}
