#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::get_identity,
            commands::generate_identity,
            commands::parse_recipient,
            commands::seal,
            commands::probe,
            commands::verify,
            commands::open_package,
            commands::list_trusted,
            commands::add_trusted,
            commands::remove_trusted,
            commands::get_settings,
            commands::set_settings,
            commands::receipt_fetch,
            commands::receipt_verify
        ])
        // Temporary viewing folders (open with `temp = true`) are removed when the window
        // goes away (best effort; a crash can leave one behind in the OS temp folder).
        .on_window_event(|_, event| {
            if let tauri::WindowEvent::Destroyed = event {
                commands::remove_view_dir();
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building sealdrop")
        .run(|_, event| {
            if let tauri::RunEvent::Exit = event {
                commands::remove_view_dir();
            }
        });
}
