//! The Nullhawk desktop shell.
//!
//! The shell is deliberately thin. All application state — projects, traffic, scan
//! jobs — lives in the Rust core, and the React frontend is a view over it. Putting
//! state in the frontend would mean the CLI and the desktop client could disagree
//! about what a project contains, and it would put security-relevant logic in the
//! most easily influenced part of the process.
//!
//! So the only thing crossing the IPC boundary is a versioned command surface:
//!
//! ```text
//! React ──invoke()──→ Tauri IPC ──→ commands ──→ nullhawk-engine / nullhawk-storage
//! ```
//!
//! Commands are added only as the milestone that implements them lands, so the
//! surface never advertises capability that does not exist. At M12.4 it covers
//! projects, the proxy, history, the repeater, the certificate authority, project
//! scope, identities, declared objects, the authorization matrix with
//! constructed attempts, findings and the report — everything
//! the CLI can do, calling exactly the same crates.
//!
//! # State lives in Rust
//!
//! [`state::AppState`] holds the open project and the running proxy. The frontend
//! holds only what it is currently rendering, and re-asks after anything that could
//! change the answer.

pub mod cloud;
pub mod commands;
pub mod mobile;
pub mod preview;
pub mod state;

pub use commands::EngineInfo;
pub use preview::{BodyPreview, Rendering};
pub use state::AppState;

/// Builds and runs the desktop application.
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("nullhawk=info")),
        )
        .init();

    tauri::Builder::default()
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::engine_info,
            commands::project_open,
            commands::pick_directory,
            commands::pick_file,
            commands::jwt_crack,
            commands::project_current,
            commands::proxy_start,
            commands::proxy_stop,
            commands::proxy_status,
            commands::history_list,
            commands::history_detail,
            commands::license_status,
            commands::license_activate,
            commands::license_start_trial,
            commands::sitemap_build,
            commands::fingerprint_scan,
            commands::crawl_run,
            commands::llm_test,
            commands::oob_test,
            commands::fuzz_slots,
            commands::fuzz_run,
            commands::bypass_run,
            commands::websocket_sessions,
            commands::websocket_messages,
            commands::repeater_draft,
            commands::repeater_new,
            commands::repeater_send,
            commands::repeater_send_raw_h2,
            commands::repeater_tree,
            commands::ca_status,
            commands::ca_install,
            commands::ca_untrust,
            mobile::mobile_setup,
            mobile::mobile_onboarding_start,
            mobile::mobile_onboarding_stop,
            mobile::mobile_analyze,
            cloud::cloud_validate_aws,
            cloud::cloud_aws_blast_radius,
            cloud::cloud_validate_gcp,
            cloud::cloud_validate_azure,
            commands::scope_list,
            commands::scope_add,
            commands::scope_remove,
            commands::matchreplace_list,
            commands::matchreplace_add,
            commands::matchreplace_remove,
            commands::matchreplace_set_enabled,
            commands::check_list,
            commands::check_add,
            commands::check_remove,
            commands::check_set_enabled,
            commands::import_parse,
            commands::import_send,
            commands::graphql_parse,
            commands::graphql_send,
            commands::sequencer_run,
            commands::domxss_run,
            commands::race_run,
            commands::header_list,
            commands::header_add,
            commands::header_remove,
            commands::programme_show,
            commands::programme_set,
            commands::programme_exclude,
            commands::programme_allow,
            commands::identities_list,
            commands::identity_add,
            commands::identity_remove,
            commands::identity_renew,
            commands::objects_list,
            commands::object_add,
            commands::object_remove,
            commands::candidates_list,
            commands::candidates_analyze,
            commands::candidate_decide,
            commands::finding_reproduction,
            commands::scan_passive,
            commands::scan_active_plan,
            commands::scan_active_run,
            commands::scan_active_stop,
            commands::scan_active_running,
            commands::detectors_list,
            commands::snapshots_list,
            commands::snapshot_take,
            commands::snapshot_delete,
            commands::snapshot_compare,
            commands::authz_run,
            commands::findings_list,
            commands::findings_detail,
            commands::findings_triage,
            commands::report_render,
        ])
        .setup(|app| {
            use tauri::{LogicalSize, Manager};
            // Fit the window to the actual monitor at startup — any resolution, any DPI —
            // rather than a fixed size that can run under the taskbar on a smaller or scaled
            // display. The tauri.conf.json size is only the fallback if this can't resolve.
            if let Some(window) = app.get_webview_window("main") {
                if let Ok(Some(monitor)) = window.primary_monitor() {
                    let scale = monitor.scale_factor();
                    let phys = monitor.size();
                    let screen_w = phys.width as f64 / scale;
                    let screen_h = phys.height as f64 / scale;
                    // Leave room for the taskbar and title bar; cap so it isn't vast on a big
                    // screen, floor at the usable minimum the config declares.
                    let w = (screen_w - 60.0).clamp(960.0, 1560.0);
                    let h = (screen_h - 110.0).clamp(600.0, 1040.0);
                    let _ = window.set_size(LogicalSize::new(w, h));
                    let _ = window.center();
                }
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to start the Nullhawk desktop shell");
}
