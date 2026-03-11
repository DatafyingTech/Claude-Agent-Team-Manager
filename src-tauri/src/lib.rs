mod remote;

use remote::{RelayClient, PersistentRelayClient, PairedDeviceInfo, ServerHandle};
use std::process::Command as StdCommand;
use std::sync::Mutex;
use tauri::{Emitter, Manager};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// ─── Existing Tauri Commands ────────────────────────────────────────

/// Creates a scheduled task that runs a PowerShell script at the specified time.
/// On Windows, uses schtasks.exe. On macOS/Linux, uses crontab.
#[tauri::command]
fn create_scheduled_task(
    task_name: String,
    script_path: String,
    start_time: String,
    start_date: String,
    repeat: String,
) -> Result<String, String> {
    // Reject null bytes in script_path (all platforms)
    if script_path.contains('\0') {
        return Err("script_path contains null bytes".to_string());
    }

    // Validate file extension
    #[cfg(target_os = "windows")]
    {
        if !script_path.to_lowercase().ends_with(".ps1") {
            return Err("script_path must end with .ps1 on Windows".to_string());
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let lower = script_path.to_lowercase();
        if !lower.ends_with(".sh") && !lower.ends_with(".bash") {
            return Err("script_path must end with .sh or .bash on Unix".to_string());
        }
    }

    // Platform-specific dangerous character validation
    #[cfg(target_os = "windows")]
    {
        if script_path.contains('&') || script_path.contains('|') || script_path.contains('`') {
            return Err("script_path contains dangerous characters".to_string());
        }
    }

    #[cfg(target_os = "windows")]
    {
        let tn = format!("AUI\\{}", task_name);
        let tr = format!(
            "powershell.exe -ExecutionPolicy Bypass -File \"{}\"",
            script_path
        );

        // Map repeat type to schtasks /SC value
        let sc = match repeat.as_str() {
            "hourly" => "HOURLY",
            "daily" => "DAILY",
            "weekly" => "WEEKLY",
            "monthly" => "MONTHLY",
            _ => "ONCE",
        };

        let mut args = vec![
            "/Create".to_string(),
            "/TN".to_string(),
            tn.clone(),
            "/TR".to_string(),
            tr,
            "/SC".to_string(),
            sc.to_string(),
            "/ST".to_string(),
            start_time.clone(),
            "/F".to_string(), // Force overwrite if exists
        ];

        // Add start date for non-hourly schedules
        if sc != "HOURLY" && !start_date.is_empty() {
            args.push("/SD".to_string());
            args.push(start_date.clone());
        }

        let output = StdCommand::new("schtasks.exe")
            .args(&args)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map_err(|e| format!("Failed to run schtasks: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("schtasks failed: {}", stderr));
        }

        Ok(format!("Created scheduled task: {}", tn))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let cron_line = match repeat.as_str() {
            "hourly" => format!("0 * * * *"),
            "daily" => {
                let parts: Vec<&str> = start_time.split(':').collect();
                let hour = parts.get(0).unwrap_or(&"9");
                let min = parts.get(1).unwrap_or(&"0");
                format!("{} {} * * *", min, hour)
            }
            "weekly" => {
                let parts: Vec<&str> = start_time.split(':').collect();
                let hour = parts.get(0).unwrap_or(&"9");
                let min = parts.get(1).unwrap_or(&"0");
                format!("{} {} * * 1", min, hour)
            }
            "monthly" => {
                let parts: Vec<&str> = start_time.split(':').collect();
                let hour = parts.get(0).unwrap_or(&"9");
                let min = parts.get(1).unwrap_or(&"0");
                format!("{} {} 1 * *", min, hour)
            }
            _ => {
                let parts: Vec<&str> = start_time.split(':').collect();
                let hour = parts.get(0).unwrap_or(&"9");
                let min = parts.get(1).unwrap_or(&"0");
                format!("{} {} * * *", min, hour)
            }
        };

        // Escape single quotes to prevent shell injection in crontab entry
        let safe_path = script_path.replace("'", "'\\''");
        let safe_name = task_name.replace("'", "'\\''");

        let entry = format!(
            "{} /bin/bash '{}' # AUI:{}\n",
            cron_line, safe_path, safe_name
        );

        let existing = StdCommand::new("crontab")
            .arg("-l")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let new_crontab = format!("{}{}", existing, entry);

        let mut child = StdCommand::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to set crontab: {}", e))?;

        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(new_crontab.as_bytes())
                .map_err(|e| format!("Failed to write crontab: {}", e))?;
        }

        child
            .wait()
            .map_err(|e| format!("crontab process error: {}", e))?;

        Ok(format!("Created cron job: AUI:{}", task_name))
    }
}

/// Lists all AUI scheduled tasks.
#[tauri::command]
fn list_scheduled_tasks() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let output = StdCommand::new("schtasks.exe")
            .args(&["/Query", "/FO", "CSV", "/NH", "/TN", "AUI\\*"])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("Failed to query schtasks: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(stdout)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = StdCommand::new("crontab")
            .arg("-l")
            .output()
            .map_err(|e| format!("Failed to read crontab: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let aui_entries: Vec<&str> = stdout
            .lines()
            .filter(|line| line.contains("# AUI:"))
            .collect();
        Ok(aui_entries.join("\n"))
    }
}

/// Deletes a scheduled task by name.
#[tauri::command]
fn delete_scheduled_task(task_name: String) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        let tn = format!("AUI\\{}", task_name);
        let output = StdCommand::new("schtasks.exe")
            .args(&["/Delete", "/TN", &tn, "/F"])
            .creation_flags(0x08000000)
            .output()
            .map_err(|e| format!("Failed to run schtasks: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("schtasks delete failed: {}", stderr));
        }

        Ok(format!("Deleted scheduled task: {}", tn))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let marker = format!("# AUI:{}", task_name);

        let existing = StdCommand::new("crontab")
            .arg("-l")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let filtered: Vec<&str> = existing
            .lines()
            .filter(|line| !line.contains(&marker))
            .collect();
        let new_crontab = format!("{}\n", filtered.join("\n"));

        let mut child = StdCommand::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to set crontab: {}", e))?;

        use std::io::Write;
        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(new_crontab.as_bytes())
                .map_err(|e| format!("Failed to write crontab: {}", e))?;
        }

        child
            .wait()
            .map_err(|e| format!("crontab process error: {}", e))?;

        Ok(format!("Deleted cron job: AUI:{}", task_name))
    }
}

/// Opens a visible terminal window running the given script.
#[tauri::command]
fn open_terminal(script_path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let raw = format!(
            "/c start \"Deploy\" powershell.exe -NoExit -ExecutionPolicy Bypass -File \"{}\"",
            script_path
        );
        StdCommand::new("cmd.exe")
            .raw_arg(raw)
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|e| format!("Failed to open terminal: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        let apple_script = format!(
            r#"tell application "Terminal"
            activate
            do script "bash '{}'"
        end tell"#,
            script_path.replace("'", "'\\''")
        );
        StdCommand::new("osascript")
            .args(&["-e", &apple_script])
            .spawn()
            .map_err(|e| format!("Failed to open terminal: {}", e))?;
    }

    #[cfg(target_os = "linux")]
    {
        let terminals = [
            ("x-terminal-emulator", vec!["-e", &script_path]),
            ("gnome-terminal", vec!["--", &script_path]),
            ("xterm", vec!["-e", &script_path]),
        ];
        let mut launched = false;
        for (term, args) in &terminals {
            if StdCommand::new(term).args(args).spawn().is_ok() {
                launched = true;
                break;
            }
        }
        if !launched {
            return Err("No terminal emulator found".into());
        }
    }

    Ok(())
}

/// Fetches a URL and returns its body as a string.
#[tauri::command]
fn fetch_url(url: String) -> Result<String, String> {
    // Validate URL scheme: only allow HTTPS
    if !url.starts_with("https://") {
        return Err("Only https:// URLs are allowed".to_string());
    }

    // Block private/internal IP ranges to prevent SSRF
    let url_lower = url.to_lowercase();
    let private_patterns = [
        "localhost",
        "127.",
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "169.254.",
        "0.0.0.0",
        "[::1]",
        "::1",
    ];
    // Extract the host portion (after "https://") for checking
    let after_scheme = &url_lower["https://".len()..];
    for pattern in &private_patterns {
        if after_scheme.starts_with(pattern) {
            return Err(format!("Access to private/internal addresses is blocked: {}", pattern));
        }
    }

    let output = StdCommand::new("curl")
        .args(&["-sL", "--max-time", "15", "--max-filesize", "10485760", &url])
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("HTTP request failed: {}", stderr));
    }

    String::from_utf8(output.stdout)
        .map_err(|e| format!("Invalid UTF-8 in response: {}", e))
}

// ─── Remote Access Tauri Commands ───────────────────────────────────
//
// NOTE: open_terminal, fetch_url, and create_scheduled_task are NOT
// exposed to remote clients (M5). These commands are desktop-only.

/// Start the remote access server. Called from the frontend when user enables remote access.
#[tauri::command]
async fn start_remote_server(
    app: tauri::AppHandle,
    port: Option<u16>,
    expose_on_network: Option<bool>,
) -> Result<serde_json::Value, String> {
    // Check if already running.
    if let Some(state) = app.try_state::<Mutex<Option<ServerHandle>>>() {
        let guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        if guard.is_some() {
            return Err("Remote server is already running".to_string());
        }
    }

    let config = remote::ServerConfig {
        port: port.unwrap_or(5175),
        expose_on_network: expose_on_network.unwrap_or(false),
        static_dir: app
            .path()
            .resource_dir()
            .ok()
            .map(|p| p.join("remote-ui").to_string_lossy().to_string()),
    };

    let handle = remote::start_server(config, app.clone()).await?;

    let pin = handle.auth.get_pin().await;
    let actual_port = handle.actual_port;
    let cert_fingerprint = handle.cert_fingerprint.clone();

    let ip = local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string());

    let url = format!("https://{}:{}", ip, actual_port);

    // Store the server handle in Tauri managed state.
    app.manage(Mutex::new(Some(handle)));

    // Emit event to frontend.
    let _ = app.emit(
        "remote-server-started",
        serde_json::json!({
            "url": url,
            "port": actual_port,
            "ip": ip,
            "pin": pin,
            "certFingerprint": cert_fingerprint,
        }),
    );

    Ok(serde_json::json!({
        "url": url,
        "port": actual_port,
        "ip": ip,
        "pin": pin,
        "certFingerprint": cert_fingerprint,
    }))
}

/// Stop the remote access server.
#[tauri::command]
async fn stop_remote_server(app: tauri::AppHandle) -> Result<(), String> {
    let state = app
        .try_state::<Mutex<Option<ServerHandle>>>()
        .ok_or("Server not initialized")?;

    // Extract auth clone and shutdown inside a sync block to avoid holding
    // the MutexGuard across an await point (MutexGuard is not Send).
    let auth_clone = {
        let mut guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        match guard.as_mut() {
            Some(handle) => {
                let auth = handle.auth.clone();
                handle.shutdown();
                *guard = None;
                Some(auth)
            }
            None => None,
        }
    };

    match auth_clone {
        Some(auth) => {
            auth.revoke_all_sessions().await;
            let _ = app.emit("remote-server-stopped", serde_json::json!({}));
            Ok(())
        }
        None => Err("Remote server is not running".to_string()),
    }
}

/// Get the current remote server status.
#[tauri::command]
async fn get_remote_status(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let state = app.try_state::<Mutex<Option<ServerHandle>>>();

    let info = match state {
        Some(state) => {
            let guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
            match guard.as_ref() {
                Some(handle) => Some((
                    handle.actual_port,
                    handle.cert_fingerprint.clone(),
                    handle.auth.clone(),
                )),
                None => None,
            }
        }
        None => None,
    };

    match info {
        Some((port, fingerprint, auth)) => {
            let sessions = auth.active_sessions().await;
            let ip = local_ip_address::local_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| "127.0.0.1".to_string());

            Ok(serde_json::json!({
                "running": true,
                "port": port,
                "url": format!("https://{}:{}", ip, port),
                "certFingerprint": fingerprint,
                "activeSessions": sessions,
            }))
        }
        None => Ok(serde_json::json!({ "running": false })),
    }
}

/// Get the current PIN (displayed on desktop for the user to share with their phone).
#[tauri::command]
async fn get_remote_pin(app: tauri::AppHandle) -> Result<String, String> {
    let state = app
        .try_state::<Mutex<Option<ServerHandle>>>()
        .ok_or("Server not initialized")?;

    let auth = {
        let guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        match guard.as_ref() {
            Some(handle) => Ok(handle.auth.clone()),
            None => Err("Remote server is not running".to_string()),
        }
    }?;

    Ok(auth.get_pin().await)
}

/// Broadcast an event to all connected remote WebSocket clients via the bridge.
/// Called from the frontend when local state changes need to be pushed to mobile clients.
#[tauri::command]
fn broadcast_to_remote(
    app: tauri::AppHandle,
    event_type: String,
    payload: serde_json::Value,
) -> Result<(), String> {
    let state = app
        .try_state::<Mutex<Option<ServerHandle>>>()
        .ok_or("Server not initialized")?;

    let bridge = {
        let guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        match guard.as_ref() {
            Some(handle) => Ok(handle.bridge.clone()),
            None => Err("Remote server is not running".to_string()),
        }
    }?;

    // Generate a simple unique ID using random bytes from rand (already a dependency).
    let mut rng = rand::rng();
    let bytes: [u8; 8] = rand::Rng::random(&mut rng);
    let id = hex::encode(bytes);
    bridge.broadcast_event(&event_type, &id, payload);
    Ok(())
}

/// Push the full app state to the Rust shared state so the REST API
/// and new WebSocket clients can access it without going through WebSocket.
#[tauri::command]
async fn sync_state_to_remote(
    app: tauri::AppHandle,
    nodes: serde_json::Value,
    layouts: serde_json::Value,
    settings: serde_json::Value,
) -> Result<(), String> {
    let state = app
        .try_state::<Mutex<Option<ServerHandle>>>()
        .ok_or("Server not initialized")?;

    let bridge = {
        let guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        match guard.as_ref() {
            Some(handle) => Ok(handle.bridge.clone()),
            None => Err("Remote server is not running".to_string()),
        }
    }?;

    bridge.store_full_state(nodes, layouts, settings).await;
    Ok(())
}

/// Regenerate the remote access PIN.
#[tauri::command]
async fn regenerate_remote_pin(app: tauri::AppHandle) -> Result<String, String> {
    let state = app
        .try_state::<Mutex<Option<ServerHandle>>>()
        .ok_or("Server not initialized")?;

    let auth = {
        let guard = state.lock().map_err(|e| format!("Lock error: {}", e))?;
        match guard.as_ref() {
            Some(handle) => Ok(handle.auth.clone()),
            None => Err("Remote server is not running".to_string()),
        }
    }?;

    Ok(auth.regenerate_pin().await)
}

/// Generate a QR code data URI for the given URL.
#[tauri::command]
fn generate_qr_code(url: String) -> Result<String, String> {
    remote::generate_qr_data_uri(&url)
}

// ─── Cloud Relay Commands ───────────────────────────────────────────

/// Connect to the cloud relay server and create a room.
#[tauri::command]
async fn connect_to_relay(
    app: tauri::AppHandle,
    relay_url: String,
    public_key: String,
) -> Result<serde_json::Value, String> {
    // Check if already connected
    if let Some(state) = app.try_state::<tokio::sync::Mutex<Option<RelayClient>>>() {
        let guard = state.lock().await;
        if guard.is_some() {
            return Err("Already connected to relay".to_string());
        }
    }

    let client = RelayClient::connect(&relay_url, &public_key, app.clone()).await?;
    let room_code = client.room_code.clone();

    // Emit room created event
    let _ = app.emit(
        "relay:room-created",
        serde_json::json!({ "room_code": room_code }),
    );

    {
        let state = app
            .try_state::<tokio::sync::Mutex<Option<RelayClient>>>()
            .ok_or("Relay state not initialized")?;
        let mut guard = state.lock().await;
        *guard = Some(client);
    }

    Ok(serde_json::json!({
        "room_code": room_code,
    }))
}

/// Disconnect from the cloud relay.
#[tauri::command]
async fn disconnect_from_relay(app: tauri::AppHandle) -> Result<(), String> {
    let state = app
        .try_state::<tokio::sync::Mutex<Option<RelayClient>>>()
        .ok_or("Relay not initialized")?;

    let mut guard = state.lock().await;
    if let Some(client) = guard.take() {
        client.disconnect();
    }

    let _ = app.emit("relay:disconnected", serde_json::json!({}));
    Ok(())
}

/// Get the current relay connection status.
#[tauri::command]
async fn get_relay_status(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let state = app.try_state::<tokio::sync::Mutex<Option<RelayClient>>>();

    match state {
        Some(state) => {
            let guard = state.lock().await;
            match guard.as_ref() {
                Some(client) => Ok(serde_json::json!({
                    "connected": true,
                    "room_code": client.room_code,
                })),
                None => Ok(serde_json::json!({ "connected": false })),
            }
        }
        None => Ok(serde_json::json!({ "connected": false })),
    }
}

/// Send an encrypted message to the relay (forwarded to mobile peer).
/// Checks persistent relay client first, then falls back to ephemeral.
#[tauri::command]
async fn send_to_relay(app: tauri::AppHandle, data: String) -> Result<(), String> {
    // Try persistent client first
    if let Some(state) = app.try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>() {
        let guard = state.lock().await;
        if let Some(client) = guard.as_ref() {
            return client.send(&data);
        }
    }

    // Fall back to ephemeral client
    let state = app
        .try_state::<tokio::sync::Mutex<Option<RelayClient>>>()
        .ok_or("Relay not initialized")?;

    let guard = state.lock().await;
    match guard.as_ref() {
        Some(client) => client.send(&data),
        None => Err("Not connected to relay".to_string()),
    }
}

// ─── Persistent Relay (Pairing) Commands ────────────────────────────

/// Register desktop with relay for persistent pairing.
#[tauri::command]
async fn register_desktop_relay(
    app: tauri::AppHandle,
    relay_url: String,
    desktop_device_id: String,
    public_key: String,
) -> Result<(), String> {
    // Check if already registered
    if let Some(state) = app.try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>() {
        let guard = state.lock().await;
        if guard.is_some() {
            return Err("Already registered with relay".to_string());
        }
    }

    let client = PersistentRelayClient::connect(
        &relay_url,
        &desktop_device_id,
        &public_key,
        app.clone(),
    )
    .await?;

    {
        let state = app
            .try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>()
            .ok_or("Persistent relay state not initialized")?;
        let mut guard = state.lock().await;
        *guard = Some(client);
    }

    Ok(())
}

/// Disconnect from persistent relay.
#[tauri::command]
async fn disconnect_desktop_relay(app: tauri::AppHandle) -> Result<(), String> {
    let state = app
        .try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>()
        .ok_or("Persistent relay not initialized")?;

    let mut guard = state.lock().await;
    if let Some(client) = guard.take() {
        client.disconnect();
    }

    let _ = app.emit("relay:disconnected", serde_json::json!({}));
    Ok(())
}

/// Issue a pairing token to the currently connected mobile peer.
/// Returns { token, pairing_id, expires_at }.
#[tauri::command]
async fn issue_pairing_token(
    app: tauri::AppHandle,
    desktop_device_id: String,
    desktop_public_key: String,
    device_name: String,
) -> Result<serde_json::Value, String> {
    let state = app
        .try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>()
        .ok_or("Persistent relay not initialized")?;

    let guard = state.lock().await;
    let client = guard.as_ref().ok_or("Not registered with relay")?;

    if client.desktop_device_id != desktop_device_id {
        return Err("Desktop device ID mismatch".to_string());
    }

    let (token, pairing_id, expires_at) = client
        .issue_pairing_token(&desktop_public_key, &device_name)
        .await?;

    Ok(serde_json::json!({
        "token": token,
        "pairing_id": pairing_id,
        "expires_at": expires_at,
    }))
}

/// List locally tracked paired devices.
#[tauri::command]
async fn list_paired_devices(
    app: tauri::AppHandle,
    desktop_device_id: String,
) -> Result<Vec<PairedDeviceInfo>, String> {
    let state = app
        .try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>()
        .ok_or("Persistent relay not initialized")?;

    let guard = state.lock().await;
    let client = guard.as_ref().ok_or("Not registered with relay")?;

    if client.desktop_device_id != desktop_device_id {
        return Err("Desktop device ID mismatch".to_string());
    }

    Ok(client.list_paired_devices().await)
}

/// Revoke a specific pairing.
#[tauri::command]
async fn revoke_pairing(
    app: tauri::AppHandle,
    pairing_id: String,
) -> Result<(), String> {
    let state = app
        .try_state::<tokio::sync::Mutex<Option<PersistentRelayClient>>>()
        .ok_or("Persistent relay not initialized")?;

    let guard = state.lock().await;
    let client = guard.as_ref().ok_or("Not registered with relay")?;

    client.revoke_pairing(&pairing_id)
}

// ─── App Entry Point ────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            // Existing commands (desktop-only, NOT exposed remotely per M5).
            open_terminal,
            fetch_url,
            create_scheduled_task,
            list_scheduled_tasks,
            delete_scheduled_task,
            // Remote access commands.
            start_remote_server,
            stop_remote_server,
            get_remote_status,
            get_remote_pin,
            regenerate_remote_pin,
            generate_qr_code,
            broadcast_to_remote,
            sync_state_to_remote,
            // Cloud relay commands.
            connect_to_relay,
            disconnect_from_relay,
            get_relay_status,
            send_to_relay,
            // Persistent pairing commands.
            register_desktop_relay,
            disconnect_desktop_relay,
            issue_pairing_token,
            list_paired_devices,
            revoke_pairing,
        ])
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            // Initialize the remote server handle slot (server is OFF by default).
            app.manage(Mutex::new(None::<ServerHandle>));

            // Initialize the relay client slot (relay is OFF by default).
            app.manage(tokio::sync::Mutex::new(None::<RelayClient>));

            // Initialize the persistent relay client slot.
            app.manage(tokio::sync::Mutex::new(None::<PersistentRelayClient>));

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
