// Shared loopback helpers and bounded checkpoint coverage.
fn bounded_native_device() -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("a".repeat(64)),
        sources: vec!["codex".into()],
    }
}
fn bounded_native_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    use std::io::Write;
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
}
