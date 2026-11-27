// Shared loopback helpers: a synthetic device binding and a raw HTTP response writer.
fn synthetic_device_binding() -> LocalDeviceBinding {
    LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("a".repeat(64)),
        sources: vec!["codex".into()],
    }
}
fn loopback_response(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    use std::io::Write;
    write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
}
