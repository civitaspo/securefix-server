use crate::api::GitHub;
use serde_json::Value;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

pub struct Route {
    method: &'static str,
    path: String,
    status: u16,
    response: Response,
    request_body: Option<Value>,
    request_header: Option<(&'static str, &'static str)>,
}

#[allow(dead_code)]
enum Response {
    Json(Value),
    Raw(Vec<u8>),
    Disconnect,
}

impl Route {
    pub fn get(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: "GET",
            path: path.into(),
            status: 200,
            response: Response::Json(body),
            request_body: None,
            request_header: None,
        }
    }
    pub fn request(
        method: &'static str,
        path: impl Into<String>,
        status: u16,
        body: Value,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            status,
            response: Response::Json(body),
            request_body: None,
            request_header: None,
        }
    }
    #[allow(dead_code)]
    pub fn raw(method: &'static str, path: impl Into<String>, status: u16, body: Vec<u8>) -> Self {
        Self {
            method,
            path: path.into(),
            status,
            response: Response::Raw(body),
            request_body: None,
            request_header: None,
        }
    }
    #[allow(dead_code)]
    pub fn disconnect(method: &'static str, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            status: 200,
            response: Response::Disconnect,
            request_body: None,
            request_header: None,
        }
    }
    pub fn with_request_body(mut self, body: Value) -> Self {
        self.request_body = Some(body);
        self
    }
    #[allow(dead_code)]
    pub fn with_request_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.request_header = Some((name, value));
        self
    }
}

pub struct Fixture {
    pub api: GitHub,
    thread: JoinHandle<()>,
}
impl Fixture {
    pub fn new(routes: Vec<Route>) -> Self {
        let monitor_extra_requests = routes
            .iter()
            .any(|route| matches!(route.response, Response::Disconnect));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let api = GitHub::new(
            &format!("http://{}", listener.local_addr().unwrap()),
            "fixture-token".into(),
        )
        .unwrap()
        .with_runtime_revision(&"a".repeat(40))
        .unwrap();
        let thread = thread::spawn(move || {
            for route in routes {
                let deadline = Instant::now() + Duration::from_secs(15);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "missing {} {}",
                                route.method,
                                route.path
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut buffer = [0u8; 4096];
                    let size = stream.read(&mut buffer).unwrap();
                    assert!(size > 0, "incomplete HTTP request");
                    request.extend_from_slice(&buffer[..size]);
                    if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        break index + 4;
                    }
                };
                let header = String::from_utf8(request[..header_end].to_vec()).unwrap();
                let first = header.lines().next().unwrap();
                assert_eq!(first, format!("{} {} HTTP/1.1", route.method, route.path));
                if let Some((name, value)) = route.request_header {
                    let values = header
                        .lines()
                        .filter_map(|line| {
                            line.split_once(':')
                                .and_then(|(header_name, header_value)| {
                                    header_name
                                        .eq_ignore_ascii_case(name)
                                        .then_some(header_value.trim())
                                })
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(values, [value], "expected exactly one {name} header");
                }
                let length = header
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|length| length.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while request.len() < header_end + length {
                    let mut buffer = [0u8; 4096];
                    let size = stream.read(&mut buffer).unwrap();
                    assert!(size > 0);
                    request.extend_from_slice(&buffer[..size]);
                }
                if let Some(expected) = route.request_body {
                    let body: Value =
                        serde_json::from_slice(&request[header_end..header_end + length]).unwrap();
                    assert_eq!(
                        body, expected,
                        "unexpected request body for {} {}",
                        route.method, route.path
                    );
                }
                let body = match route.response {
                    Response::Json(body) => serde_json::to_vec(&body).unwrap(),
                    Response::Raw(body) => body,
                    Response::Disconnect => continue,
                };
                write!(stream,"HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",route.status,body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
            if monitor_extra_requests {
                let deadline = Instant::now() + Duration::from_millis(25);
                while Instant::now() < deadline {
                    match listener.accept() {
                        Ok(_) => panic!("unexpected extra API request"),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("{error}"),
                    }
                }
            }
        });
        Self { api, thread }
    }
    pub fn finish(self) {
        self.thread.join().unwrap();
    }
}
