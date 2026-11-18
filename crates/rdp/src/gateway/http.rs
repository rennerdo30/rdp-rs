//! The HTTP/1.1 requests and responses of the RD Gateway transport setup:
//! for the HTTP transport (MS-TSGU 3.3.5.1, 3.3.5.3.1) a WebSocket Upgrade
//! request (RFC 6455 4.1), for the RPC transport the RPC_IN_DATA and
//! RPC_OUT_DATA channel requests (MS-RPCH 2.1.2.1.1, 2.1.2.1.2); both
//! authenticated with `Authorization: NTLM` (RFC 4559 style).

use crate::error::{Result, proto};

/// The gateway's resource path (MS-TSGU 4.2.1 step 1).
pub const PATH: &str = "/remoteDesktopGateway/";

/// The WebSocket Upgrade request with the RDG-Connection-Id header (2.2.3.2.1).
pub fn upgrade_request(
    host: &str,
    port: u16,
    ws_key: &str,
    connection_id: &str,
    authorization: &str,
) -> String {
    let host = host_header(host, port);
    format!(
        "GET {PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Accept: */*\r\n\
         Cache-Control: no-cache\r\n\
         Pragma: no-cache\r\n\
         User-Agent: MS-RDGateway/1.0\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {ws_key}\r\n\
         RDG-Connection-Id: {connection_id}\r\n\
         Authorization: {authorization}\r\n\
         \r\n"
    )
}

/// The RPC over HTTP proxy path and the TsProxy endpoint behind it: the
/// gateway's own RPC server on port 3388 (MS-RPCH 2.2.2, MS-TSGU 2.1.1).
pub const RPC_PATH: &str = "/rpc/rpcproxy.dll?localhost:3388";

/// The Host header value: the port only when it is not 443.
fn host_header(host: &str, port: u16) -> String {
    if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// An IN (`RPC_IN_DATA`) or OUT (`RPC_OUT_DATA`) channel request head
/// (MS-RPCH 2.1.2.1.1, 2.1.2.1.2); the PDU stream follows as its body.
/// `session_id` is a UUID without braces.
pub fn rpc_channel_request(
    method: &str,
    host: &str,
    port: u16,
    content_length: u32,
    session_id: &str,
    authorization: &str,
) -> String {
    let host = host_header(host, port);
    format!(
        "{method} {RPC_PATH} HTTP/1.1\r\n\
         Accept: application/rpc\r\n\
         Cache-Control: no-cache\r\n\
         Connection: Keep-Alive\r\n\
         Content-Length: {content_length}\r\n\
         User-Agent: MSRPC\r\n\
         Host: {host}\r\n\
         Pragma: No-cache, ResourceTypeUuid=44e265dd-7daf-42cd-8560-3cdb6e7a2729, SessionId={session_id}\r\n\
         Authorization: {authorization}\r\n\
         \r\n"
    )
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// The reason phrase; an RPC proxy puts "RPC Error: <hex>" here
    /// (MS-RPCH 2.1.2.1.3).
    pub reason: String,
    pub headers: Vec<(String, String)>,
    /// Length of the head including the empty line.
    pub head_len: usize,
}

impl Response {
    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values of header `name`, one per header line (WWW-Authenticate
    /// values may contain commas, so they are not split).
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Body length from Content-Length, 0 if absent.
    pub fn content_length(&self) -> Result<usize> {
        match self.header("Content-Length") {
            None => Ok(0),
            Some(v) => v
                .trim()
                .parse()
                .or_else(|_| proto(format!("bad Content-Length {v:?}"))),
        }
    }

    /// The error code of an RPC proxy's "RPC Error: <hex>[, EEInfo: ...]"
    /// reason phrase (MS-RPCH 2.1.2.1.3).
    pub fn rpc_error(&self) -> Option<u32> {
        let rest = self.reason.strip_prefix("RPC Error: ")?;
        let hex = rest.split([',', ' ']).next()?;
        u32::from_str_radix(hex, 16).ok()
    }

    /// Whether any WWW-Authenticate header offers `scheme`, with or without
    /// a token.
    pub fn offers(&self, scheme: &str) -> bool {
        self.headers_named("WWW-Authenticate").any(|v| {
            v.split(' ')
                .next()
                .is_some_and(|s| s.eq_ignore_ascii_case(scheme))
        })
    }

    /// The token of `WWW-Authenticate: <scheme> <token>`, base64-decoded.
    pub fn auth_token(&self, scheme: &str) -> Result<Option<Vec<u8>>> {
        for v in self.headers_named("WWW-Authenticate") {
            let v = v.trim();
            let Some((s, token)) = v.split_once(' ') else {
                continue;
            };
            if s.eq_ignore_ascii_case(scheme) {
                return super::ws::base64_decode(token.trim()).map(Some);
            }
        }
        Ok(None)
    }
}

/// Parses the response head at the start of `buf` once it is complete.
pub fn parse_response(buf: &[u8]) -> Result<Option<Response>> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > 64 * 1024 {
            return proto("HTTP response head too long");
        }
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end])
        .map_err(|_| crate::Error::Protocol("HTTP response head is not UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return proto(format!("not an HTTP response: {status_line:?}"));
    }
    let status = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| crate::Error::Protocol(format!("bad status line {status_line:?}")))?;
    let reason = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for line in lines {
        let Some((n, v)) = line.split_once(':') else {
            return proto(format!("bad HTTP header line {line:?}"));
        };
        headers.push((n.trim().to_string(), v.trim().to_string()));
    }
    Ok(Some(Response {
        status,
        reason,
        headers,
        head_len: end + 4,
    }))
}

/// A random GUID in registry format, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn random_guid() -> String {
    let b: [u8; 16] = crate::crypto::random();
    let h: String = b.iter().map(|x| format!("{x:02X}")).collect();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_request_headers() {
        let r = upgrade_request("gw.example", 443, "a2V5", "{GUID}", "NTLM Zm9v");
        assert!(r.starts_with("GET /remoteDesktopGateway/ HTTP/1.1\r\nHost: gw.example\r\n"));
        for h in [
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Key: a2V5\r\n",
            "RDG-Connection-Id: {GUID}\r\n",
            "Authorization: NTLM Zm9v\r\n",
        ] {
            assert!(r.contains(h), "missing {h:?}");
        }
        assert!(r.ends_with("\r\n\r\n"));
        assert!(upgrade_request("gw", 8443, "k", "i", "a").contains("Host: gw:8443\r\n"));
    }

    #[test]
    fn parses_401_with_ntlm_challenge() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\n\
            Content-Length: 5\r\n\
            WWW-Authenticate: Negotiate\r\n\
            www-authenticate: NTLM Zm9vYmFy\r\n\r\nbody!rest";
        let r = parse_response(raw).unwrap().unwrap();
        assert_eq!(r.status, 401);
        assert_eq!(r.content_length().unwrap(), 5);
        assert_eq!(&raw[r.head_len..r.head_len + 5], b"body!");
        assert_eq!(r.auth_token("NTLM").unwrap().unwrap(), b"foobar");
        assert_eq!(r.auth_token("Basic").unwrap(), None);
        // The bare "Negotiate" offer has no token and is skipped.
        assert_eq!(r.auth_token("Negotiate").unwrap(), None);
    }

    #[test]
    fn incomplete_and_bad_responses() {
        assert!(parse_response(b"HTTP/1.1 101 Switching").unwrap().is_none());
        assert!(parse_response(b"SSH-2.0-x\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 abc x\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n").is_err());
    }

    #[test]
    fn rpc_channel_request_headers() {
        let r = rpc_channel_request(
            "RPC_IN_DATA",
            "gw.example",
            443,
            1 << 30,
            "sid",
            "NTLM Zm9v",
        );
        assert!(r.starts_with(
            "RPC_IN_DATA /rpc/rpcproxy.dll?localhost:3388 HTTP/1.1\r\nAccept: application/rpc\r\n"
        ));
        for h in [
            "Cache-Control: no-cache\r\n",
            "Connection: Keep-Alive\r\n",
            "Content-Length: 1073741824\r\n",
            "User-Agent: MSRPC\r\n",
            "Host: gw.example\r\n",
            "SessionId=sid\r\n",
            "Authorization: NTLM Zm9v\r\n",
        ] {
            assert!(r.contains(h), "missing {h:?}");
        }
        assert!(r.ends_with("\r\n\r\n"));
        let r = rpc_channel_request("RPC_OUT_DATA", "gw", 8443, 76, "s", "a");
        assert!(r.contains("Host: gw:8443\r\n") && r.contains("Content-Length: 76\r\n"));
    }

    #[test]
    fn rpc_proxy_error_reason() {
        let raw = b"HTTP/1.0 503 RPC Error: 6BA, EEInfo: AAAA\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw).unwrap().unwrap();
        assert_eq!(r.status, 503);
        assert_eq!(r.rpc_error(), Some(0x6BA));
        let raw = b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Negotiate\r\n\r\n";
        let r = parse_response(raw).unwrap().unwrap();
        assert_eq!(r.rpc_error(), None);
        assert!(r.offers("negotiate") && !r.offers("NTLM"));
    }

    #[test]
    fn guid_format() {
        let g = random_guid();
        assert_eq!(g.len(), 38);
        assert!(g.starts_with('{') && g.ends_with('}'));
        assert_eq!(g.matches('-').count(), 4);
        assert_ne!(g, random_guid());
    }
}
