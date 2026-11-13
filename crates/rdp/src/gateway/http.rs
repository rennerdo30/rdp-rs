//! The HTTP/1.1 requests and responses of the RD Gateway transport setup
//! (MS-TSGU 3.3.5.1, 3.3.5.3.1): a WebSocket Upgrade request (RFC 6455 4.1)
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
    let host = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
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

#[derive(Debug)]
pub struct Response {
    pub status: u16,
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
    let mut headers = Vec::new();
    for line in lines {
        let Some((n, v)) = line.split_once(':') else {
            return proto(format!("bad HTTP header line {line:?}"));
        };
        headers.push((n.trim().to_string(), v.trim().to_string()));
    }
    Ok(Some(Response {
        status,
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
    fn guid_format() {
        let g = random_guid();
        assert_eq!(g.len(), 38);
        assert!(g.starts_with('{') && g.ends_with('}'));
        assert_eq!(g.matches('-').count(), 4);
        assert_ne!(g, random_guid());
    }
}
