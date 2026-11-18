use super::*;

/// MS-RAI 2.2.2's example (the ID's line break in the spec removed).
const SPEC: &str = r#"<E>
    <A KH="YiKwWUY8Ioq5NB3wAQHSbs5kwrM=" KH2="sha256:wKSAkAV3sBfa9WpuRFJcP9q1twJc6wOBuoJ9tsyXwpk=" ID="8rYm30RBW8/4dAWoUsWbFCF5jno/7jr5tNpHQc2goLbw4uuBBJvLsU02YYLlBMg5"/>
    <C>
        <T ID="1" SID="1440550163">
            <L P="49749" N="2001:4898:1a:5:79e2:3356:9b22:3470"/>
            <L P="49751" N="172.31.250.64"/>
        </T>
    </C>
</E>"#;

#[test]
fn parses_the_spec_example() {
    let inv = Invitation::parse(SPEC).unwrap();
    assert_eq!(
        inv.auth_id,
        "8rYm30RBW8/4dAWoUsWbFCF5jno/7jr5tNpHQc2goLbw4uuBBJvLsU02YYLlBMg5"
    );
    assert_eq!(
        inv.key_hash.as_deref(),
        Some("YiKwWUY8Ioq5NB3wAQHSbs5kwrM=")
    );
    assert_eq!(
        inv.key_hash2.as_deref(),
        Some("sha256:wKSAkAV3sBfa9WpuRFJcP9q1twJc6wOBuoJ9tsyXwpk=")
    );
    assert_eq!(inv.transports.len(), 1);
    assert_eq!(inv.transports[0].id, 1);
    let targets = inv.targets();
    assert_eq!(
        targets,
        vec![
            (
                Listener {
                    host: "2001:4898:1a:5:79e2:3356:9b22:3470".into(),
                    port: 49749
                },
                1_440_550_163
            ),
            (
                Listener {
                    host: "172.31.250.64".into(),
                    port: 49751
                },
                1_440_550_163
            ),
        ]
    );
}

#[test]
fn parses_a_one_line_desktop_sharing_string() {
    // The shape IRDPSRAPIInvitation returns: one line, KH2 optional, an
    // IPv6 zone, single quotes and an entity in the ID.
    let s = "<?xml version=\"1.0\"?><E><A KH=\"rNOdFflS6iHJn8KIM63ZXWGufhA=\" \
             ID='Tri&amp;al'/><C><T ID=\"1\" SID=\"0\"><L P=\"9792\" \
             N=\"fe80::1%3\"/><L U=\"wss://h/x\" N=\"h\"/><L P=\"9795\" N=\"10.0.0.5\"/></T></C></E>";
    let inv = Invitation::parse(s).unwrap();
    assert_eq!(inv.auth_id, "Tri&al");
    assert_eq!(inv.key_hash2, None);
    let ports: Vec<_> = inv.targets().iter().map(|(l, _)| l.port).collect();
    assert_eq!(
        ports,
        vec![9792, 9795],
        "the websocket-only listener is skipped"
    );
    assert_eq!(inv.targets()[0].0.host, "fe80::1%3");
}

#[test]
fn the_invitation_may_sit_inside_other_text() {
    let s = format!("saved by a tool\r\n{SPEC}\r\n<E><A ID=\"other\"/></E>");
    assert_eq!(
        Invitation::parse(&s).unwrap(),
        Invitation::parse(SPEC).unwrap(),
        "parsing stops at the first </E>"
    );
}

#[test]
fn rejects_broken_invitations() {
    for bad in [
        "",
        "<E><C><T ID=\"1\" SID=\"2\"/></C></E>",    // no <A>
        "<E><A KH=\"x\"/></E>",                     // <A> without ID
        "<E><A ID=\"x\"/><L P=\"1\" N=\"h\"/></E>", // <L> outside <T>
        "<E><A ID=\"x\"/><T ID=\"1\" SID=\"s\"></T></E>", // SID not a number
        "<E><A ID=\"x\"/><T ID=\"1\" SID=\"2\"><L P=\"70000\" N=\"h\"/></T></E>",
        "<E><A ID=\"x\"/><T ID=\"1\" SID=\"2\"><L P=\"1\"/></T></E>", // no N
        "<E><A ID=\"x&bogus;\"/></E>",                                // unknown entity
        "<E><A ID=\"x\"",                                             // unterminated tag
        "<E><A ID=x/></E>",                                           // unquoted value
    ] {
        assert!(Invitation::parse(bad).is_err(), "{bad}");
    }
    let huge = format!("<E><A ID=\"{}\"/></E>", "a".repeat(70_000));
    assert!(Invitation::parse(&huge).is_err());
}

#[test]
fn encrypted_remote_assistance_files_are_unsupported() {
    let file = r#"<?xml version="1.0"?><UPLOADINFO TYPE="Escalated"><UPLOADDATA USERNAME="jeff" LHTICKET="3CD9" RCTICKET="65538,1,1.2.3.4:3389,*,x,*,*,y" PassStub="z" L="0"/></UPLOADINFO>"#;
    assert!(matches!(
        Invitation::parse(file),
        Err(Error::Unsupported(_))
    ));
}

/// The connection to a sharer: the Preconnection PDU comes first, then an
/// X.224 request for TLS only (no NLA). A sharer that answers with Standard
/// RDP Security gets a clear "not implemented" error.
#[test]
fn connecting_to_a_sharer_sends_preconnection_then_asks_for_tls_only() {
    use crate::server::connect::{connection_confirm, parse_connection_request};
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let timeout = std::time::Duration::from_secs(5);
        s.set_read_timeout(Some(timeout)).unwrap();
        let mut pre = [0u8; 16];
        s.read_exact(&mut pre).unwrap();
        let mut tpkt = vec![0u8; 4];
        s.read_exact(&mut tpkt).unwrap();
        let len = usize::from(u16::from_be_bytes([tpkt[2], tpkt[3]]));
        tpkt.resize(len, 0);
        s.read_exact(&mut tpkt[4..]).unwrap();
        let req = parse_connection_request(&tpkt).unwrap();
        s.write_all(&connection_confirm(crate::x224::PROTOCOL_RDP, 0))
            .unwrap();
        (pre, req.requested_protocols)
    });
    let mut cfg = crate::Config::new("127.0.0.1", "viewer", "");
    cfg.port = port;
    cfg.timeout = std::time::Duration::from_secs(5);
    cfg.assistance = Some(AssistanceLogon {
        auth_id: "id".into(),
        password: None,
        preconnection_id: Some(1_440_550_163),
    });
    let err = crate::Client::connect(&cfg).err().expect("no TLS offered");
    assert!(
        matches!(&err, Error::Unsupported(m) if m.contains("Standard RDP Security")),
        "{err}"
    );
    let (pre, requested) = server.join().unwrap();
    assert_eq!(pre.to_vec(), crate::preconnection::pdu_v1(1_440_550_163));
    assert_eq!(requested, Some(crate::x224::PROTOCOL_SSL));
}
