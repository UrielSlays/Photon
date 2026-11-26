//! Regression test: the JMAP transport decodes an RFC 2047 display name in the `From` header.
//!
//! Reproduction:
//! `header_summary_from_row` (crates/aruna-jmap/src/transport.rs ~line 1006) reads the raw `From`
//! header through `aruna::mailbox::parse_from`, whose `display_name` is explicitly
//! NOT RFC 2047-decoded (`ParsedMailbox`'s own doc: "the transport decodes this half, and only
//! this half"). The Gmail transport calls `decode_rfc2047` on its `from_name`
//! (crates/aruna-gmail/src/transport.rs ~line 2276); nothing in `aruna-jmap` ever calls
//! `decode_rfc2047` (grepped: the function doesn't exist in this crate or in `aruna`), so the JMAP
//! path's `from_name` keeps the raw `=?charset?...?=` token.
//!
//! `header_summary_from_row` and `HttpJmapTransport::connect_with`/the internal fake-HTTP test
//! harness (`FakeHttp`, `connected()`) are crate-PRIVATE — unreachable from this external
//! integration-test crate. The only PUBLIC path to the same code is the `JmapTransport` trait's
//! `list_inbox_page` on `HttpJmapTransport<ReqwestClient>` (the only public constructors —
//! `connect`/`connect_basic`/`connect_for_test_fixture` — all build the REAL reqwest client), so
//! this probe drives it over an actual loopback TCP socket: a ~120-line hand-rolled HTTP/1.1
//! responder (std::net only, no new dependency) serving the exact three-request sequence
//! `list_inbox_page` issues (session discovery GET, then the `Mailbox/query` POST
//! `mailbox_id_for_role` sends, then the combined `Email/query`+`Email/get` POST) — canned
//! response bodies copied verbatim from this crate's own internal unit test
//! `list_inbox_page_issues_the_role_lookup_then_one_combined_request_and_maps_every_field`
//! (`transport.rs`'s `connected()`/`session_body()`/`resp()` helpers).
use aruna::jmap::{AccountId, JmapTransport};
use aruna::read_surface::ListedPage;
use aruna_jmap::transport::HttpJmapTransport;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

/// Read one HTTP/1.1 request off `stream` (headers + any `Content-Length` body) and discard it —
/// this probe canned-answers by REQUEST ORDER, never by inspecting what was sent.
fn drain_one_request(stream: &TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone the stream to read it"));
    let mut header_bytes = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line).expect("read a header line");
        if n == 0 {
            break;
        }
        let is_blank = line == b"\r\n" || line == b"\n";
        header_bytes.extend_from_slice(&line);
        if is_blank {
            break;
        }
    }
    let headers = String::from_utf8_lossy(&header_bytes);
    let content_length: usize = headers
        .lines()
        .find_map(|l| {
            let lower = l.to_ascii_lowercase();
            lower
                .strip_prefix("content-length:")
                .and_then(|v| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).expect("read the request body");
    }
}

fn write_json_response(stream: &mut TcpStream, body: &str) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).expect("write the response");
    stream.flush().expect("flush the response");
}

#[test]
fn jmap_raw_from_decodes_an_rfc2047_display_name() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = listener.local_addr().expect("read the bound port").port();
    let base_url = format!("http://127.0.0.1:{port}");
    let api_url = format!("{base_url}/jmap");

    let session_body = format!(
        r#"{{"apiUrl":"{api_url}","capabilities":{{"urn:ietf:params:jmap:core":{{}},"urn:ietf:params:jmap:mail":{{}}}},"primaryAccounts":{{"urn:ietf:params:jmap:mail":"ACCT-1"}}}}"#
    );
    let mailbox_query_body =
        r#"{"methodResponses":[["Mailbox/query",{"accountId":"ACCT-1","ids":["MBX-inbox"]},"c0"]]}"#.to_string();
    let combined_body = r#"{"methodResponses":[
        ["Email/query",{"accountId":"ACCT-1","ids":["E1"],"total":1,"position":0},"c1"],
        ["Email/get",{"accountId":"ACCT-1","list":[
            {"id":"E1","receivedAt":"2024-01-15T10:30:00Z","header:From:asRaw:all":["=?UTF-8?Q?Legal_Hold?= <hold@example.com>"],"subject":"s","keywords":{},"hasAttachment":false,"mailboxIds":{"MBX-inbox":true}}
        ]},"c2"]
    ]}"#
    .to_string();

    let responses = [session_body, mailbox_query_body, combined_body];
    let server = std::thread::spawn(move || {
        for (i, stream) in listener.incoming().enumerate().take(3) {
            let mut stream = stream.expect("accept a connection");
            drain_one_request(&stream);
            write_json_response(&mut stream, &responses[i]);
        }
    });

    let transport = HttpJmapTransport::connect_basic(&base_url, "user", "pass")
        .expect("connect over the loopback fixture (session discovery GET)");
    let page: ListedPage = transport
        .list_inbox_page(&AccountId("ACCT-1".to_string()), 50, None)
        .expect("list_inbox_page over the loopback fixture");

    server.join().expect("the loopback responder thread must not panic");

    assert_eq!(page.rows.len(), 1, "one row: {:?}", page.rows);
    eprintln!(
        "r5_p3: from_name={:?} from_addr={:?}",
        page.rows[0].from_name, page.rows[0].from_addr
    );
    // Before the fix the encoded token arrived unchanged (`=?UTF-8?Q?Legal_Hold?=`), never
    // decoded to "Legal Hold".
    assert_eq!(page.rows[0].from_name, "Legal Hold");
    assert_eq!(page.rows[0].from_addr, "hold@example.com");
}
