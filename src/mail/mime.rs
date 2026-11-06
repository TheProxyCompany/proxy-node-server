//! RFC-5322 / MIME email parser and builder for `<username>@proxy.ing`.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::{MailAttachment, SendEmailRequest};

/// Parsed RFC-5322 email headers, body parts, and attachments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedMimeMessage {
    pub from: String,
    pub from_name: Option<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub reply_to: Option<String>,
    pub subject: String,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub date: Option<String>,
    pub text_body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<MailAttachment>,
}

/// Parse a raw RFC-5322 message (headers + plain text / HTML / multipart body).
pub fn parse_raw_rfc5322(raw: &[u8]) -> ParsedMimeMessage {
    let text = String::from_utf8_lossy(raw);
    let normalized = text.replace("\r\n", "\n");
    let (header_block, body_block) = normalized
        .split_once("\n\n")
        .unwrap_or((normalized.as_str(), ""));

    let headers = unfold_headers(header_block);
    let mut out = ParsedMimeMessage::default();
    let mut content_type = String::from("text/plain");
    let mut transfer_encoding = String::new();

    for (name, value) in &headers {
        match name.as_str() {
            "from" => {
                let (name_opt, addr) = parse_mailbox(value);
                out.from = addr;
                out.from_name = name_opt;
            }
            "to" => out.to = parse_address_list(value),
            "cc" => out.cc = parse_address_list(value),
            "reply-to" => {
                let (_, addr) = parse_mailbox(value);
                if !addr.is_empty() {
                    out.reply_to = Some(addr);
                }
            }
            "subject" => out.subject = value.trim().to_string(),
            "message-id" => out.message_id = Some(value.trim().to_string()),
            "in-reply-to" => out.in_reply_to = Some(value.trim().to_string()),
            "references" => {
                out.references = value
                    .split_whitespace()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "date" => out.date = Some(value.trim().to_string()),
            "content-type" => content_type = value.clone(),
            "content-transfer-encoding" => transfer_encoding = value.trim().to_ascii_lowercase(),
            _ => {}
        }
    }

    parse_mime_entity(&content_type, &transfer_encoding, body_block, &mut out);
    if out.text_body.is_empty()
        && let Some(html) = &out.html_body
    {
        out.text_body = strip_html_tags(html);
    }
    out
}

fn unfold_headers(block: &str) -> Vec<(String, String)> {
    let mut unfolded: Vec<String> = Vec::new();
    for line in block.lines() {
        if (line.starts_with(' ') || line.starts_with('\t'))
            && let Some(last) = unfolded.last_mut()
        {
            last.push(' ');
            last.push_str(line.trim());
            continue;
        }
        unfolded.push(line.to_string());
    }
    let mut out = Vec::new();
    for line in unfolded {
        if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    out
}

fn parse_mime_entity(
    content_type_header: &str,
    transfer_encoding: &str,
    body: &str,
    out: &mut ParsedMimeMessage,
) {
    let lower_ct = content_type_header.to_ascii_lowercase();
    if lower_ct.starts_with("multipart/")
        && let Some(boundary) = extract_param(content_type_header, "boundary")
    {
        let delim = format!("--{boundary}");
        let end_delim = format!("--{boundary}--");
        for part in body.split(&delim).skip(1) {
            let trimmed = part.trim_start_matches('\n');
            if trimmed.starts_with("--") || trimmed.is_empty() {
                continue;
            }
            let clean = trimmed
                .split(&end_delim)
                .next()
                .unwrap_or(trimmed)
                .trim_end_matches('\n');
            let (part_hdr_raw, part_body) = clean.split_once("\n\n").unwrap_or(("", clean));
            let part_headers = unfold_headers(part_hdr_raw);
            let mut part_ct = String::from("text/plain");
            let mut part_te = String::new();
            let mut disposition = String::new();
            for (k, v) in &part_headers {
                match k.as_str() {
                    "content-type" => part_ct = v.clone(),
                    "content-transfer-encoding" => part_te = v.trim().to_ascii_lowercase(),
                    "content-disposition" => disposition = v.clone(),
                    _ => {}
                }
            }
            if disposition.to_ascii_lowercase().contains("attachment")
                || extract_param(&disposition, "filename").is_some()
            {
                let filename = extract_param(&disposition, "filename")
                    .or_else(|| extract_param(&part_ct, "name"))
                    .unwrap_or_else(|| "attachment.bin".to_string());
                let raw_bytes = decode_part_bytes(&part_te, part_body);
                let mime = part_ct
                    .split(';')
                    .next()
                    .unwrap_or("application/octet-stream")
                    .trim()
                    .to_string();
                out.attachments.push(MailAttachment {
                    filename,
                    content_type: mime,
                    size_bytes: raw_bytes.len(),
                    content_base64: STANDARD.encode(&raw_bytes),
                });
            } else {
                parse_mime_entity(&part_ct, &part_te, part_body, out);
            }
        }
        return;
    }

    let decoded = decode_part_string(transfer_encoding, body);
    if lower_ct.starts_with("text/html") {
        if out.html_body.is_none() {
            out.html_body = Some(decoded.trim().to_string());
        }
    } else if out.text_body.is_empty() {
        out.text_body = decoded.trim().to_string();
    }
}

fn extract_param(header_val: &str, param_name: &str) -> Option<String> {
    for segment in header_val.split(';').skip(1) {
        let Some((k, v)) = segment.split_once('=') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(param_name) {
            return Some(v.trim().trim_matches('"').to_string());
        }
    }
    None
}

fn decode_part_bytes(encoding: &str, body: &str) -> Vec<u8> {
    match encoding.trim() {
        "base64" => {
            let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            STANDARD
                .decode(compact.as_bytes())
                .unwrap_or_else(|_| body.as_bytes().to_vec())
        }
        "quoted-printable" => decode_quoted_printable(body),
        _ => body.as_bytes().to_vec(),
    }
}

fn decode_part_string(encoding: &str, body: &str) -> String {
    let bytes = decode_part_bytes(encoding, body);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn decode_quoted_printable(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'=' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if i + 2 < bytes.len()
                && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
            {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_mailbox(raw: &str) -> (Option<String>, String) {
    let trimmed = raw.trim();
    if let Some((before, rest)) = trimmed.split_once('<')
        && let Some((addr, _)) = rest.split_once('>')
    {
        let name = before.trim().trim_matches('"').trim();
        let name_opt = (!name.is_empty()).then(|| name.to_string());
        return (name_opt, addr.trim().to_ascii_lowercase());
    }
    (None, trimmed.trim_matches('"').to_ascii_lowercase())
}

fn parse_address_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|part| parse_mailbox(part).1)
        .filter(|addr| !addr.is_empty())
        .collect()
}

fn strip_html_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Build an RFC-5322 compliant MIME message from `req`.
pub fn build_raw_rfc5322(
    from_addr: &str,
    from_name: Option<&str>,
    req: &SendEmailRequest,
    message_id: &str,
) -> String {
    let mut lines = Vec::new();
    let from_header = match from_name.map(str::trim).filter(|s| !s.is_empty()) {
        Some(name) => format!("\"{}\" <{}>", name.replace('"', ""), from_addr),
        None => from_addr.to_string(),
    };
    lines.push(format!("From: {from_header}"));
    lines.push(format!("To: {}", req.to.join(", ")));
    if let Some(cc) = &req.cc
        && !cc.is_empty()
    {
        lines.push(format!("Cc: {}", cc.join(", ")));
    }
    if let Some(reply_to) = &req.reply_to
        && !reply_to.trim().is_empty()
    {
        lines.push(format!("Reply-To: {}", reply_to.trim()));
    }
    lines.push(format!(
        "Subject: {}",
        req.subject.replace(['\r', '\n'], " ")
    ));
    let msg_id = if message_id.starts_with('<') {
        message_id.to_string()
    } else {
        format!("<{message_id}>")
    };
    lines.push(format!("Message-ID: {msg_id}"));
    if let Some(irt) = &req.in_reply_to
        && !irt.trim().is_empty()
    {
        lines.push(format!("In-Reply-To: {}", irt.trim()));
    }
    if let Some(refs) = &req.references
        && !refs.is_empty()
    {
        lines.push(format!("References: {}", refs.join(" ")));
    }
    lines.push("MIME-Version: 1.0".to_string());

    if let Some(html) = &req.html_body
        && !html.trim().is_empty()
    {
        let boundary = "proxy_ing_mime_boundary_v1";
        lines.push(format!(
            "Content-Type: multipart/alternative; boundary=\"{boundary}\""
        ));
        lines.push(String::new());
        lines.push(format!("--{boundary}"));
        lines.push("Content-Type: text/plain; charset=utf-8".to_string());
        lines.push("Content-Transfer-Encoding: 8bit".to_string());
        lines.push(String::new());
        lines.push(req.text_body.clone());
        lines.push(format!("--{boundary}"));
        lines.push("Content-Type: text/html; charset=utf-8".to_string());
        lines.push("Content-Transfer-Encoding: 8bit".to_string());
        lines.push(String::new());
        lines.push(html.clone());
        lines.push(format!("--{boundary}--"));
    } else {
        lines.push("Content-Type: text/plain; charset=utf-8".to_string());
        lines.push("Content-Transfer-Encoding: 8bit".to_string());
        lines.push(String::new());
        lines.push(req.text_body.clone());
    }

    lines.join("\r\n")
}
