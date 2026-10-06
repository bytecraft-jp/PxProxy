//! フローの種類（HTML / XHR / 画像 …）の判定。一覧のフィルタに使う。

/// 種類。値はビットマスクのビット位置として使うので変更しないこと。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FlowKind {
    Html = 0,
    Xhr = 1,
    Script = 2,
    Css = 3,
    Image = 4,
    Font = 5,
    Media = 6,
    Other = 7,
}

impl FlowKind {
    pub const ALL: [FlowKind; 8] = [
        Self::Html,
        Self::Xhr,
        Self::Script,
        Self::Css,
        Self::Image,
        Self::Font,
        Self::Media,
        Self::Other,
    ];

    pub fn from_i64(v: i64) -> Self {
        Self::ALL.get(v as usize).copied().unwrap_or(Self::Other)
    }

    pub fn bit(self) -> u32 {
        1 << self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Html => "HTML",
            Self::Xhr => "XHR",
            Self::Script => "JS",
            Self::Css => "CSS",
            Self::Image => "画像",
            Self::Font => "フォント",
            Self::Media => "メディア",
            Self::Other => "その他",
        }
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// レスポンスの Content-Type（パラメータを除いた小文字）。
pub fn content_type(res_head: Option<&[u8]>) -> Option<String> {
    let head = String::from_utf8_lossy(res_head?);
    let v = header(&head, "content-type")?;
    let mime = v.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    (!mime.is_empty()).then_some(mime)
}

/// 判定順: Sec-Fetch-Dest → X-Requested-With → Content-Type → 拡張子。
pub fn classify(target: &str, req_head: &[u8], content_type: Option<&str>) -> FlowKind {
    let req = String::from_utf8_lossy(req_head);
    let dest = header(&req, "sec-fetch-dest").map(str::to_ascii_lowercase);
    match dest.as_deref() {
        Some("document" | "iframe" | "frame") => return FlowKind::Html,
        Some("script" | "worker" | "sharedworker" | "serviceworker") => return FlowKind::Script,
        Some("style") => return FlowKind::Css,
        Some("image") => return FlowKind::Image,
        Some("font") => return FlowKind::Font,
        Some("audio" | "video" | "track") => return FlowKind::Media,
        _ => {}
    }
    if header(&req, "x-requested-with").is_some_and(|v| v.eq_ignore_ascii_case("xmlhttprequest"))
        || dest.as_deref() == Some("empty")
    {
        return FlowKind::Xhr;
    }
    if let Some(ct) = content_type {
        let kind = match ct {
            "text/html" | "application/xhtml+xml" => Some(FlowKind::Html),
            "text/css" => Some(FlowKind::Css),
            c if c.contains("javascript") || c.contains("ecmascript") => Some(FlowKind::Script),
            c if c.starts_with("image/") => Some(FlowKind::Image),
            c if c.starts_with("font/") || c.contains("font-woff") => Some(FlowKind::Font),
            c if c.starts_with("audio/") || c.starts_with("video/") => Some(FlowKind::Media),
            c if c.contains("json") || c.ends_with("/xml") || c.contains("+xml") => Some(FlowKind::Xhr),
            _ => None,
        };
        if let Some(k) = kind {
            return k;
        }
    }
    let path = target.split(['?', '#']).next().unwrap_or("");
    let ext = path.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => FlowKind::Html,
        "js" | "mjs" => FlowKind::Script,
        "css" => FlowKind::Css,
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "ico" | "avif" | "bmp" => FlowKind::Image,
        "woff" | "woff2" | "ttf" | "otf" | "eot" => FlowKind::Font,
        "mp4" | "webm" | "mp3" | "m4a" | "ogg" | "wav" | "m3u8" | "ts" => FlowKind::Media,
        "json" => FlowKind::Xhr,
        _ => FlowKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_order() {
        let xhr = b"GET /api HTTP/1.1\r\nSec-Fetch-Dest: empty\r\n\r\n";
        assert_eq!(classify("/api", xhr, Some("text/html")), FlowKind::Xhr);
        let img = b"GET /a HTTP/1.1\r\nsec-fetch-dest: image\r\n\r\n";
        assert_eq!(classify("/a", img, None), FlowKind::Image);
        let plain = b"GET /x HTTP/1.1\r\n\r\n";
        assert_eq!(classify("/x", plain, Some("application/json")), FlowKind::Xhr);
        assert_eq!(classify("/s/app.js?v=1", plain, None), FlowKind::Script);
        assert_eq!(classify("/", plain, None), FlowKind::Other);
        assert_eq!(
            content_type(Some(b"HTTP/1.1 200 OK\r\nContent-Type: Text/HTML; charset=utf-8\r\n\r\n")).as_deref(),
            Some("text/html")
        );
    }
}
