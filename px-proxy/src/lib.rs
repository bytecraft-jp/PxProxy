//! HTTP/1.1 MITM プロキシ。キャプチャしたフローは `px_store::FlowSink` へ送る。

pub mod ca;
pub mod http1;
pub mod intercept;
mod limit;
pub mod mock;
mod repeater;
pub mod rules;
mod server;
mod tls;
mod ws;

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use px_store::{FlowSink, NewFlow};
use thiserror::Error;

pub use ca::CertAuthority;
pub use intercept::{Decision, Direction, Held, Interceptor};
pub use mock::{MockRoute, MockServer};
pub use repeater::{Origin, RepeatRequest};
pub use rules::{
    ConnectionLimits, DEFAULT_MAX_RECORD_BODY_MB, HostEntry, InterceptRules, ProjectSettings, Scope, ScopeRule,
    UpstreamProxy, parse_host_list, parse_hosts,
};
pub use server::ProxyServer;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("invalid server name: {0}")]
    ServerName(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("CA: {0}")]
    Ca(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("upstream: {0}")]
    Upstream(String),
    #[error("{0}")]
    Dropped(&'static str),
}

pub type Result<T> = std::result::Result<T, ProxyError>;

/// 記録するフローを受け取るコールバック（CLI のログ表示用）。
pub type FlowObserver = Arc<dyn Fn(&px_store::NewFlow) + Send + Sync>;

/// プロキシ全体で共有する状態。案件の切り替えは `set_sink` で行う。
pub struct ProxyContext {
    ca: Arc<CertAuthority>,
    client_tls: Arc<rustls::ClientConfig>,
    sink: RwLock<Option<FlowSink>>,
    observer: RwLock<Option<FlowObserver>>,
    interceptor: Interceptor,
    limiter: Arc<limit::Limiter>,
    /// 待ち受け中のアドレス（上流が自分自身に向いていないかの判定に使う）
    listeners: RwLock<Vec<SocketAddr>>,
}

impl ProxyContext {
    pub fn new(ca: Arc<CertAuthority>) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            ca,
            client_tls: Arc::new(tls::client_config()?),
            sink: RwLock::new(None),
            observer: RwLock::new(None),
            interceptor: Interceptor::default(),
            limiter: Arc::default(),
            listeners: RwLock::new(Vec::new()),
        }))
    }

    /// `addr` へ接続すると、このプロキシ自身の待受に届くか。
    fn is_own_listener(&self, addr: SocketAddr) -> bool {
        self.listeners.read().iter().any(|l| {
            l.port() == addr.port()
                && (l.ip() == addr.ip()
                    || l.ip().is_unspecified()
                    || addr.ip().is_unspecified()
                    || (l.ip().is_loopback() && addr.ip().is_loopback()))
        })
    }

    pub fn ca(&self) -> &CertAuthority {
        &self.ca
    }

    pub fn interceptor(&self) -> &Interceptor {
        &self.interceptor
    }

    pub fn set_sink(&self, sink: Option<FlowSink>) {
        *self.sink.write() = sink;
    }

    /// 記録の直前に呼ばれるコールバックを設定する。
    pub fn set_observer(&self, observer: Option<FlowObserver>) {
        *self.observer.write() = observer;
    }

    fn submit(&self, flow: NewFlow) {
        if let Some(o) = self.observer.read().as_ref() {
            o(&flow);
        }
        if let Some(s) = self.sink.read().as_ref() {
            s.submit(flow);
        }
    }

    /// 記録して、続けて同じ案件へ書き込むための sink と記録した ID を返す（WebSocket のメッセージ用）。
    /// 案件を切り替えても、接続が続く間は元の案件に書く。
    fn submit_with_sink(&self, flow: NewFlow) -> Option<(FlowSink, i64)> {
        if let Some(o) = self.observer.read().as_ref() {
            o(&flow);
        }
        let sink = self.sink.read().clone()?;
        let id = sink.submit(flow);
        Some((sink, id))
    }
}
