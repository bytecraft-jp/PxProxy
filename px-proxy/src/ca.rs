//! MITM 用のローカル CA。CA は案件ではなくユーザー単位で保持する
//! （案件を移動してもブラウザに CA を入れ直さなくて済むように）。

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType, SerialNumber,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

use crate::{ProxyError, Result, tls};

const CA_CERT_FILE: &str = "ca.crt";
const CA_KEY_FILE: &str = "ca.key";
const CA_NAME: &str = "pxproxy Local CA";
const LEAF_CACHE_MAX: usize = 4096;

pub struct CertAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    /// 全ホストのリーフで鍵を共有し、鍵生成コストを無くす。
    leaf_key: KeyPair,
    serial: AtomicU64,
    cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertAuthority {
    /// `dir` に CA があれば読み込み、無ければ生成して保存する。
    pub fn load_or_create(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let (ca_pem, key) = if cert_path.exists() && key_path.exists() {
            (fs::read_to_string(&cert_path)?, KeyPair::from_pem(&fs::read_to_string(&key_path)?)?)
        } else {
            let key = KeyPair::generate()?;
            let cert = ca_params().self_signed(&key)?;
            fs::create_dir_all(dir)?;
            fs::write(&key_path, key.serialize_pem())?;
            fs::write(&cert_path, cert.pem())?;
            (cert.pem(), key)
        };
        let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes())
            .map_err(|e| ProxyError::Ca(format!("parse {}: {e}", cert_path.display())))?;
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, key)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        Ok(Self {
            issuer,
            ca_der,
            ca_pem,
            leaf_key: KeyPair::generate()?,
            serial: AtomicU64::new(now.as_nanos() as u64),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn default_dir() -> PathBuf {
        let base = std::env::var_os("APPDATA")
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("pxproxy")
    }

    /// ブラウザ/OS にインストールする CA 証明書 (PEM)。
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// ホスト用の TLS サーバ設定（キャッシュ付き）。
    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let host = host.to_ascii_lowercase();
        if let Some(cfg) = self.cache.lock().get(&host) {
            return Ok(cfg.clone());
        }
        let leaf = self.leaf_cert(&host)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let cfg = Arc::new(tls::server_config(vec![leaf, self.ca_der.clone()], key)?);
        let mut cache = self.cache.lock();
        if cache.len() >= LEAF_CACHE_MAX {
            cache.clear();
        }
        cache.insert(host, cfg.clone());
        Ok(cfg)
    }

    fn leaf_cert(&self, host: &str) -> Result<CertificateDer<'static>> {
        let mut params = CertificateParams::default();
        let san = match host.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(
                Ia5String::try_from(host.to_string()).map_err(|e| ProxyError::Ca(format!("bad host {host}: {e}")))?,
            ),
        };
        params.subject_alt_names = vec![san];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.use_authority_key_identifier_extension = true;
        // 同一 issuer+serial の重複は Firefox がエラーにするので毎回変える。
        params.serial_number = Some(SerialNumber::from(self.serial.fetch_add(1, Ordering::Relaxed)));
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365);
        Ok(params.signed_by(&self.leaf_key, &self.issuer)?.der().clone())
    }
}

fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NAME);
    dn.push(DnType::OrganizationName, "pxproxy");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365 * 10);
    params
}
