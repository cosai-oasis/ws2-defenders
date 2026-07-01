//! RFC 5424 syslog exporter (UDP or TCP).
//!
//! Each AgentDR event becomes one syslog message:
//! `<priority>1 <ts> <host> <appname> <pid> <msgid> [aitf@... k="v" ...] <json>`
//!
//! Priority = facility * 8 + severity. We map the AgentDR risk_level
//! to a syslog severity (informational..critical → notice..alert).
//! Structured data is included for the most relevant AITF fields so
//! syslog-aware SIEMs can index without parsing the JSON body.

use super::Exporter;
use crate::config::SyslogConfig;
use crate::models::EventRecord;
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

pub struct Syslog {
    protocol: Proto,
    address:  String,
    facility: u8,
    appname:  String,
    udp:      tokio::sync::OnceCell<Arc<UdpSocket>>,
    tcp:      Mutex<Option<TcpStream>>,
}

enum Proto { Udp, Tcp }

impl Syslog {
    pub fn new(cfg: &SyslogConfig) -> Result<Self, String> {
        if cfg.address.is_empty() {
            return Err("syslog.address is empty".into());
        }
        let protocol = match cfg.protocol.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            other => return Err(format!("syslog.protocol must be udp|tcp (got {other})")),
        };
        Ok(Self {
            protocol,
            address: cfg.address.clone(),
            facility: cfg.facility,
            appname: cfg.appname.clone(),
            udp: tokio::sync::OnceCell::new(),
            tcp: Mutex::new(None),
        })
    }

    fn severity(risk: &str) -> u8 {
        match risk {
            "critical" => 1, // Alert
            "high"     => 2, // Critical
            "medium"   => 4, // Warning
            "low"      => 5, // Notice
            _          => 6, // Informational
        }
    }

    fn format(&self, ev: &EventRecord) -> String {
        let priority = (self.facility as u16) * 8 + Self::severity(&ev.risk_level) as u16;
        let host = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "-".to_string());
        let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        // Structured data (sd-element); escape `]` `"` `\` per RFC 5424.
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"").replace(']', "\\]");
        let mut sd = String::from("[aitf@53595");
        for (k, v) in [
            ("class_uid",   ev.class_uid.map(|x| x.to_string())),
            ("activity_id", ev.activity_id.map(|x| x.to_string())),
            ("risk",        Some(ev.risk_level.clone())),
            ("event_type",  Some(ev.event_type.clone())),
            ("provider",    ev.provider.clone()),
            ("model",       ev.model.clone()),
            ("agent_name",  ev.agent_name.clone()),
            ("tool_name",   ev.tool_name.clone()),
            ("mcp_server",  ev.mcp_server.clone()),
            ("trace_id",    Some(ev.trace_id.clone())),
        ] {
            if let Some(val) = v {
                sd.push_str(&format!(" {}=\"{}\"", k, esc(&val)));
            }
        }
        sd.push(']');
        let body = serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
        format!(
            "<{}>1 {} {} {} {} - {} {}\n",
            priority,
            ts,
            host,
            self.appname,
            std::process::id(),
            sd,
            body,
        )
    }

    async fn udp_socket(&self) -> Result<Arc<UdpSocket>, String> {
        let s = self.udp.get_or_try_init(|| async {
            let sock = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| e.to_string())?;
            sock.connect(&self.address).await.map_err(|e| e.to_string())?;
            Ok::<_, String>(Arc::new(sock))
        }).await?;
        Ok(s.clone())
    }
}

#[async_trait]
impl Exporter for Syslog {
    fn name(&self) -> &'static str { "syslog" }

    async fn send(&self, events: &[EventRecord]) -> Result<(), String> {
        match self.protocol {
            Proto::Udp => {
                let sock = self.udp_socket().await?;
                for ev in events {
                    let msg = self.format(ev);
                    sock.send(msg.as_bytes()).await.map_err(|e| format!("syslog/udp: {e}"))?;
                }
            }
            Proto::Tcp => {
                let mut guard = self.tcp.lock().await;
                if guard.is_none() {
                    *guard = Some(TcpStream::connect(&self.address).await
                        .map_err(|e| format!("syslog/tcp connect: {e}"))?);
                }
                let stream = guard.as_mut().unwrap();
                for ev in events {
                    let msg = self.format(ev);
                    // Octet-counting framing per RFC 6587.
                    let frame = format!("{} {}", msg.len(), msg);
                    if let Err(e) = stream.write_all(frame.as_bytes()).await {
                        *guard = None;
                        return Err(format!("syslog/tcp write: {e}"));
                    }
                }
            }
        }
        Ok(())
    }
}
