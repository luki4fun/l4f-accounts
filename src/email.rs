//! Outgoing mail: verification links, password resets, notices. SMTP with
//! implicit TLS (port 465), optionally through the host's egress allow-list,
//! which forwards by SNI: the connection goes to the egress address while TLS
//! names and verifies the real server.

use std::net::SocketAddr;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};

/// Where and as whom to send.
pub struct SmtpSettings<'a> {
    /// The server's name, for TLS: `smtp.example.org`.
    pub host: &'a str,
    /// The server's implicit-TLS port, usually 465. Ignored with `egress`.
    pub port: u16,
    /// The host's egress forwarder, e.g. 127.0.0.1:8443. `None` connects directly.
    pub egress: Option<SocketAddr>,
    pub user: &'a str,
    pub password: Option<String>,
    /// `Name <addr>` or `addr`.
    pub from: &'a str,
}

pub struct Mailer {
    kind: Kind,
    from: Mailbox,
}

enum Kind {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    #[cfg(test)]
    Capture(std::sync::Arc<std::sync::Mutex<Vec<Sent>>>),
}

/// A message as a test sees it.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct Sent {
    pub to: String,
    pub subject: String,
    pub body: String,
}

impl Mailer {
    pub fn smtp(s: &SmtpSettings<'_>) -> Result<Mailer, String> {
        let from: Mailbox = s.from.parse().map_err(|e| format!("smtp_from: {e}"))?;
        let tls = TlsParameters::new(s.host.to_string()).map_err(|e| format!("smtp TLS: {e}"))?;
        let mut b = match s.egress {
            Some(addr) => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(addr.ip().to_string()).port(addr.port()),
            None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(s.host).port(s.port),
        }
        .tls(Tls::Wrapper(tls))
        .timeout(Some(std::time::Duration::from_secs(15)));
        if let Some(pw) = &s.password {
            b = b.credentials(Credentials::new(s.user.to_string(), pw.clone()));
        }
        Ok(Mailer { kind: Kind::Smtp(b.build()), from })
    }

    #[cfg(test)]
    pub fn capture() -> (Mailer, std::sync::Arc<std::sync::Mutex<Vec<Sent>>>) {
        let sent = std::sync::Arc::default();
        let from = "l4f <noreply@l4f.test>".parse().unwrap();
        (Mailer { kind: Kind::Capture(std::sync::Arc::clone(&sent)), from }, sent)
    }

    /// Plain text only. `to` was checked by `clean_email` before it got here.
    pub async fn send(&self, to: &str, subject: &str, body: String) -> Result<(), String> {
        let to_box: Mailbox = to.parse().map_err(|e| format!("recipient: {e}"))?;
        let msg = Message::builder()
            .from(self.from.clone())
            .to(to_box)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.clone())
            .map_err(|e| format!("message: {e}"))?;
        match &self.kind {
            Kind::Smtp(t) => t.send(msg).await.map(|_| ()).map_err(|e| format!("smtp: {e}")),
            #[cfg(test)]
            Kind::Capture(sent) => {
                sent.lock().unwrap().push(Sent { to: to.to_string(), subject: subject.to_string(), body });
                Ok(())
            }
        }
    }
}
