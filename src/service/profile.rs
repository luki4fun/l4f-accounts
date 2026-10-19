//! The opt-in public profile behind a random link, and the avatar.
//!
//! The link is a random 16-byte id shown as a UUID: nothing in it names the
//! account, and rotating it kills the old one. The profile shows only what the
//! owner chose: display name, avatar, bio, role badges, the linked identities
//! marked public, and whatever public links the host adds.

use super::{Accounts, Ctx, Error, Host, Put, need};
use crate::model::{AccountId, User, UserStatus};
use crate::store::Profile;
use crate::{scope, util};

pub const AVATAR_MAX: usize = 64 * 1024;
const AVATAR_NS: &str = "avatar";
const AVATAR_K: &str = "a";

/// What anyone with the link sees.
pub struct PublicProfile {
    pub user: AccountId,
    pub display_name: String,
    pub bio: String,
    pub badges: Vec<String>,
    /// (provider, name) of the identities marked public.
    pub identities: Vec<(String, String)>,
    pub avatar: bool,
}

/// `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`.
pub fn uuid_of(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

pub fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    if s.len() != 36 || h.len() != 32 {
        return None;
    }
    hex::decode(h.to_ascii_lowercase()).ok()?.try_into().ok()
}

/// Random, with the UUID version 4 and variant bits set so it looks like one.
fn new_public_id() -> [u8; 16] {
    let mut b = util::random::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    b
}

/// A bio: up to 1000 characters, line breaks allowed, no other control or
/// invisible character, nothing that reorders the text around it.
fn clean_bio(raw: &str) -> Result<String, Error> {
    let bio = raw.replace("\r\n", "\n");
    let bio = bio.trim();
    if bio.chars().nth(1000).is_some() {
        return Err(Error::Invalid("Keep the bio to 1000 characters or fewer."));
    }
    if bio.chars().any(|c| c != '\n' && scope::breaks_text(c)) {
        return Err(Error::Invalid("The bio cannot contain control, invisible or text-direction characters."));
    }
    Ok(bio.to_string())
}

/// PNG or WebP, by their magic bytes; anything else is refused whatever it says.
pub fn image_type(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.len() >= 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

pub(crate) fn provider_label(kind: &str) -> String {
    match kind.strip_prefix("oauth:").unwrap_or(kind) {
        "discord" => "Discord".into(),
        "google" => "Google".into(),
        "facebook" => "Facebook".into(),
        other => other.to_string(),
    }
}

impl<H: Host> Accounts<H> {
    pub async fn profile_settings(&self, user: AccountId) -> sqlx::Result<Profile> {
        self.store.profile(user).await
    }

    /// Turning it on needs `profile:public` and makes a link if there is none;
    /// turning it off drops the link, so turning it on again makes a new one.
    pub async fn profile_save(&self, ctx: &Ctx, user: &User, scopes: &[String], on: bool, bio: &str, show_badges: bool) -> Result<(), Error> {
        if on {
            need(scopes, "profile:public")?;
        }
        let mut p = self.store.profile(user.id).await?;
        p.bio = clean_bio(bio)?;
        p.show_badges = show_badges;
        p.public_id = match (on, p.public_id) {
            (false, _) => None,
            (true, Some(id)) => Some(id),
            (true, None) => Some(new_public_id()),
        };
        self.store.save_profile(user.id, &p, util::now()).await?;
        self.audit_after(ctx, Some(user.id), Some(user.id), "profile_save", if on { "on" } else { "off" }).await;
        Ok(())
    }

    /// A new link; the old one stops working.
    pub async fn profile_rotate(&self, ctx: &Ctx, user: &User) -> Result<(), Error> {
        let mut p = self.store.profile(user.id).await?;
        if p.public_id.is_none() {
            return Err(Error::Invalid("The profile is off."));
        }
        p.public_id = Some(new_public_id());
        self.store.save_profile(user.id, &p, util::now()).await?;
        self.audit_after(ctx, Some(user.id), Some(user.id), "profile_rotate", "").await;
        Ok(())
    }

    pub async fn identity_public(&self, user: &User, kind: &str, ext_id: &[u8], public: bool) -> Result<(), Error> {
        if !kind.starts_with("oauth:") || !self.store.set_credential_public(user.id, kind, ext_id, public).await? {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// The profile behind a link, if it is on and its owner may still have one.
    pub async fn public_profile(&self, link: &str) -> Result<Option<PublicProfile>, Error> {
        let Some(public_id) = parse_uuid(link) else { return Ok(None) };
        let Some(owner) = self.store.profile_owner(&public_id).await? else { return Ok(None) };
        let Some(user) = self.store.user_by_id(owner).await?.filter(|u| u.status == UserStatus::Active) else { return Ok(None) };
        if !scope::allowed(&self.effective_scopes(&user).await?, "profile:public") {
            return Ok(None);
        }
        let p = self.store.profile(owner).await?;
        let badges = if p.show_badges {
            self.store.user_roles(owner).await?.into_iter().filter_map(|r| r.badge).collect()
        } else {
            Vec::new()
        };
        let identities = self.store.public_identities(owner).await?.into_iter().map(|(k, n)| (provider_label(&k), n)).collect();
        let avatar = self.store.blob(owner, AVATAR_NS, AVATAR_K).await?.is_some();
        Ok(Some(PublicProfile { user: owner, display_name: user.display_name, bio: p.bio, badges, identities, avatar }))
    }

    /// Replaces the avatar: PNG or WebP, at most 64 KiB, in the storage quota.
    pub async fn avatar_put(&self, ctx: &Ctx, user: &User, scopes: &[String], bytes: &[u8]) -> Result<(), Error> {
        need(scopes, "profile:public")?;
        if bytes.len() > AVATAR_MAX || image_type(bytes).is_none() {
            return Err(Error::Invalid("An avatar is a PNG or WebP image of at most 64 KiB."));
        }
        let expect = self.store.blob(user.id, AVATAR_NS, AVATAR_K).await?.map_or(0, |b| b.version);
        if let Put::Conflict(_) = self.put(user, AVATAR_NS, AVATAR_K, bytes, expect, None).await? {
            return Err(Error::Invalid("It changed meanwhile. Try again."));
        }
        self.audit_after(ctx, Some(user.id), Some(user.id), "avatar", "").await;
        Ok(())
    }

    pub async fn avatar_remove(&self, user: &User) -> sqlx::Result<()> {
        self.store.delete_blob(user.id, AVATAR_NS, AVATAR_K, 0).await.map(|_| ())
    }

    /// The image and its type, sniffed again on the way out.
    pub async fn avatar(&self, user: AccountId) -> sqlx::Result<Option<(Vec<u8>, &'static str)>> {
        Ok(self.store.blob(user, AVATAR_NS, AVATAR_K).await?.and_then(|b| image_type(&b.v).map(|t| (b.v, t))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_look_like_uuids_and_parse_back() {
        let id = new_public_id();
        let s = uuid_of(&id);
        assert_eq!((s.len(), &s[14..15]), (36, "4"));
        assert!(matches!(&s[19..20], "8" | "9" | "a" | "b"));
        assert_eq!(parse_uuid(&s), Some(id));
        assert_eq!(parse_uuid(&s.to_uppercase()), Some(id));
        assert_eq!(parse_uuid("not-a-uuid"), None);
        assert_eq!(parse_uuid(&s.replace('-', "")), None, "the dashed form only");
    }

    #[test]
    fn bios_and_images() {
        assert_eq!(clean_bio(" a\r\nb ").unwrap(), "a\nb");
        assert!(clean_bio("a\u{202e}b").is_err() && clean_bio("a\u{0007}").is_err() && clean_bio(&"x".repeat(1001)).is_err());
        assert_eq!(image_type(b"\x89PNG\r\n\x1a\n...."), Some("image/png"));
        assert_eq!(image_type(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_type(b"<svg onload=alert(1)>"), None);
        assert_eq!(image_type(b"GIF89a"), None);
    }
}
