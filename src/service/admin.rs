//! Roles and user administration. Every call checks its scope here, so a
//! handler that forgets to cannot hand out more than its caller holds.

use serde::Serialize;

use super::{Accounts, Ctx, Error, Host};
use crate::model::{AccountId, AuditEntry, Role, User, UserStatus};
use crate::scope;

/// Who acts, with the scopes their session grants right now (from
/// `session_from_token`). Step-up is the caller's to check.
#[derive(Clone, Copy)]
pub struct Actor<'a> {
    pub user: &'a User,
    pub scopes: &'a [String],
}

impl Actor<'_> {
    pub(super) fn need(&self, required: &str) -> Result<(), Error> {
        if scope::allowed(self.scopes, required) { Ok(()) } else { Err(Error::Forbidden) }
    }
}

/// A role as the admin form sends it. `name` only counts on create; roles are
/// never renamed.
pub struct RoleForm<'a> {
    pub name: &'a str,
    pub description: &'a str,
    /// Empty for none.
    pub badge: &'a str,
    pub scopes: &'a [String],
}

#[derive(Serialize)]
pub struct UserDetail {
    pub user: User,
    pub roles: Vec<Role>,
    pub audit: Vec<AuditEntry>,
}

/// Role names sit in URLs (`/admin/roles/{name}`): the username alphabet.
pub(super) fn role_name(raw: &str) -> Result<String, &'static str> {
    let n = raw.trim().to_ascii_lowercase();
    let ok = (2..=32).contains(&n.len())
        && n.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
        && n.starts_with(|c: char| c.is_ascii_alphanumeric());
    if ok { Ok(n) } else { Err("A role name is 2 to 32 characters of a-z, 0-9, _ and -, starting with a letter or digit.") }
}

/// Descriptions show on the admin pages, badges on public profiles: no line
/// breaks, control or text-direction characters, like a display name.
fn role_text(form: &RoleForm<'_>) -> Result<(String, Option<String>), &'static str> {
    let d = form.description.trim();
    if d.chars().nth(255).is_some() {
        return Err("Keep the description to 255 characters or fewer.");
    }
    if d.chars().any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || scope::invisible(c)) {
        return Err("The description cannot contain control, line-break or invisible characters.");
    }
    let badge = match form.badge.trim() {
        "" => None,
        b => {
            let b = scope::clean_display_name(b)?;
            if b.chars().nth(32).is_some() {
                return Err("Keep the badge to 32 characters or fewer.");
            }
            Some(b)
        }
    };
    Ok((d.to_string(), badge))
}

impl<H: Host> Accounts<H> {
    /// Trimmed, deduplicated, sorted, and every one registered.
    fn grants_from(&self, raw: &[String]) -> Result<Vec<String>, Error> {
        let mut out: Vec<String> = raw.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).map(String::from).collect();
        out.sort();
        out.dedup();
        if !out.iter().all(|g| self.known_grant(g)) {
            return Err(Error::Invalid("That is not a scope this site knows."));
        }
        Ok(out)
    }

    async fn role(&self, name: &str) -> Result<Role, Error> {
        let name = role_name(name).map_err(|_| Error::NotFound)?;
        self.store.role_by_name(&name).await?.ok_or(Error::NotFound)
    }

    pub async fn roles(&self, actor: Actor<'_>) -> Result<Vec<Role>, Error> {
        if !["roles:admin", "users:admin", "users:read"].iter().any(|s| scope::allowed(actor.scopes, s)) {
            return Err(Error::Forbidden);
        }
        Ok(self.store.roles().await?)
    }

    pub async fn create_role(&self, ctx: &Ctx, actor: Actor<'_>, form: RoleForm<'_>) -> Result<AccountId, Error> {
        actor.need("roles:admin")?;
        let name = role_name(form.name).map_err(Error::Invalid)?;
        let (description, badge) = role_text(&form).map_err(Error::Invalid)?;
        let scopes = self.grants_from(form.scopes)?;
        if !scope::covers(actor.scopes, &scopes) {
            return Err(Error::Forbidden);
        }
        let id = self.store.create_role(&name, &description, badge.as_deref()).await?.ok_or(Error::RoleTaken)?;
        if let Err(e) = self.store.set_role_scopes(id, &scopes).await {
            // Without its scopes the role is not what the admin asked for.
            let _ = self.store.delete_role(id).await;
            return Err(e.into());
        }
        self.audit(ctx, None, Some(actor.user.id), "role_create", &format!("{name}: {}", scopes.join(" "))).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "role_create", actor = %actor.user.id.hex(),
            role = ?name);
        Ok(id)
    }

    /// Description, badge and the scope set. The actor must cover the old set
    /// and the new one: taking a scope away is as much a use of it as handing
    /// it out.
    pub async fn update_role(&self, ctx: &Ctx, actor: Actor<'_>, form: RoleForm<'_>) -> Result<(), Error> {
        actor.need("roles:admin")?;
        let role = self.role(form.name).await?;
        let (description, badge) = role_text(&form).map_err(Error::Invalid)?;
        let scopes = self.grants_from(form.scopes)?;
        if !scope::covers(actor.scopes, &role.scopes) || !scope::covers(actor.scopes, &scopes) {
            return Err(Error::Forbidden);
        }
        // Scopes first: the last-admin refusal then leaves the role untouched.
        if scopes != role.scopes {
            self.store.set_role_scopes(role.id, &scopes).await?;
        }
        self.store.update_role(role.id, &description, badge.as_deref()).await?;
        self.audit(ctx, None, Some(actor.user.id), "role_update", &format!("{}: {}", role.name, scopes.join(" "))).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "role_update", actor = %actor.user.id.hex(),
            role = ?role.name);
        Ok(())
    }

    pub async fn delete_role(&self, ctx: &Ctx, actor: Actor<'_>, name: &str) -> Result<(), Error> {
        actor.need("roles:admin")?;
        let role = self.role(name).await?;
        if !scope::covers(actor.scopes, &role.scopes) {
            return Err(Error::Forbidden);
        }
        if !self.store.delete_role(role.id).await? {
            return Err(Error::NotFound);
        }
        self.audit(ctx, None, Some(actor.user.id), "role_delete", &role.name).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "role_delete", actor = %actor.user.id.hex(),
            role = ?role.name);
        Ok(())
    }

    /// False when the account already held the role.
    pub async fn grant_role(&self, ctx: &Ctx, actor: Actor<'_>, target: AccountId, role: &str) -> Result<bool, Error> {
        actor.need("users:admin")?;
        let role = self.role(role).await?;
        if !scope::covers(actor.scopes, &role.scopes) {
            return Err(Error::Forbidden);
        }
        self.store.user_by_id(target).await?.ok_or(Error::NotFound)?;
        if !self.store.grant_role(target, role.id, Some(actor.user.id)).await? {
            return Ok(false);
        }
        self.audit(ctx, Some(target), Some(actor.user.id), "role_grant", &role.name).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "role_grant", actor = %actor.user.id.hex(),
            user = %target.hex(), role = ?role.name);
        Ok(true)
    }

    /// False when the account did not hold the role. Ends every session of the
    /// account, so the loss counts from now on in every tab.
    pub async fn revoke_role(&self, ctx: &Ctx, actor: Actor<'_>, target: AccountId, role: &str) -> Result<bool, Error> {
        actor.need("users:admin")?;
        let role = self.role(role).await?;
        if !scope::covers(actor.scopes, &role.scopes) {
            return Err(Error::Forbidden);
        }
        if !self.store.revoke_role(target, role.id).await? {
            return Ok(false);
        }
        self.store.delete_sessions_of(target, None).await?;
        self.audit(ctx, Some(target), Some(actor.user.id), "role_revoke", &role.name).await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = "role_revoke", actor = %actor.user.id.hex(),
            user = %target.hex(), role = ?role.name);
        Ok(true)
    }

    /// Newest first, at most 100 a page, with the total.
    pub async fn list_users(&self, actor: Actor<'_>, search: Option<&str>, limit: u32, offset: u32) -> Result<(Vec<User>, i64), Error> {
        actor.need("users:read")?;
        Ok(self.store.list_users(search, limit.min(100), offset).await?)
    }

    pub async fn user_detail(&self, actor: Actor<'_>, id: AccountId) -> Result<UserDetail, Error> {
        actor.need("users:read")?;
        let user = self.store.user_by_id(id).await?.ok_or(Error::NotFound)?;
        Ok(UserDetail { user, roles: self.store.user_roles(id).await?, audit: self.store.audit_of(id, 100).await? })
    }

    /// Disabling ends every session of the account. False when it already had
    /// that status.
    pub async fn set_user_status(&self, ctx: &Ctx, actor: Actor<'_>, target: AccountId, status: UserStatus) -> Result<bool, Error> {
        actor.need("users:admin")?;
        let user = self.manageable(actor, target).await?;
        if user.status == status {
            return Ok(false);
        }
        self.store.set_status(target, status).await?;
        if status == UserStatus::Disabled {
            self.store.delete_sessions_of(target, None).await?;
        }
        let event = if status == UserStatus::Disabled { "disable" } else { "enable" };
        self.audit(ctx, Some(target), Some(actor.user.id), event, "").await?;
        tracing::info!(target: "accounts", ip = %self.shaped_ip(ctx.ip), outcome = event, actor = %actor.user.id.hex(),
            user = %target.hex());
        Ok(true)
    }
}
