//! Roles and user administration. Every call that takes an `Actor` checks its
//! scope here, so a handler that forgets to cannot hand out more than its
//! caller holds. The `*_as_host` calls are for the host's own shell, where no
//! signed-in admin answers for them: they check nothing, and their audit rows
//! have no actor and say "(host)".

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
        super::need(self.scopes, required)
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
    if d.chars().any(scope::breaks_text) {
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

    pub(super) async fn role(&self, name: &str) -> Result<Role, Error> {
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
        // In one go: meanwhile an empty role would pass `grant_role`'s check.
        let id = self.store.create_role_with_scopes(&name, &description, badge.as_deref(), &scopes).await?.ok_or(Error::RoleTaken)?;
        self.record_after(ctx, None, Some(actor.user.id), "role_create", &format!("{name}: {}", scopes.join(" "))).await;
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
        self.record_after(ctx, None, Some(actor.user.id), "role_update", &format!("{}: {}", role.name, scopes.join(" "))).await;
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
        self.record_after(ctx, None, Some(actor.user.id), "role_delete", &role.name).await;
        Ok(())
    }

    /// False when the account already held the role. The actor covers the
    /// role and the target, as for a suspension: a grant and a revoke could
    /// otherwise be repeated at will on someone with more power.
    pub async fn grant_role(&self, ctx: &Ctx, actor: Actor<'_>, target: AccountId, role: &str) -> Result<bool, Error> {
        actor.need("users:admin")?;
        let role = self.role(role).await?;
        if !scope::covers(actor.scopes, &role.scopes) {
            return Err(Error::Forbidden);
        }
        self.manageable(actor, target).await?;
        self.do_grant_role(ctx, Some(actor.user.id), target, &role).await
    }

    /// `grant_role` for the host itself (its own shell), where no signed-in
    /// admin answers for it. The audit row has no actor.
    pub async fn grant_role_as_host(&self, ctx: &Ctx, target: AccountId, role: &str) -> Result<bool, Error> {
        let role = self.role(role).await?;
        self.do_grant_role(ctx, None, target, &role).await
    }

    async fn do_grant_role(&self, ctx: &Ctx, actor: Option<AccountId>, target: AccountId, role: &Role) -> Result<bool, Error> {
        self.store.user_by_id(target).await?.ok_or(Error::NotFound)?;
        if !self.store.grant_role(target, role.id, actor).await? {
            return Ok(false);
        }
        self.record_after(ctx, Some(target), actor, "role_grant", &marked(&role.name, actor)).await;
        Ok(true)
    }

    /// False when the account did not hold the role. Ends every session of the
    /// account, so the loss counts from now on in every tab. The actor covers
    /// the role and the target, as for `grant_role`.
    pub async fn revoke_role(&self, ctx: &Ctx, actor: Actor<'_>, target: AccountId, role: &str) -> Result<bool, Error> {
        actor.need("users:admin")?;
        let role = self.role(role).await?;
        if !scope::covers(actor.scopes, &role.scopes) {
            return Err(Error::Forbidden);
        }
        self.manageable(actor, target).await?;
        self.do_revoke_role(ctx, Some(actor.user.id), target, &role).await
    }

    /// `revoke_role` for the host itself. The last holder of `*` still keeps it.
    pub async fn revoke_role_as_host(&self, ctx: &Ctx, target: AccountId, role: &str) -> Result<bool, Error> {
        let role = self.role(role).await?;
        self.do_revoke_role(ctx, None, target, &role).await
    }

    async fn do_revoke_role(&self, ctx: &Ctx, actor: Option<AccountId>, target: AccountId, role: &Role) -> Result<bool, Error> {
        if !self.store.revoke_role(target, role.id).await? {
            return Ok(false);
        }
        self.store.delete_sessions_of(target, None).await?;
        self.record_after(ctx, Some(target), actor, "role_revoke", &marked(&role.name, actor)).await;
        Ok(true)
    }

    /// For someone who lost their second factor: codes, recovery codes,
    /// passkeys, device keys and sessions all go, whichever of them there
    /// were. The next sign-in is by password, a linked account or an SSH key,
    /// and a role that needs a second factor asks for a new one. False when
    /// there was nothing to remove.
    pub async fn reset_2fa(&self, ctx: &Ctx, actor: Actor<'_>, target: AccountId) -> Result<bool, Error> {
        actor.need("users:admin")?;
        self.manageable(actor, target).await?;
        self.do_reset_2fa(ctx, Some(actor.user.id), target).await
    }

    /// `reset_2fa` for the host itself: the way back in for a sole admin who
    /// lost their authenticator. The audit row has no actor.
    pub async fn reset_2fa_as_host(&self, ctx: &Ctx, target: AccountId) -> Result<bool, Error> {
        self.store.user_by_id(target).await?.ok_or(Error::NotFound)?;
        self.do_reset_2fa(ctx, None, target).await
    }

    async fn do_reset_2fa(&self, ctx: &Ctx, actor: Option<AccountId>, target: AccountId) -> Result<bool, Error> {
        let codes = self.store.set_totp(target, None, 0).await?;
        let passkeys = self.store.delete_credentials_of(target, super::passkey::KIND).await?;
        let recovery = self.store.recovery_left(target).await?;
        self.store.delete_recovery(target).await?;
        // Device keys before sessions, as everywhere (`revoke_devkeys`).
        let devkeys = self.revoke_devkeys(ctx, target, actor, "totp_reset").await?;
        let sessions = self.store.delete_sessions_of(target, None).await?;
        if !codes && passkeys == 0 && recovery == 0 && devkeys == 0 && sessions == 0 {
            return Ok(false);
        }
        self.record_after(ctx, Some(target), actor, "totp_reset", &marked("", actor)).await;
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
        self.record_after(ctx, Some(target), Some(actor.user.id), event, "").await;
        Ok(true)
    }
}

/// Who did it, for the log line: the admin's account, or the host's own shell.
pub(super) fn by(actor: Option<AccountId>) -> String {
    actor.map_or_else(|| "host".to_string(), |a| a.hex())
}

/// An audit detail, with " (host)" when the host's own shell acted: the row
/// has no actor then, which the History shows as blank, like the account's
/// own doing.
pub(super) fn marked(detail: &str, actor: Option<AccountId>) -> String {
    match actor {
        Some(_) => detail.to_string(),
        None => format!("{detail} (host)").trim_start().to_string(),
    }
}
