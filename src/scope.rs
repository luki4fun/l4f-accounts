//! Scopes (`links:own`, `links:*`, `*`), the crate's scope registry, and the
//! rules for usernames and display names.
//!
//! A scope is lowercase segments joined by `:`. Lowercase only, so `Links:own`
//! can never sit in a role as a second scope that reads the same in the admin UI.
//! A wildcard may only close a grant, which keeps matching a prefix test that
//! ends on a segment boundary: `links:*` must not grant `linksx`.

const MAX_LEN: usize = 64;

/// A requested or required scope: no wildcards.
pub fn valid_scope(s: &str) -> bool {
    s.len() <= MAX_LEN
        && s.split(':').all(|seg| !seg.is_empty() && seg.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-')))
}

/// A scope as stored on a role: a plain scope, `prefix:*`, or `*`.
pub fn valid_grant(s: &str) -> bool {
    s == "*" || (s.len() <= MAX_LEN && valid_scope(s.strip_suffix(":*").unwrap_or(s)))
}

/// Does `grant` (from a role) grant `required`?
///
/// Malformed input on either side grants nothing: a hand-edited role row such as
/// `links*` would otherwise match `linksx` as a bare prefix, and a wildcard is
/// never a valid requirement (to ask whether someone may hold `*`, use `covers`).
pub fn grants(grant: &str, required: &str) -> bool {
    if !valid_grant(grant) || !valid_scope(required) {
        return false;
    }
    match grant.strip_suffix('*') {
        // "" for `*`, "links:" for `links:*`: the colon is what keeps `linksx` out.
        Some(prefix) => required.starts_with(prefix),
        None => grant == required,
    }
}

pub fn allowed(held: &[String], required: &str) -> bool {
    held.iter().any(|g| grants(g, required))
}

/// Role-edit guard: an actor may hand out `role_scopes` (grant the role, or edit
/// its scopes) only if they already hold every one of them, or a role editor
/// could promote themselves.
///
/// A wildcard on the role needs an equal or wider wildcard on the actor. Holding
/// `links:own` and `links:admin` is not enough to hand out `links:*`, because
/// `links:*` also grants every `links:` scope an app registers later.
pub fn covers(actor: &[String], role_scopes: &[String]) -> bool {
    role_scopes.iter().all(|give| valid_grant(give) && actor.iter().any(|have| grant_covers(have, give)))
}

/// Is everything `give` grants, today and after new scopes appear, also granted
/// by `have`? `give` is already a valid grant.
fn grant_covers(have: &str, give: &str) -> bool {
    match give.strip_suffix('*') {
        // `*` → "", `links:own:*` → "links:own:"; `have` must be a wildcard whose
        // prefix is the same or shorter, on a segment boundary.
        Some(given) => valid_grant(have) && have.strip_suffix('*').is_some_and(|held| given.starts_with(held)),
        None => grants(have, give),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeDef {
    pub name: &'static str,
    pub description: &'static str,
}

/// The crate's own scopes. Apps register theirs next to these; a role may only
/// carry a registered scope, so a typo cannot become a silent no-op grant.
pub const CRATE_SCOPES: &[ScopeDef] = &[
    ScopeDef { name: "users:read", description: "See the user list and account details" },
    ScopeDef { name: "users:admin", description: "Suspend users, reset their credentials and delete accounts" },
    ScopeDef { name: "roles:admin", description: "Create roles, edit their scopes and assign them" },
    ScopeDef { name: "storage:sync", description: "Sync settings and saved data to the server" },
    ScopeDef { name: "vault:use", description: "Keep an end-to-end encrypted vault" },
    ScopeDef { name: "profile:public", description: "Publish a public profile page" },
];

/// Names people trust by default, and words that read as part of the site. On an
/// open sign-up page, whoever takes `admin` first speaks as the site's staff.
#[rustfmt::skip]
pub const RESERVED: &[&str] = &[
    "admin", "administrator", "root", "system", "support", "help", "security", "abuse", "postmaster",
    "hostmaster", "webmaster", "noreply", "no-reply", "staff", "mod", "moderator", "l4f", "luki", "luki4fun",
    "account", "accounts", "profile", "login", "logout", "register", "signup", "api", "static", "oauth",
    "settings", "me", "null", "undefined",
];

/// The stored, unique form of a username, or why it is refused. `extra_reserved`
/// is the app's own list (its route words), compared case-insensitively.
///
/// ASCII only, so no two names look alike through Unicode homoglyphs (Cyrillic
/// `а` for `a`) or Unicode case folding; ASCII look-alikes of a reserved name
/// (`1uki`, `adrnin`, `luki_`) are refused through `skeleton`. Never all
/// digits, so a name cannot pass for a numeric id; never a leading `_` or `-`,
/// which read as markers and flags.
pub fn normalize_username(raw: &str, extra_reserved: &[&str]) -> Result<String, &'static str> {
    let name = username_shape(raw)?;
    let sk = skeleton(&name);
    if RESERVED.iter().chain(extra_reserved).any(|r| skeleton(r) == sk) {
        return Err("That username is reserved. Pick another one.");
    }
    Ok(name)
}

/// Every rule but the reserved list. For names the site picks itself (the
/// bootstrap admin, `luki4fun`, is reserved for exactly that reason) and for
/// the login lookup, which must find such names too.
pub(crate) fn username_shape(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim().to_ascii_lowercase();
    // Charset first: after it, bytes are characters and the length check is exact.
    if !name.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')) {
        return Err("Only a-z, 0-9, _ and - are allowed in a username.");
    }
    if !(3..=32).contains(&name.len()) {
        return Err("Pick a username between 3 and 32 characters.");
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return Err("A username must start with a letter or a digit.");
    }
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return Err("A username cannot be only digits.");
    }
    Ok(name)
}

/// Folds ASCII look-alikes so a name that reads as a reserved one counts as it:
/// `1` and `i` as `l`, `0` as `o`, `rn` as `m`, `vv` as `w`, `cl` as `d`
/// (confusables.txt, plus i/l, which many fonts barely tell apart), and `-`/`_`
/// dropped. Only ever compared, never stored.
fn skeleton(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| !matches!(c, '-' | '_'))
        .map(|c| match c.to_ascii_lowercase() {
            '1' | 'i' => 'l',
            '0' => 'o',
            c => c,
        })
        .collect();
    s.replace("rn", "m").replace("vv", "w").replace("cl", "d")
}

/// Bidi controls and marks reorder the text and whatever the page prints after
/// it; the zero-width space, word joiner and BOM only make look-alikes differ.
/// ZWJ and ZWNJ are not here: emoji and Persian or Indic spelling need them.
pub(crate) fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061c}' | '\u{200b}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}' | '\u{2066}'..='\u{2069}' | '\u{feff}'
    )
}

/// Renders as nothing on its own: whitespace, the `invisible` set, joiners,
/// fillers, variation selectors, tag characters and the blank Braille cell.
fn blank(c: char) -> bool {
    c.is_whitespace()
        || invisible(c)
        || matches!(
            c,
            '\u{00ad}'
                | '\u{034f}'
                | '\u{115f}'
                | '\u{1160}'
                | '\u{17b4}'
                | '\u{17b5}'
                | '\u{180b}'..='\u{180f}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{2061}'..='\u{2065}'
                | '\u{206a}'..='\u{206f}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{fe00}'..='\u{fe0f}'
                | '\u{ffa0}'
                | '\u{fff0}'..='\u{fffb}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0000}'..='\u{e0fff}'
        )
}

/// A display name is free text shown next to other people's content, so it must
/// not break a log line or a layout (control characters, and the Unicode line and
/// paragraph separators U+2028/U+2029, which are not `Cc` but still force a line
/// break and could fake a second line under the name) or reorder the text
/// around it (bidi overrides and isolates, the "Trojan Source" trick that can make
/// a name render as someone else's or flip an adjacent file name). Zero-width
/// characters are refused too, and a name must show at least one visible
/// character, so nobody appears as a blank.
pub fn clean_display_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.trim();
    if name.is_empty() {
        return Err("The display name cannot be empty.");
    }
    // `nth` stops after 65 characters instead of counting a huge paste.
    if name.chars().nth(64).is_some() {
        return Err("Keep the display name to 64 characters or fewer.");
    }
    if name.chars().any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')) {
        return Err("The display name cannot contain control characters or line breaks.");
    }
    if name.chars().any(invisible) {
        return Err("The display name cannot contain invisible or text-direction characters.");
    }
    if name.chars().all(blank) {
        return Err("The display name needs at least one visible character.");
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    /// Refused, and for the stated reason, so a test cannot pass on the wrong rule.
    fn assert_err(got: Result<String, &str>, reason: &str, input: &str) {
        match got {
            Err(e) => assert!(e.contains(reason), "{input:?}: expected a {reason:?} error, got {e:?}"),
            Ok(s) => panic!("{input:?} must be refused ({reason}), got {s:?}"),
        }
    }

    #[test]
    fn valid_scope_accepts_plain_segments() {
        for ok in ["links:own", "users:admin", "a", "a.b-c_d:0", "links:own:x", &"a".repeat(64), &format!("{}:b", "a".repeat(62))] {
            assert!(valid_scope(ok), "{ok:?} should be a valid scope");
        }
    }

    #[test]
    fn valid_scope_refuses_wildcards_and_malformed_input() {
        for bad in [
            "",
            ":",
            "a:",
            ":a",
            "a::b",
            "Links:own",
            "links:Own",
            "links:*",
            "*",
            "links*",
            "a b",
            "links:own ",
            " links:own",
            "links/own",
            "links:öwn",
            "links:own\n",
            "links:\0",
            &"a".repeat(65),
        ] {
            assert!(!valid_scope(bad), "{bad:?} must not be a valid scope");
        }
    }

    #[test]
    fn valid_grant_allows_a_trailing_wildcard_only() {
        for ok in ["*", "links:*", "links:own:*", "links:own", "a", &format!("{}:*", "a".repeat(62))] {
            assert!(valid_grant(ok), "{ok:?} should be a valid grant");
        }
        for bad in [
            "",
            "**",
            "*:links",
            "links:*:own",
            "links*",
            "links:**",
            ":*",
            "links:*x",
            "links:x*",
            "Links:*",
            "links: *",
            "*links",
            "links:*:*",
            "* ",
            " *",
            &format!("{}:*", "a".repeat(63)),
        ] {
            assert!(!valid_grant(bad), "{bad:?} must not be a valid grant");
        }
    }

    #[test]
    fn star_grants_every_valid_scope() {
        for s in ["users:admin", "roles:admin", "links:own", "x"] {
            assert!(grants("*", s), "* must grant {s:?}");
        }
        assert!(!grants("*", ""), "an empty requirement is malformed, not free");
        assert!(!grants("*", "Users:admin"));
    }

    #[test]
    fn prefix_wildcard_grants_children_on_a_segment_boundary() {
        assert!(grants("links:*", "links:own"));
        assert!(grants("links:*", "links:own:x"));
        assert!(grants("links:*", "links:admin"));
        assert!(!grants("links:*", "linksx"), "the wildcard must not match a longer first segment");
        assert!(!grants("links:*", "linksx:own"));
        assert!(!grants("links:*", "links"), "links:* grants children, not the bare parent");
        assert!(!grants("links:*", "users:read"));
        assert!(!grants("links:own:*", "links:admin"));
        assert!(!grants("links:own:*", "links:own"));
        assert!(grants("links:own:*", "links:own:x"));
    }

    #[test]
    fn exact_grants_match_exactly() {
        assert!(grants("links:own", "links:own"));
        assert!(!grants("links:own", "links:own:x"), "an exact scope has no children");
        assert!(!grants("links:own", "links:admin"));
        assert!(!grants("links:own", "links"));
        assert!(!grants("links:own", "links:ow"));
    }

    #[test]
    fn malformed_grants_and_requirements_never_grant() {
        assert!(!grants("links*", "linksx"), "a bare-prefix wildcard is malformed, not a prefix match");
        assert!(!grants("Links:*", "links:own"));
        assert!(!grants("links:", "links:own"));
        assert!(!grants("", ""));
        assert!(!grants("", "links:own"));
        assert!(!grants("links:*", "links:*"), "a wildcard is never a requirement");
        assert!(!grants("*", "*"));
        assert!(!grants("Links:own", "Links:own"), "equal but invalid strings still grant nothing");
    }

    #[test]
    fn allowed_needs_one_matching_grant() {
        let held = v(&["users:read", "links:*"]);
        assert!(allowed(&held, "users:read"));
        assert!(allowed(&held, "links:admin"));
        assert!(!allowed(&held, "users:admin"));
        assert!(!allowed(&[], "users:read"), "no grants, no access");
        assert!(allowed(&v(&["bogus*", "*"]), "roles:admin"), "a malformed row does not spoil the valid ones");
    }

    #[test]
    fn covers_links_wildcard_hands_out_links_only() {
        let actor = v(&["links:*"]);
        for ok in [&["links:own"][..], &["links:*"], &["links:own:*"], &["links:own", "links:admin"], &[]] {
            assert!(covers(&actor, &v(ok)), "links:* must cover {ok:?}");
        }
        for bad in [&["*"][..], &["users:admin"], &["links:own", "users:admin"], &["linksx:*"], &["linksx"], &["links"], &["users:*"]] {
            assert!(!covers(&actor, &v(bad)), "links:* must not cover {bad:?}");
        }
    }

    #[test]
    fn covers_star_hands_out_anything_valid() {
        let actor = v(&["*"]);
        for ok in [&["*"][..], &["users:admin", "links:*", "roles:admin"], &["links:own:*"], &["x"]] {
            assert!(covers(&actor, &v(ok)), "* must cover {ok:?}");
        }
    }

    #[test]
    fn exact_scopes_never_cover_a_wildcard() {
        let actor = v(&["links:own", "links:admin"]);
        assert!(covers(&actor, &v(&["links:own"])));
        assert!(covers(&actor, &v(&["links:own", "links:admin"])));
        assert!(!covers(&actor, &v(&["links:*"])), "a future links: scope would come along for free");
        assert!(!covers(&actor, &v(&["links:own:*"])), "an exact scope does not cover its own subtree");
        assert!(!covers(&actor, &v(&["*"])));
    }

    #[test]
    fn narrower_wildcard_does_not_cover_a_wider_one() {
        let actor = v(&["links:own:*"]);
        assert!(covers(&actor, &v(&["links:own:*"])));
        assert!(covers(&actor, &v(&["links:own:x"])));
        assert!(covers(&actor, &v(&["links:own:x:*"])));
        assert!(!covers(&actor, &v(&["links:*"])));
        assert!(!covers(&actor, &v(&["links:own"])), "links:own:* does not include the bare links:own");
        assert!(!covers(&actor, &v(&["*"])));
    }

    #[test]
    fn covers_needs_every_role_scope() {
        let actor = v(&["links:*", "users:read"]);
        assert!(covers(&actor, &v(&["links:own", "users:read"])));
        assert!(!covers(&actor, &v(&["links:own", "users:read", "users:admin"])), "one uncovered scope refuses all");
        assert!(!covers(&actor, &v(&["users:*"])), "users:read does not cover users:*");
        assert!(!covers(&[], &v(&["users:read"])), "an actor without grants hands out nothing");
        assert!(covers(&[], &[]), "an empty role grants nothing, so anyone may hand it out");
    }

    #[test]
    fn covers_refuses_malformed_role_scopes_even_for_star() {
        let actor = v(&["*"]);
        for bad in ["", "Links:own", "links:*:x", "links*", "**", "links:", &"a".repeat(65)] {
            assert!(!covers(&actor, &v(&[bad])), "{bad:?} must never be handed out");
        }
    }

    #[test]
    fn covers_ignores_malformed_actor_grants() {
        assert!(!covers(&v(&["links*"]), &v(&["linksx:*"])), "a malformed wildcard must not act as a bare prefix");
        assert!(!covers(&v(&["links*"]), &v(&["linksx"])));
        assert!(!covers(&v(&["Links:*"]), &v(&["links:own"])));
        assert!(!covers(&v(&["*x"]), &v(&["*"])));
        assert!(!covers(&v(&["* "]), &v(&["users:admin"])));
    }

    /// Whatever `covers` lets an actor hand out must never grant more than the
    /// actor already has, checked over every pair from a small universe.
    #[test]
    fn covers_never_hands_out_more_than_the_actor_holds() {
        let grants_universe = [
            "*",
            "links:*",
            "links:own",
            "links:admin",
            "links:own:*",
            "links:own:x",
            "linksx:*",
            "linksx",
            "links",
            "users:*",
            "users:read",
            "users:admin",
            "links*",
            "Links:*",
            "",
        ];
        let scopes = [
            "links",
            "links:own",
            "links:admin",
            "links:own:x",
            "links:own:x:y",
            "linksx",
            "linksx:own",
            "users:read",
            "users:admin",
            "roles:admin",
            "x",
        ];
        for have in grants_universe {
            for give in grants_universe {
                if !covers(&v(&[have]), &v(&[give])) {
                    continue;
                }
                for s in scopes {
                    assert!(!grants(give, s) || grants(have, s), "{have:?} handed out {give:?}, which grants {s:?}");
                }
                if give.ends_with('*') {
                    assert!(have.ends_with('*'), "{have:?} handed out the open-ended {give:?}");
                }
            }
        }
    }

    #[test]
    fn crate_scopes_are_the_six_declared_and_valid() {
        let names: Vec<&str> = CRATE_SCOPES.iter().map(|d| d.name).collect();
        assert_eq!(names, ["users:read", "users:admin", "roles:admin", "storage:sync", "vault:use", "profile:public"]);
        for d in CRATE_SCOPES {
            assert!(valid_scope(d.name), "{} must be a valid, wildcard-free scope", d.name);
            assert!(!d.description.is_empty(), "{} needs a description for the role editor", d.name);
        }
    }

    #[test]
    fn usernames_are_trimmed_and_lowercased() {
        assert_eq!(normalize_username("  Alice_01 ", &[]), Ok("alice_01".into()));
        assert_eq!(normalize_username("Bob-Smith", &[]), Ok("bob-smith".into()));
        assert_eq!(normalize_username("1alice", &[]), Ok("1alice".into()), "a leading digit is fine");
        assert_eq!(normalize_username("123a", &[]), Ok("123a".into()));
        assert_eq!(normalize_username("alice_", &[]), Ok("alice_".into()));
        assert_eq!(normalize_username("admin2", &[]), Ok("admin2".into()), "only the exact word is reserved");
    }

    #[test]
    fn username_length_is_3_to_32() {
        assert!(normalize_username("abc", &[]).is_ok());
        assert!(normalize_username(&"a".repeat(32), &[]).is_ok());
        for bad in ["", "   ", "ab", " ab ", &"a".repeat(33)] {
            assert_err(normalize_username(bad, &[]), "between 3 and 32", bad);
        }
    }

    #[test]
    fn username_charset_is_ascii_only() {
        for bad in [
            "al ice",
            "alice!",
            "alice.b",
            "alice@x",
            "ali\0ce",
            "ali\nce",
            "älice",
            "ａｌｉｃｅ",
            "\u{212A}elvin",
            "\u{0430}dmin",
            "alice\u{200B}",
            "ali\u{0301}ce",
        ] {
            assert_err(normalize_username(bad, &[]), "Only a-z", bad);
        }
    }

    #[test]
    fn username_must_start_with_a_letter_or_digit() {
        assert_err(normalize_username("_alice", &[]), "start with", "_alice");
        assert_err(normalize_username("-alice", &[]), "start with", "-alice");
        assert_err(normalize_username(" _alice", &[]), "start with", "trimming must not hide a leading underscore");
    }

    #[test]
    fn username_cannot_be_all_digits() {
        for bad in ["123", "0000", &"9".repeat(32)] {
            assert_err(normalize_username(bad, &[]), "only digits", bad);
        }
    }

    #[test]
    fn reserved_usernames_are_refused_in_any_case() {
        for r in RESERVED {
            // `me` is caught by the length rule first; it must be refused either way.
            let why = if r.len() < 3 { "between 3 and 32" } else { "reserved" };
            assert_err(normalize_username(r, &[]), why, r);
            assert_err(normalize_username(&r.to_ascii_uppercase(), &[]), why, r);
        }
        assert_err(normalize_username(" Admin ", &[]), "reserved", " Admin ");
        assert_err(normalize_username("No-Reply", &[]), "reserved", "No-Reply");
    }

    #[test]
    fn app_reserved_words_are_refused_case_insensitively() {
        let extra = ["links", "Tools", "dns"];
        assert_err(normalize_username("links", &extra), "reserved", "links");
        assert_err(normalize_username("tools", &extra), "reserved", "the app's list may use any case");
        assert_err(normalize_username("TOOLS", &extra), "reserved", "TOOLS");
        assert!(normalize_username("links", &[]).is_ok(), "only reserved when the app says so");
        assert!(normalize_username("linksx", &extra).is_ok());
    }

    #[test]
    fn lookalikes_of_reserved_names_are_refused() {
        for bad in ["1uki", "luk1", "lukl", "adrnin", "adm1n", "admln", "r00t", "luki_", "l-u-k-i", "vvebmaster", "he1p", "nu11", "AdRnIn"] {
            assert_err(normalize_username(bad, &[]), "reserved", bad);
        }
        assert_err(normalize_username("1inks", &["links"]), "reserved", "app words are folded too");
        for ok in ["lucky", "luka", "admins", "rootkit", "helper", "linkz"] {
            assert!(normalize_username(ok, &["links"]).is_ok(), "{ok} only resembles a reserved name");
        }
    }

    #[test]
    fn display_names_are_trimmed_free_text() {
        assert_eq!(clean_display_name("  Luki  "), Ok("Luki".into()));
        assert_eq!(clean_display_name("\tLuki\n"), Ok("Luki".into()), "edge whitespace is trimmed, not refused");
        assert_eq!(clean_display_name("Anna Müller 🚀"), Ok("Anna Müller 🚀".into()));
        assert_eq!(clean_display_name("x\u{2070}"), Ok("x\u{2070}".into()), "a neighbour of the bidi range is fine");
        assert_eq!(clean_display_name("مرحبا"), Ok("مرحبا".into()), "right-to-left text itself is fine");
    }

    #[test]
    fn display_name_length_counts_characters() {
        assert!(clean_display_name(&"ä".repeat(64)).is_ok(), "64 two-byte characters fit");
        assert_err(clean_display_name(&"a".repeat(65)), "64 characters", "65 ASCII");
        assert_err(clean_display_name(&"ä".repeat(65)), "64 characters", "65 two-byte");
        assert_err(clean_display_name(""), "empty", "empty");
        assert_err(clean_display_name(" \t\n "), "empty", "whitespace only is empty");
    }

    #[test]
    fn display_name_refuses_control_characters() {
        for bad in [
            "Lu\nki",
            "Lu\tki",
            "Lu\rki",
            "Lu\0ki",
            "Lu\u{7f}ki",
            "Lu\u{85}ki",
            "Lu\u{9b}ki",
            "Lu\u{1b}[31mki",
            "Lu\u{2028}ki",
            "Lu\u{2029}ki",
            "Luki\u{2028}(Administrator)",
        ] {
            assert_err(clean_display_name(bad), "control characters", bad);
        }
    }

    #[test]
    fn display_name_refuses_bidi_overrides_and_isolates() {
        for c in ('\u{202A}'..='\u{202E}').chain('\u{2066}'..='\u{2069}') {
            let name = format!("admin{c}nimda");
            let label = format!("U+{:04X}", c as u32);
            assert_err(clean_display_name(&name), "text-direction", &label);
            assert_err(clean_display_name(&format!("{c}x")), "text-direction", &format!("{label} at the start"));
        }
    }

    #[test]
    fn display_name_refuses_bidi_marks_and_zero_width_characters() {
        for c in ['\u{200E}', '\u{200F}', '\u{061C}', '\u{200B}', '\u{2060}', '\u{FEFF}'] {
            assert_err(clean_display_name(&format!("ad{c}min")), "invisible", &format!("U+{:04X}", c as u32));
        }
    }

    #[test]
    fn display_name_needs_a_visible_character() {
        for bad in ["\u{3164}", "\u{200D}", "\u{200C}\u{200D}", "\u{2800}", "\u{00AD}", "\u{FE0F}", "\u{E0041}", "\u{3164} \u{3164}", "\u{2065}", "\u{FFF0}", "\u{13430}", "\u{1BCA0}"] {
            assert_err(clean_display_name(bad), "visible", &format!("{bad:?}"));
        }
        assert!(clean_display_name("👨\u{200D}👩\u{200D}👧").is_ok(), "ZWJ inside an emoji sequence stays allowed");
        assert!(clean_display_name("\u{3164}x").is_ok(), "one visible character is enough");
    }
}
