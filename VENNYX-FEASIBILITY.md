# Vennyx Stalwart Fork — Feasibility Map

Fork: https://github.com/vennyx-org/stalwart
Clone: `/Users/oguz/SoftwareProjects/Vennyx/stalwart-fork`
Base branch: `vennyx/base` (pinned to tag `v0.16.11`, the version the task specified and the version already running in Vennyx Mila prod — confirmed this tag exists upstream, no substitution needed).
Toolchain note: the ambient `rustc`/`cargo` were 1.84.1, too old for this workspace (`crates/main/Cargo.toml` requires `edition2024`, stabilized in Rust 1.85). Ran `rustup update stable` → 1.96.1. `cargo check -p smtp` (and its full dependency chain: `store`, `directory`, `coordinator`, `common`, `groupware`, `spam-filter`, `email`) now compiles clean.

Workspace layout: 26 crates under `crates/`, largest relevant ones for this recon: `smtp` (SMTP session state machine, MTA hooks, milters), `common` (config types, domain/principal cache, auth), `directory` (SASL credential decoding, backend directories incl. SQL/LDAP), `spam-filter` (scoring engine).

---

## 1. Spam verdict in MTA-hook payload — IMPLEMENTED (this session)

**Tractability: Easy.** Confirmed and shipped on branch `vennyx/spam-verdict-in-hook` (off `vennyx/base`).

**Root cause confirmed:** `crates/smtp/src/inbound/data.rs`'s `handle_data` runs, in this exact order: (1) `self.spam_classify(...)` → `SpamFilterAction::Allow(SpamFilterScore { score, is_spam, headers, .. })` (`crates/spam-filter/src/analysis/score.rs:183`), which appends spam headers to a **local, separate** `headers: Vec<u8>` buffer; (2) `self.run_milters(Stage::Data, (&auth_message).into(), ...)`; (3) `self.run_mta_hooks(Stage::Data, (&auth_message).into(), ...)`. `auth_message` (an `AuthenticatedMessage` built from the wire bytes, untouched by step 1's header buffer) is the only thing serialized into the hook JSON body (`crates/smtp/src/inbound/hooks/message.rs::run_mta_hook`, `crates/smtp/src/inbound/hooks/mod.rs::Message`/`Context`/`Request`). The spam score/`is_spam`/tags are computed but never reach the hook payload — matches the task's premise and matches what Vennyx Mila's own `spam.resolver.ts` doc comment had already independently proven from the outside (its "THE CRUX" section cites the identical call chain).

**Change made** (all under `crates/smtp/src/inbound/`):
- `hooks/mod.rs`: added `pub struct Spam { pub score: f32, #[serde(rename = "isSpam")] pub is_spam: bool }` (Copy, cheap to thread through) and a `pub spam: Option<Spam>` field on `Context` (`skip_serializing_if = "Option::is_none"` — absent on every stage except `data`, so the payload shape is unchanged for non-DATA hooks and for anyone not yet reading the field).
- `hooks/message.rs`: `run_mta_hooks`/`run_mta_hook` gained a `spam: Option<Spam>` parameter, plumbed into `Context { ..., spam }`.
- `data.rs`: captures `spam_verdict = Some(Spam { score: score.score, is_spam: score.is_spam })` inside the existing `SpamFilterAction::Allow(score) => { ... }` arm (before `score` is otherwise consumed), then passes it into the `Stage::Data` `run_mta_hooks(...)` call. `None` when spam filtering is disabled, the session is authenticated (Stalwart skips classification for authenticated senders — unchanged behavior), or the message is discarded/rejected by the spam filter itself (those paths `return` before hooks ever run, same as before this change).
- `mail.rs`, `rcpt.rs`, `spawn.rs`, `ehlo.rs`: their `run_mta_hooks(...)` calls at `Connect`/`Ehlo`/`Mail`/`Rcpt` stages updated to pass `None` for the new parameter (spam is only known at `data`).

**Resulting payload** (only present at `stage: "data"`):
```json
"context": {
  "stage": "data",
  ...
  "spam": { "score": 4.2, "isSpam": false }
}
```
This directly unblocks Vennyx Mila's `apps/api/src/mta-hook/rule-context.ts::isSpamScoreVerdict` stub (currently hardcoded `false`) and the `aggressiveness`-threshold logic already fully implemented and unit-tested in `apps/api/src/mta-hook/resolvers/spam.resolver.ts` (`computeEffectiveAggressiveness`) but previously starved of a real content-score input.

**Verification:** `cargo check -p smtp` — clean (only pre-existing warnings in unrelated crates, not touched by this change). Full `cargo build --release` / Docker image build was **not** run (large workspace; out of scope for this pass per instructions) — see "To produce a runnable image" below.

**Not done / deliberately deferred:** did not expose the matched rule *tags* (`ctx.result.tags`, e.g. `RBL_SPAMHAUS`, `DKIM_FAIL`) — `SpamFilterContext` is dropped by the time `SpamFilterAction::Allow` returns and isn't part of `SpamFilterScore`. Score + `is_spam` boolean is the minimal, sufficient signal for the aggressiveness knob; adding tags would require threading `ctx.result.tags` out of `spam_filter_finalize` too — straightforward follow-up if Vennyx Mila later wants tag-level rules, but out of scope for "highest value, minimal diff" here.

---

## 2. Authorized-senders / wildcard-sender enforcement — Medium, genuine fork item

**Where:** `crates/smtp/src/inbound/mail.rs::handle_mail_from`, lines ~231–271, block commented `"Make sure that the authenticated user is allowed to send from this address"`.

**What actually happens:** The `Stage::Mail` MTA hook (`run_mta_hooks(Stage::Mail, ...)`) already runs **before** this block (line ~196), so the premise "hook runs before the check" is confirmed. But the check itself is independent of the hook's response: it's gated by an evaluable expression `self.server.core.smtp.session.auth.must_match_sender` (already a Stalwart `IfBlock`, i.e. admin-configurable per arbitrary session context — but the context variables available to that expression are the fixed built-in set, e.g. remote IP, authenticated user, HELO domain; there's no hook-supplied variable to hook into). If the expression evaluates true, the code compares `authenticated_as` (from SQL/directory login) against the envelope `MAIL FROM` and the account's own `authenticated_emails()` list (also SQL-sourced, i.e. the alias table) — a hard reject (`501 5.5.4 You are not allowed to send from this address.`) with **no** consultation of anything the hook could have decided at Stage::Mail.

**Approach:** Add a way for the Stage::Mail hook's response to set a per-session "sender pre-authorized" flag that this block honors as an alternative to the SQL alias-list match. Concretely:
- Add a new field to the hook `Response` struct (`crates/smtp/src/inbound/hooks/mod.rs`), e.g. `authorize_sender: bool` (or reuse/extend the existing `Modification` enum with a new variant), defaulting to `false`/absent so old hook servers are unaffected.
- In `hooks/message.rs::run_mta_hooks`, when handling the Stage::Mail hook's `Action::Accept` response, propagate that flag out (currently `Action::Accept => continue` just moves to the next hook / falls through with no side effect — would need `run_mta_hooks` to return this alongside modifications, e.g. widen its `Ok(...)` return type, or write directly into `self.data`).
- Add a `pub hook_authorized_sender: bool` field to `SessionData` (`crates/smtp/src/core/mod.rs`), reset alongside `mail_from` (it already has multiple `self.data.mail_from = None` reset points in `mail.rs` — same lifecycle).
- In `mail.rs`'s authorization block, short-circuit the reject when `self.data.hook_authorized_sender` is true.

**Effort estimate:** ~0.5–1 day: touches 3 files, all mechanical, but needs careful attention to the several `mail_from = None` reset points in `mail.rs` so the flag doesn't leak into the next `MAIL FROM` in the same session (SMTP pipelining/multiple messages per connection). **Fork item, not a vennyx-mila-side fix** — the gate genuinely lives in Rust before the hook has any say, exactly as the task assumed.

---

## 3. `move_to_junk` real folder move — NOT a fork item

**Tractability: N/A (config, not code).** Confirmed: Stalwart CE already ships full Sieve + ManageSieve support (`crates/managesieve`, `crates/email/src/sieve`), a first-class `Junk`/`$Junk` special-use mailbox and keyword (`crates/types/src/special_use.rs`, `crates/email/src/mailbox/manage.rs`, `crates/email/src/message/ingest.rs`), and IMAP/JMAP-level junk mailbox handling (`crates/imap/src/core/mailbox.rs`, `crates/jmap/src/mailbox/set.rs`). Filing a message into Junk (`fileinto :flags "\\Seen" "Junk"` or setting `$Junk`/`mailboxIds` at ingest time) is a Sieve-script or JMAP-set concern that vennyx-mila already controls (it can push per-account Sieve scripts via ManageSieve, or set the mailbox at insert time via JMAP `Email/import`). **No Stalwart code change needed** — matches the task's own suspicion. Action: implement in vennyx-mila by generating/uploading a Sieve script (or JMAP-side move) when `MailboxSpamAction` (`spam.resolver.ts`) resolves to a junk-filing action, not by touching this fork.

---

## 4. Master-access token mid-string (`local@TOKEN@domain`) — Medium/Hard, genuine fork item (parsing is easy; end-to-end verification is the hard part)

**Where:** `crates/common/src/auth/authentication.rs::UsernameParts::new` (lines ~566–597) — the exact SASL/login username parser.

**Current design:** Stalwart's own master-user impersonation syntax is `target-account%master-credentials` — the parser walks the raw username char-by-char; on hitting `%` it starts accumulating into a second `Username` (`master_user`), everything after is treated as the identity actually authenticated (its password is checked normally), and `account` (before `%`) is the identity acted-as. `UsernameParts::is_master()` / `auth_as()` / `account()` expose this downstream (`crates/common/src/auth/authentication.rs:40` `authenticate`, lines ~90, ~132, ~145, ~174, ~260 all branch on `username.is_master()`).

**Vennyx's desired shape is different in kind, not just delimiter:** `local@TOKEN@domain` isn't "log in as X, using credentials for Y" (two identities) — it's "log in as `local@domain`, using an opaque bearer TOKEN spliced into the username instead of a second identity." This needs:
1. **Parsing (Easy):** detect a username with exactly two `@` characters, split into `local`, `TOKEN`, `domain`, and reconstruct the real account as `local@domain`. A few lines in `UsernameParts::new` (or a new sibling parser invoked before it, since the current one treats `@` purely as a `domain_start` marker per identity, not a segmentation feature).
2. **Verification (Medium/Hard — the actual design work):** the parsed TOKEN has to be checked against *something*. Options: (a) a per-domain shared secret stored in the SQL directory (new directory/registry field + lookup, touches `crates/directory`), (b) treat it as an alternate `Credentials` variant validated the same place OAuth bearer tokens are today (`Credentials::Bearer`, `crates/directory/src/core/sasl.rs`), reusing existing bearer-token infrastructure instead of inventing a new one. Option (b) is materially less work since the bearer-token code path, permission checks (`Permission::EmailSend`), and error handling (`crates/smtp/src/inbound/auth.rs::authenticate`) already exist — the fork work would mainly be re-routing `local@TOKEN@domain`-shaped `AUTH PLAIN` usernames into that existing bearer path instead of `Basic`.

**Effort estimate:** parsing alone ~2–3 hours; full verified flow (reusing the Bearer path) ~1–2 days including directory-side token storage/lookup and tests. **Fork item** — this is SASL-layer parsing, cannot be done from vennyx-mila.

---

## 5. MX proxying outbound relay + subdomain addressing RCPT-stage acceptance — split verdict: outbound relay is **already CE-supported (not a fork item)**; subdomain RCPT acceptance is a **genuine, Easy/Medium fork item**

**Outbound relay / smart-host routing (not a fork item):** `crates/common/src/config/smtp/queue.rs` already defines `RoutingStrategy::{Local, Mx(MxConfig), Relay(RelayConfig)}` keyed per named routing strategy (`routing_strategy: AHashMap<String, RoutingStrategy>`), consumed by `crates/smtp/src/outbound/delivery.rs`. None of this is behind `#[cfg(feature = "enterprise")]` (checked — zero enterprise gating in `queue.rs`). Per-domain relay/smart-host behavior is a matter of Stalwart config (`IfBlock` expressions selecting a virtual queue / routing strategy per recipient domain), not Rust code. **Recommendation: configure, don't fork.**

**RCPT-stage domain acceptance (`Server::domain()`, `crates/common/src/cache/principals.rs:48`) — genuine fork item for subdomain matching:** `domain()` does an **exact-name** cache/registry lookup (`domain_names.get(domain)` then a registry `primary_key` lookup by exact `Property::Name`) — no wildcard or subdomain fallback. `crates/common/src/network/mta.rs::rcpt_resolve` (the actual RCPT-stage gate, called from `crates/smtp/src/inbound/rcpt.rs`) calls this `domain()` and returns `RcptResolution::UnknownDomain` immediately on a miss — a subdomain of a registered domain (e.g. `user@mail.customer.com` when only `customer.com` is registered) is rejected before anything else runs, confirming the task's premise. Note: this is **distinct** from Stalwart's existing `DOMAIN_FLAG_SUB_ADDRESSING` (already CE-supported — that's Gmail-style `user+tag@domain` **local-part** sub-addressing with an optional custom resolver expression, unrelated to subdomain routing on the domain part).

**Approach:** in `Server::domain()`, on an exact-match miss, walk up the label hierarchy of `domain_part` (strip one leftmost label at a time) and retry the lookup, gated by a new domain flag (e.g. `DOMAIN_FLAG_ACCEPT_SUBDOMAINS`, alongside the existing `DOMAIN_FLAG_RELAY`/`DOMAIN_FLAG_SUB_ADDRESSING` in `crates/common/src/auth/mod.rs` or wherever those flag constants live) so it's strictly opt-in per domain and doesn't change behavior for anyone not using it. `rcpt_resolve` would then also need to rewrite the effective recipient (map `user@mail.customer.com` → `user@customer.com`, similar to the existing `RcptResolution::Rewrite` path already used for sub-addressing) rather than accepting the literal subdomain address as-is.

**Effort estimate:** ~0.5–1 day — the cache/registry lookup change is small, but the label-walking needs a sane bound (e.g. cap at N labels, avoid pathological lookups on garbage input) and the rewrite-vs-accept semantics need to match how vennyx-mila actually wants subdomain mail routed (same mailbox as parent domain? separate per-subdomain mailbox?) — worth a short design confirmation with vennyx-mila before implementing, since the "correct" resolution (Accept as-is vs. Rewrite to parent domain) changes what downstream JMAP/IMAP sees. **Fork item** for the domain-part acceptance gate; the outbound relay half is not.

---

## Summary table

| # | Feature | Tractability | Fork item? | Status |
|---|---|---|---|---|
| 1 | Spam verdict in MTA-hook payload | Easy | Yes | **Implemented**, `cargo check -p smtp` clean, committed on `vennyx/spam-verdict-in-hook` |
| 2 | Authorized-senders / wildcard-sender enforcement | Medium (~0.5–1 day) | Yes | Not implemented (documented only, per instructions) |
| 3 | `move_to_junk` real folder move | N/A (config) | **No** — vennyx-mila Sieve/JMAP | Not applicable |
| 4 | Master-access token mid-string | Medium/Hard (parsing easy ~hrs, verified flow ~1–2 days) | Yes | Not implemented (documented only) |
| 5a | MX proxying outbound relay | N/A (config) | **No** — already CE-supported | Not applicable |
| 5b | Subdomain addressing RCPT-stage acceptance | Easy/Medium (~0.5–1 day) | Yes | Not implemented (documented only) |

## To produce a runnable fork image for prod

1. `cargo build --release` (or `docker buildx build` using the repo's own `Dockerfile`/`Dockerfile.build`/`docker-bake.hcl`) on `vennyx/base` (or a branch merged from it) — not run in this session; full workspace release builds are slow (LTO + codegen-units=1 per `Cargo.toml`'s `[profile.release]`) and were explicitly out of scope for this recon pass.
2. Tag and push the built image to whatever registry Vennyx Mila's deploy pulls from (the OCI prod host per existing Vennyx infra notes) — not GHCR under `stalwartlabs`, obviously; needs a `vennyx-org`-owned image name/tag.
3. Merge `vennyx/spam-verdict-in-hook` into `vennyx/base` (or keep it as the deploy branch directly) once vennyx-mila's `mta-hook` service is updated to read `context.spam.score`/`context.spam.isSpam` from the payload — coordinate the Rust-side rollout with the vennyx-mila `rule-context.ts::isSpamScoreVerdict` change so they land together.
4. No CI/release workflow exists yet in the fork for this — will need a Vennyx-side build/push pipeline (could mirror the existing `vennyx-release-v2.12.0.yml`-style workflow already used for other Vennyx forks, per this environment's existing conventions).
