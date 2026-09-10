# OAuth lab — hand-crafting every message

A companion to `docs/mcp-auth-id-jag.md`. Every flow the authorization server
supports, driven by hand with curl so you can watch each message on the wire.
Work through it in order — each lab builds on the previous one's artifacts.

Conventions:

```bash
export RH="https://roundhouse.karmatek.io"   # your MCP_BASE_URL
export PAT="<your dashboard token>"           # superadmin personal access token
jq --version                                  # you'll want jq
```

A JWT decoder you'll use constantly (claims only; **decoding is not verifying**):

```bash
jwt() { cut -d. -f2 <<<"$1" | tr '_-' '/+' | base64 -d 2>/dev/null | jq .; }
```

---

## Lab 0 — wire up the Entra tenant (one-time, `az` cli)

Everything below assumes Entra is the upstream IdP. Two app registrations are
needed, and it pays to understand *why two*:

| registration | plays the part of | client type | who validates its tokens |
|---|---|---|---|
| **Roundhouse** | the platform itself: dashboard SSO **and** the AS's federated login leg (`/oauth/entra/start` → `/oauth/entra/callback`) | confidential web app (client secret) | Roundhouse's OIDC client (`app/services/oidc.py`) |
| **Test Harness** | a generic agent harness (Valkyrie, Claude Code, …). Its Entra `id_token` is the RFC 7523 assertion in Lab 3 | public client (device code / PKCE) | Roundhouse's token endpoint, via the `entra-id-token` assertion profile whose `audience` = this app's client id |

Roundhouse deliberately uses Entra **app roles** (the `roles` claim), not
group claims — see `docs/entra-sso-plan.md` §2 for the >200-group overage
reason. The app roles are mapped to Roundhouse roles/teams in the dashboard
(Settings → Entra ID SSO → Role mappings); nothing in Entra is tied to MCP
*scopes* directly. The chain is: app role → Roundhouse role + team membership →
server access (`can_access`: superadmin, owner, or teammate of the owner) →
all of that server's registered scopes. That is the scope projection today;
per-role scope subsets are the "Phase 2 engine" seam in `claim_mapping.py`.

### 0.1 The Roundhouse app (SSO + AS federation)

```bash
TENANT=$(az account show --query tenantId -o tsv)
RH="https://roundhouse.karmatek.io"   # your MCP_BASE_URL

cat > rh-app.json <<EOF
{
  "displayName": "Roundhouse (lab)",
  "signInAudience": "AzureADMyOrg",
  "web": {"redirectUris": [
      "$RH/api/auth/oidc/callback",
      "$RH/oauth/entra/callback",
      "http://localhost:8000/api/auth/oidc/callback",
      "http://localhost:8000/oauth/entra/callback"]},
  "appRoles": [
    {"id": "$(uuidgen | tr A-Z a-z)", "allowedMemberTypes": ["User"], "isEnabled": true,
     "displayName": "Roundhouse Admin", "description": "platform superadmin", "value": "Roundhouse.Admin"},
    {"id": "$(uuidgen | tr A-Z a-z)", "allowedMemberTypes": ["User"], "isEnabled": true,
     "displayName": "Roundhouse User",  "description": "standard user",      "value": "Roundhouse.User"}],
  "optionalClaims": {"idToken": [{"name": "email"}, {"name": "preferred_username"}]},
  "requiredResourceAccess": [{"resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      {"id": "37f7f235-527c-4136-accd-4a02d197296e", "type": "Scope"},
      {"id": "14dad69e-099b-42c9-810b-d002981feec1", "type": "Scope"},
      {"id": "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0", "type": "Scope"}]}]
}
EOF
# (those three Graph scope ids are openid / profile / email)
az rest -m POST -u https://graph.microsoft.com/v1.0/applications -b @rh-app.json > rh-app.out.json
APP_OBJ=$(jq -r .id rh-app.out.json); RH_CLIENT_ID=$(jq -r .appId rh-app.out.json)

# Client secret — the value is returned ONCE. Store it; it goes into the dashboard.
az rest -m POST -u "https://graph.microsoft.com/v1.0/applications/$APP_OBJ/addPassword" \
  -b '{"passwordCredential":{"displayName":"roundhouse","endDateTime":"2027-08-23T00:00:00Z"}}' \
  | jq -r .secretText

# Service principal (the "Enterprise application") + assign yourself the admin app role
SP=$(az ad sp create --id $RH_CLIENT_ID --query id -o tsv)
ME=$(az ad signed-in-user show --query id -o tsv)
ADMIN_ROLE=$(jq -r '.appRoles[] | select(.value=="Roundhouse.Admin") | .id' rh-app.out.json)
az rest -m POST -u "https://graph.microsoft.com/v1.0/users/$ME/appRoleAssignments" \
  -b "{\"principalId\":\"$ME\",\"resourceId\":\"$SP\",\"appRoleId\":\"$ADMIN_ROLE\"}"
```

Then in Roundhouse: **Settings → Entra ID SSO → Connection**: tenant id,
`$RH_CLIENT_ID`, the secret. **Role mappings**: `Roundhouse.Admin` →
superadmin, `Roundhouse.User` → user (+ a team if you want team-scoped
server access). Sign in with Microsoft once — that JIT-provisions your Entra
user (the token endpoint never provisions; Lab 3 needs the user to exist).

### 0.2 The harness app (the assertion issuer for Lab 3)

```bash
cat > harness-app.json <<'EOF'
{
  "displayName": "Roundhouse Test Harness (lab)",
  "signInAudience": "AzureADMyOrg",
  "isFallbackPublicClient": true,
  "publicClient": {"redirectUris": ["http://localhost:8765/callback"]},
  "optionalClaims": {"idToken": [{"name": "email"}, {"name": "preferred_username"}]},
  "requiredResourceAccess": [{"resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      {"id": "37f7f235-527c-4136-accd-4a02d197296e", "type": "Scope"},
      {"id": "14dad69e-099b-42c9-810b-d002981feec1", "type": "Scope"},
      {"id": "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0", "type": "Scope"}]}]
}
EOF
az rest -m POST -u https://graph.microsoft.com/v1.0/applications -b @harness-app.json > harness-app.out.json
HARNESS_CLIENT_ID=$(jq -r .appId harness-app.out.json)
az ad sp create --id $HARNESS_CLIENT_ID --query id -o tsv
```

`isFallbackPublicClient: true` is the portal's "Allow public client flows" —
it is what lets the **device-code** grant work, which is the easiest way to
get a real Entra `id_token` with nothing but curl (3.3 below).

### 0.3 Watch an Entra id_token get minted (device code, by hand)

```bash
TENANT=$(az account show --query tenantId -o tsv)
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/devicecode" \
  -d "client_id=$HARNESS_CLIENT_ID" -d "scope=openid profile email" | tee dc.json | jq .message
# -> "To sign in, use a web browser to open https://microsoft.com/devicelogin and enter the code …"
# Do that in a browser, then poll:
curl -s -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d "client_id=$HARNESS_CLIENT_ID" -d "device_code=$(jq -r .device_code dc.json)" | tee tok.json | jq 'keys'
# ("authorization_pending" until you finish the browser step — poll every `interval` seconds)
export ENTRA_ID_TOKEN=$(jq -r .id_token tok.json)
jwt "$ENTRA_ID_TOKEN"
```

Read the claims: `iss` is `https://login.microsoftonline.com/<tenant>/v2.0`,
`aud` is the **harness** app id (not Roundhouse's), `sub` is an opaque
*pairwise* id — different for every app registration — and
`preferred_username` is your UPN. Two consequences for Lab 3:

- The assertion profile's `audience` must be `$HARNESS_CLIENT_ID`. Present an
  id_token from the *Roundhouse* app instead and the token endpoint refuses
  it (`invalid_grant`, aud mismatch) — correct: that token was issued to a
  different client.
- Roundhouse stores the user's `sub` from the **Roundhouse** app, so the
  harness assertion's `sub` will not match; the token endpoint falls back to
  matching `preferred_username`/`email` against the user table
  (`oauth_assertions._resolve_user`). Cross-app identity is by email in the
  interim.

### 0.4 Headless alternative — an Entra-signed token straight from `az`

Device code needs a browser once. For scripted runs (CI, an agent testing
itself) let the harness app *expose an API* and pre-authorize the Azure CLI's
first-party client for it; then `az account get-access-token` returns a v2.0
**access** token whose `aud` is the harness app — which is all the
`entra-id-token` profile checks (signature, `iss`, `aud`, `exp`, then
`preferred_username`/`email` for user resolution):

```bash
cat > harness-api.json <<EOF
{"identifierUris": ["api://$HARNESS_CLIENT_ID"],
 "api": {"requestedAccessTokenVersion": 2,
         "oauth2PermissionScopes": [{"id": "$(uuidgen | tr A-Z a-z)", "value": "access_as_user",
           "type": "User", "isEnabled": true,
           "adminConsentDisplayName": "Access harness as user",
           "adminConsentDescription": "Lab: az CLI obtains a harness token used as the RFC 7523 assertion"}]}}
EOF
HARNESS_OBJ=$(jq -r .id harness-app.out.json)
az rest -m PATCH -u "https://graph.microsoft.com/v1.0/applications/$HARNESS_OBJ" -b @harness-api.json
SCOPE_ID=$(jq -r '.api.oauth2PermissionScopes[0].id' harness-api.json)
# 04b07795-… is the Azure CLI's own app id; pre-authorizing it skips the consent prompt
az rest -m PATCH -u "https://graph.microsoft.com/v1.0/applications/$HARNESS_OBJ" \
  -b "{\"api\":{\"preAuthorizedApplications\":[{\"appId\":\"04b07795-8ddb-461a-bbee-02f9e1bf7b46\",\"delegatedPermissionIds\":[\"$SCOPE_ID\"]}]}}"

export ENTRA_ID_TOKEN=$(az account get-access-token --scope "api://$HARNESS_CLIENT_ID/access_as_user" --query accessToken -o tsv)
jwt "$ENTRA_ID_TOKEN"   # aud = harness app, iss = …/v2.0, azp = the az CLI, preferred_username = you
```

It is an access token rather than an id_token, but RFC 7523 doesn't care and
neither does the profile: what matters is that Entra signed a JWT *for the
harness app* naming the user. Lab 3.3 runs unchanged with it.

---

## Lab 1 — the token plane (no OAuth flows yet)

Slice 1 exists so you can see audience binding and scope gates work before any
grant machinery is involved.

### 1.1 The platform's public keys

```bash
curl -s $RH/.well-known/jwks.json | jq .
```

One RSA key (`kid` like `rh-…`). This is everything a spawned server needs to
validate tokens — note what's absent: no secrets, no callback URL. Stateless.

### 1.2 Mint a real token by hand

`/api/oauth/dev/mint` is a superadmin-only lab endpoint that skips the OAuth
front door and just exercises the mint + verify plane:

```bash
TOK=$(curl -s -X POST $RH/api/oauth/dev/mint \
  -H "Authorization: Bearer $PAT" -H 'content-type: application/json' \
  -d '{"server": "net-tools", "scopes": ["tools:ping"]}' | jq -r .access_token)
jwt "$TOK"
```

Read the claims against the design doc §7: `iss` (our AS), `aud` (exactly one
server), `sub` (you), `scope`, `exp` (≤ 1h — "revocation = short TTL").

### 1.3 Use it — and watch the two gates

```bash
# Gate 1+2 pass: right audience, scope covers the tool
curl -s $RH/s/net-tools/mcp -H "Authorization: Bearer $TOK" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | jq .

# Gate 1 fails: same (valid!) token against a different server -> 401
curl -si $RH/s/billing-api/mcp -H "Authorization: Bearer $TOK" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -1
```

That 401 is the confused-deputy defence: a compromised server cannot replay
its callers' tokens against a neighbour. Mint another token *without*
`tools:ping` and watch the scope gate hide/deny the tool instead (403 / absent
from `tools/list`) — same middleware that gates static tokens today.

> Servers built before this branch don't verify JWTs yet — redeploy one so
> codegen emits the verifier chain (`_RhMultiVerifier`). Its old `mcps_`
> static token keeps working side by side: that's the no-flag-day migration.

---

## Lab 2 — discovery: follow the breadcrumbs from a bare 401

What Claude Code does automatically, done by hand.

```bash
# 1. Knock without a token
curl -si $RH/s/net-tools/mcp -d '{}' | head -3
# 401. Now probe the RFC 9728 well-known location for this resource path:

# 2. Protected Resource Metadata — "who am I, who can issue tokens for me"
curl -s $RH/.well-known/oauth-protected-resource/s/net-tools/mcp | jq .

# 3. Its authorization_servers[0] is the platform. Fetch the AS metadata:
curl -s $RH/.well-known/oauth-authorization-server | jq .
# (also served at /.well-known/openid-configuration for enterprise probes)
```

You now know the authorize, token, and registration endpoints without any
out-of-band configuration. Fetch a second server's PRM and diff: same AS,
different `resource` — fifty servers, fifty audiences, one desk.

---

## Lab 3 — the interim Valkyrie path (jwt-bearer, RFC 7523)

The "log in once" grant. Two setup steps, then one POST per (user, server).

### 3.1 Register a trusted client (the courier's badge)

```bash
curl -s -X POST $RH/api/oauth/clients -H "Authorization: Bearer $PAT" \
  -H 'content-type: application/json' \
  -d '{"client_name": "valkyrie", "trusted": true, "confidential": true}' | jq .
export CID="rhc_…" CSEC="rhs_…"   # from the response — secret is shown ONCE
```

`trusted: true` is the admin blessing that unlocks this grant. Try the
exchange below with an untrusted DCR client and you'll get
`unauthorized_client` — that refusal *is* the design.

### 3.2 Configure the assertion profile (the allowlist)

Tell the AS which IdP-issued assertions to accept. With Entra SSO already
configured, only the audience (the harness's own Entra app client id) is new:

```bash
curl -s -X PUT $RH/api/oauth/assertion-profiles -H "Authorization: Bearer $PAT" \
  -H 'content-type: application/json' \
  -d "{\"profiles\": [{\"name\": \"entra-id-token\", \"enabled\": true,
       \"audience\": \"$HARNESS_CLIENT_ID\"}]}" | jq .
```

### 3.3 The exchange — one back-channel POST

Get a real Entra id_token for a user of the harness's Entra app — Lab 0.3's
device-code flow puts one in `$ENTRA_ID_TOKEN` — then:

```bash
curl -s -X POST $RH/oauth/token -u "$CID:$CSEC" \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d "assertion=$ENTRA_ID_TOKEN" \
  -d "resource=$RH/s/net-tools/mcp" \
  -d "scope=tools:ping" | jq .
```

Two factors in one request: `-u` proves *who's asking* (the courier),
`assertion` proves *who the user is* (the badge). Decode both JWTs side by
side — the assertion's `aud` is the harness's Entra app; the minted token's
`aud` is one server. The Entra token stopped at the desk (token-passthrough
ban). No refresh token comes back: cache per (user, server), re-exchange on
expiry.

Things to try: an expired assertion; a token whose `aud` is some other app;
a user who exists in Entra but not in Roundhouse (`invalid_grant` — the token
endpoint deliberately never JIT-provisions). Errors are the curriculum.

### 3.4 Introspect like a resource server would

```bash
curl -s -X POST $RH/oauth/introspect -u "$CID:$CSEC" -d "token=$TOK" | jq .
```

### 3.5 The ID-JAG future, today's config

The migration is one profile row (design §8). It's already implemented —
enable it to see the stricter checks (typ `oauth-id-jag+jwt`, `aud` = our
issuer, single-use `jti` with replay refusal):

```bash
curl -s -X PUT $RH/api/oauth/assertion-profiles -H "Authorization: Bearer $PAT" \
  -H 'content-type: application/json' \
  -d '{"profiles": [
        {"name": "entra-id-token", "enabled": true, "audience": "<harness-app-id>"},
        {"name": "id-jag", "enabled": true}]}' | jq .
```

Both rows live at once = the cutover posture. When Entra ships leg 1, Valkyrie
swaps which JWT it puts in the same `assertion` field; nothing else moves.

---

## Lab 4 — the interactive flow, PKCE by hand

The full browser dance with you as the client.

### 4.1 Register yourself (DCR, RFC 7591)

```bash
curl -s -X POST $RH/oauth/register -H 'content-type: application/json' \
  -d '{"client_name": "marty-by-hand",
       "redirect_uris": ["http://localhost:9999/cb"]}' | jq .
export LABCID="rhc_…"
```

Anonymous, instant, public client (`token_endpoint_auth_method: none`) — PKCE
will carry the proof instead of a secret.

### 4.2 Craft PKCE

```bash
VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=')
CHALLENGE=$(printf %s "$VERIFIER" | openssl dgst -sha256 -binary \
            | openssl base64 -A | tr '+/' '-_' | tr -d '=')
echo "verifier:  $VERIFIER"; echo "challenge: $CHALLENGE"
```

The challenge goes out in the front channel; the verifier never leaves your
shell until token time. That asymmetry is the entire defence.

### 4.3 Authorize

Listen for the redirect, then open the authorize URL in a browser:

```bash
nc -l 9999 &     # catches the redirect so you can read the code off the wire
open "$RH/oauth/authorize?response_type=code&client_id=$LABCID\
&redirect_uri=http://localhost:9999/cb&scope=tools:ping&state=lab42\
&code_challenge=$CHALLENGE&code_challenge_method=S256\
&resource=$RH/s/net-tools/mcp"
```

You'll hit the login page (first time), then the consent page (untrusted
client, first time). Approve, and read the raw redirect in the `nc` window:
`GET /cb?code=rhac_…&state=lab42`. Check `state` matches.

### 4.4 Redeem — where PKCE pays off

```bash
curl -s -X POST $RH/oauth/token \
  -d grant_type=authorization_code -d "code=rhac_…" \
  -d redirect_uri=http://localhost:9999/cb \
  -d "code_verifier=$VERIFIER" -d "client_id=$LABCID" | jq .
```

Try it with a wrong verifier first — `invalid_grant`. Then correctly. Then
**redeem the same code again**: single-use, refused. You get an access token
(decode it — same shape as every other grant's product) and a refresh token.

### 4.5 Sessions: the "login once" property, observed

Run 4.2–4.4 again for a *different* server (`resource=$RH/s/other/mcp`).
No login page, no consent page — the browser bounces straight back with a
code. That's the AS session cookie + remembered consent doing what the field
guide promised: an OAuth *flow* per server, a *login* per lifetime.

### 4.6 Refresh rotation and theft detection

```bash
curl -s -X POST $RH/oauth/token -d grant_type=refresh_token \
  -d "refresh_token=rhrt_…" -d "client_id=$LABCID" | jq .
# -> new access token AND a NEW refresh token (rotation).
# Now replay the OLD refresh token: refused — and the whole family is revoked.
```

### 4.7 The real thing

```bash
claude mcp add --transport http net-tools $RH/s/net-tools/mcp
```

Claude Code walks Lab 2 + Lab 4 automatically. Watch the platform's auth log
(`/api/…` Logs console, context `auth`) fill with `oauth.authorize` /
`oauth.token` events carrying *your* identity — the audit upgrade from
"someone with the key" to a named human.

---

## Reference: what exists where

| Piece | Path |
|---|---|
| AS metadata / JWKS / PRM | `api/app/routes/well_known.py` |
| authorize / token / register / introspect / revoke | `api/app/routes/oauth.py` |
| admin: clients, profiles, dev mint, key rotation | `api/app/routes/oauth_admin.py` |
| signing keys (encrypted at rest) | `api/app/services/oauth_keys.py` |
| JWT mint/verify, scope intersection | `api/app/services/oauth_tokens.py` |
| client registry (manual/DCR/CIMD) | `api/app/services/oauth_clients.py` |
| assertion profiles (interim + id-jag) | `api/app/services/oauth_assertions.py` |
| codes + rotating refresh tokens | `api/app/services/oauth_flows.py` |
| generated-server verifier chain | `api/app/services/codegen.py` (`_oauth_verifier_src`) |
| tests for all of the above | `api/tests/test_oauth_as.py` |
