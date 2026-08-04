import { useCallback, useEffect, useState } from "react";
import { api, type OAuthClientInfo } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/copy-button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { KeyRound, Plus, ShieldAlert, Trash2 } from "lucide-react";

/** One-shot reveal of a freshly created client's credentials. The secret is
 * shown exactly once — the server stores only its hash. */
type FreshCredentials = {
  client_id: string;
  client_name: string;
  client_secret?: string;
};

const parseRedirectUris = (s: string): string[] =>
  s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);

/**
 * Platform Settings → OAuth clients (the MCP data-path AS's client registry).
 *
 * Manual registrations here are the admin blessing — `trusted` unlocks the
 * jwt-bearer identity-assertion grant (tokens for a user with no user
 * present), which no self-registration path may acquire. DCR/CIMD clients
 * appear in the same list read-only-ish: deleting one revokes it the same
 * way, but they re-register themselves on their next connect.
 */
export function OAuthClientsCard() {
  const [clients, setClients] = useState<OAuthClientInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);

  // Create dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [trusted, setTrusted] = useState(false);
  const [confidential, setConfidential] = useState(true);
  const [redirectUris, setRedirectUris] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Secret reveal dialog (post-create)
  const [fresh, setFresh] = useState<FreshCredentials | null>(null);

  // Delete confirmation
  const [toDelete, setToDelete] = useState<OAuthClientInfo | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setClients(await api.listOAuthClients());
      setListError(null);
    } catch (e) {
      setListError(e instanceof Error ? e.message : "Failed to load OAuth clients");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  function openCreate() {
    setName("");
    setTrusted(false);
    setConfidential(true);
    setRedirectUris("");
    setCreateError(null);
    setCreateOpen(true);
  }

  async function submitCreate() {
    setCreating(true);
    setCreateError(null);
    try {
      const out = await api.createOAuthClient({
        client_name: name.trim(),
        trusted,
        confidential,
        redirect_uris: parseRedirectUris(redirectUris),
      });
      setCreateOpen(false);
      setFresh({
        client_id: out.client_id,
        client_name: out.client_name,
        client_secret: out.client_secret,
      });
      await reload();
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "Failed to create client");
    } finally {
      setCreating(false);
    }
  }

  async function confirmDelete() {
    if (!toDelete) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await api.deleteOAuthClient(toDelete.client_id);
      setToDelete(null);
      await reload();
    } catch (e) {
      setDeleteError(e instanceof Error ? e.message : "Failed to delete client");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div>
            <CardTitle className="flex items-center gap-2">
              <KeyRound className="h-5 w-5" />
              OAuth clients
            </CardTitle>
            <CardDescription>
              Client registry of the MCP data-path authorization server.
              Register trusted app clients (e.g. an agent backend using the
              jwt-bearer grant) here; ad-hoc MCP clients self-register via
              DCR/CIMD and are never trusted. Deleting a client stops new
              tokens and refresh immediately; outstanding access tokens expire
              within their TTL.
            </CardDescription>
          </div>
          <Button size="sm" onClick={openCreate}>
            <Plus className="mr-1 h-4 w-4" />
            Register client
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {listError && <p className="mb-3 text-sm text-destructive">{listError}</p>}
        {loading ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : clients.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No clients registered yet. MCP clients that connect interactively
            will appear here as they self-register.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Client ID</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Registration</TableHead>
                <TableHead>Trusted</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {clients.map((c) => (
                <TableRow key={c.client_id}>
                  <TableCell className="font-medium">{c.client_name}</TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-1 font-mono text-xs">
                      <span className="max-w-56 truncate" title={c.client_id}>
                        {c.client_id}
                      </span>
                      <CopyButton value={c.client_id} title="Copy client ID" />
                    </span>
                  </TableCell>
                  <TableCell className="text-sm">
                    {c.token_endpoint_auth_method === "none"
                      ? "Public (PKCE)"
                      : "Confidential"}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{c.registration_type}</Badge>
                  </TableCell>
                  <TableCell>
                    {c.trusted ? (
                      <Badge>trusted</Badge>
                    ) : (
                      <span className="text-sm text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="icon"
                      title="Delete / revoke client"
                      onClick={() => {
                        setDeleteError(null);
                        setToDelete(c);
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      {/* Create */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register OAuth client</DialogTitle>
            <DialogDescription>
              Manual registration is for app clients you operate. Interactive
              MCP clients (VS Code, Claude, …) don't need this — they
              self-register when they first connect.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="oc-name">Client name</Label>
              <Input
                id="oc-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="valkyrie"
              />
            </div>
            <div className="flex items-start gap-2">
              <input
                id="oc-confidential"
                type="checkbox"
                className="mt-1"
                checked={confidential}
                onChange={(e) => setConfidential(e.target.checked)}
              />
              <div>
                <Label htmlFor="oc-confidential">Confidential client</Label>
                <p className="text-xs text-muted-foreground">
                  Issues a client secret (server-side apps). Uncheck for a
                  public client that proves itself with PKCE instead.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-2">
              <input
                id="oc-trusted"
                type="checkbox"
                className="mt-1"
                checked={trusted}
                onChange={(e) => setTrusted(e.target.checked)}
              />
              <div>
                <Label htmlFor="oc-trusted" className="flex items-center gap-1">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Trusted
                </Label>
                <p className="text-xs text-muted-foreground">
                  Unlocks the jwt-bearer identity-assertion grant: this client
                  can obtain tokens on behalf of any user, with no user
                  interaction. Reserve for app backends you operate.
                </p>
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="oc-redirects">Redirect URIs (optional)</Label>
              <Input
                id="oc-redirects"
                value={redirectUris}
                onChange={(e) => setRedirectUris(e.target.value)}
                placeholder="https://app.example.com/callback, one per comma or line"
              />
              <p className="text-xs text-muted-foreground">
                Only needed if this client also uses the interactive
                authorization-code flow.
              </p>
            </div>
            {createError && <p className="text-sm text-destructive">{createError}</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button onClick={submitCreate} disabled={creating || name.trim() === ""}>
              {creating ? "Registering…" : "Register"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Secret reveal — once */}
      <Dialog open={fresh !== null} onOpenChange={(o) => !o && setFresh(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Client registered</DialogTitle>
            <DialogDescription>
              {fresh?.client_secret
                ? "Copy the secret now — it is shown once and only its hash is stored."
                : "Public client registered — no secret; it authenticates with PKCE."}
            </DialogDescription>
          </DialogHeader>
          {fresh && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label>Client ID</Label>
                <div className="flex items-center gap-1">
                  <Input readOnly value={fresh.client_id} className="font-mono text-xs" />
                  <CopyButton value={fresh.client_id} title="Copy client ID" />
                </div>
              </div>
              {fresh.client_secret && (
                <div className="space-y-1.5">
                  <Label>Client secret</Label>
                  <div className="flex items-center gap-1">
                    <Input
                      readOnly
                      value={fresh.client_secret}
                      className="font-mono text-xs"
                    />
                    <CopyButton value={fresh.client_secret} title="Copy client secret" />
                  </div>
                </div>
              )}
            </div>
          )}
          <DialogFooter>
            <Button onClick={() => setFresh(null)}>Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation */}
      <Dialog open={toDelete !== null} onOpenChange={(o) => !o && setToDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete client?</DialogTitle>
            <DialogDescription>
              {toDelete?.trusted
                ? `"${toDelete?.client_name}" is a trusted client. Deleting it immediately stops all token issuance for it (including jwt-bearer exchanges); outstanding access tokens expire within their TTL.`
                : `"${toDelete?.client_name}" will no longer be able to obtain or refresh tokens. A DCR/CIMD client can re-register on its next connect.`}
            </DialogDescription>
          </DialogHeader>
          {deleteError && <p className="text-sm text-destructive">{deleteError}</p>}
          <DialogFooter>
            <Button variant="outline" onClick={() => setToDelete(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={deleting}>
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
