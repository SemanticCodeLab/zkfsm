import { useEffect, useState } from "preact/hooks";
import { LoginMethods, Session, session } from "../lib/api";
import { Button, TextInput } from "../components/ui";

export function Login({ onLogin }: { onLogin: (s: Session) => void }) {
  const [ak, setAk] = useState("");
  const [sk, setSk] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [methods, setMethods] = useState<LoginMethods>({ password: true, openid: [] });
  useEffect(() => {
    session.methods().then(setMethods, () => {});
    const e = new URLSearchParams(location.search).get("error");
    if (e) setErr(e);
  }, []);
  return (
    <div class="login">
      <form
        class="login-card"
        aria-label="Log in"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setErr(null);
          try {
            onLogin(await session.login(ak, sk));
          } catch (x) {
            setErr((x as Error).message || "Login failed");
          } finally {
            setBusy(false);
          }
        }}
      >
        <h1>zkfsm console</h1>
        {methods.password && (
          <>
            <TextInput label="Access key" value={ak} onInput={setAk} autoComplete="username" autoFocus required name="accessKey" />
            <TextInput label="Secret key" value={sk} onInput={setSk} type="password" autoComplete="current-password" required name="secretKey" />
            {err && (
              <div class="notice notice-error" role="alert">
                {err}
              </div>
            )}
            <Button type="submit" variant="primary" disabled={busy || !ak || !sk}>
              {busy ? "Signing in…" : "Log in"}
            </Button>
          </>
        )}
        {methods.openid.length > 0 && (
          <div class="sso">
            <div class="or">or</div>
            {methods.openid.map((p) => (
              <a key={p.name} class="btn btn-default" href={session.openidStart(p.name)}>
                Log in with {p.label || p.name}
              </a>
            ))}
          </div>
        )}
      </form>
    </div>
  );
}
