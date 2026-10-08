import { useEffect, useState } from "preact/hooks";
import { cluster, session } from "../lib/api";
import { date, duration } from "../lib/format";
import { getPref, setTheme, ThemePref } from "../lib/theme";
import { Button, Card, Field, KeyValue, Loading, PageHeader, Select, toast, toastError, useAsync } from "../components/ui";
import { auditSubsystems, getConfigText, helpConfig, notifySubsystems, setConfig } from "./ops/configApi";
import { parseConfig } from "./ops/configkv";
import "./ops/ops.css";

function ThemeCard() {
  const [pref, setPref] = useState<ThemePref>(getPref);
  useEffect(() => {
    setTheme(pref);
    if (pref !== "system") return;
    const mq = matchMedia("(prefers-color-scheme: dark)");
    const f = () => setTheme("system");
    mq.addEventListener("change", f);
    return () => mq.removeEventListener("change", f);
  }, [pref]);
  return (
    <Card title="Appearance">
      <fieldset class="ops-radio">
        <legend>Theme</legend>
        {(["light", "dark", "system"] as ThemePref[]).map((p) => (
          <label key={p}>
            <input type="radio" name="theme" value={p} checked={pref === p} onChange={() => setPref(p)} />
            {p === "system" ? "Match system" : p[0].toUpperCase() + p.slice(1)}
          </label>
        ))}
      </fieldset>
    </Card>
  );
}

const subsystems = [...notifySubsystems, ...auditSubsystems];

function ConfigCard() {
  const [sub, setSub] = useState(subsystems[0]);
  const text = useAsync(() => getConfigText(sub), [sub]);
  const help = useAsync(() => helpConfig(sub), [sub]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => setDraft(text.data ?? ""), [text.data]);
  const bad = draft
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .find((l) => {
      const head = l.split(/\s/)[0].split(":")[0];
      return head !== sub;
    });
  const save = async () => {
    setBusy(true);
    try {
      if (!parseConfig(draft).length) throw new Error("Nothing to save.");
      await setConfig(draft);
      toast(`${sub} saved`);
      text.reload();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Server configuration" actions={<Button small onClick={text.reload}>Reload</Button>}>
      <p class="hint">The server exposes event and audit target subsystems through the configuration API. Lines use the form <code>subsys[:id] key=value ...</code>; keys you leave out keep their stored value.</p>
      <div class="ops-toolbar">
        <Select label="Subsystem" value={sub} onChange={setSub} options={subsystems} hint={help.data?.description} />
      </div>
      <Loading state={text}>
        {() => (
          <>
            <Field label={`${sub} configuration`} error={bad ? `Every line must start with ${sub} or ${sub}:<id>.` : null} hint={help.data ? `Keys: ${help.data.keysHelp.map((k) => k.key).join(", ")}` : undefined}>
              {(id) => <textarea id={id} class="mono" rows={8} spellcheck={false} value={draft} onInput={(e) => setDraft((e.target as HTMLTextAreaElement).value)} />}
            </Field>
            <div class="actions">
              <Button variant="primary" onClick={save} disabled={busy || !!bad || draft === text.data}>
                Save
              </Button>
              <Button onClick={() => setDraft(text.data ?? "")} disabled={draft === text.data}>
                Revert
              </Button>
            </div>
          </>
        )}
      </Loading>
    </Card>
  );
}

function SessionCard() {
  const s = useAsync(() => session.current());
  return (
    <Card title="Session">
      <Loading state={s}>
        {() => (
          <KeyValue
            rows={[
              ["User", s.data!.user],
              ["Access key", <span class="ops-mono">{s.data!.accessKey}</span>],
              ["Sign-in method", s.data!.provider],
              ["Expires", date(s.data!.expires)],
            ]}
          />
        )}
      </Loading>
    </Card>
  );
}

function AboutCard() {
  const c = useAsync(() => cluster.info());
  return (
    <Card title="About">
      <Loading state={c}>
        {() => (
          <KeyValue
            rows={[
              ["Server", c.data!.version],
              ["Mode", c.data!.mode],
              ["Region", c.data!.region],
              ["Protection", c.data!.protection],
              ["Uptime", duration(c.data!.uptimeSeconds)],
              ["Console", "zkfsm console"],
            ]}
          />
        )}
      </Loading>
    </Card>
  );
}

export function Settings() {
  return (
    <>
      <PageHeader title="Settings" />
      <div class="grid-2">
        <ThemeCard />
        <SessionCard />
      </div>
      <ConfigCard />
      <AboutCard />
    </>
  );
}
