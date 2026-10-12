// Shared IAM widgets: checkbox pickers, search box, credential reveal.
import { useState } from "preact/hooks";
import { Button, Modal, toast } from "../../components/ui";

export function SearchBox({ value, onInput, label }: { value: string; onInput: (v: string) => void; label: string }) {
  return <input type="search" class="iam-search" placeholder={label} aria-label={label} value={value} onInput={(e) => onInput((e.target as HTMLInputElement).value)} />;
}

/** Multi-select as a scrollable checkbox list; each box is labelled with its name. */
export function CheckList({ legend, options, selected, onChange, empty = "None available." }: { legend: string; options: string[]; selected: string[]; onChange: (v: string[]) => void; empty?: string }) {
  const [q, setQ] = useState("");
  const shown = options.filter((o) => o.toLowerCase().includes(q.toLowerCase()));
  return (
    <fieldset class="iam-checklist">
      <legend>{legend}</legend>
      {options.length > 8 && <SearchBox value={q} onInput={setQ} label={`Filter ${legend.toLowerCase()}`} />}
      {options.length === 0 && <div class="hint">{empty}</div>}
      <div class="iam-checks">
        {shown.map((o) => (
          <label key={o} class="iam-check">
            <input
              type="checkbox"
              checked={selected.includes(o)}
              onChange={(e) => onChange((e.target as HTMLInputElement).checked ? [...selected, o] : selected.filter((x) => x !== o))}
            />
            <span>{o}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

export function copy(text: string) {
  navigator.clipboard?.writeText(text).then(
    () => toast("Copied to clipboard", "info"),
    () => toast("Copy failed; select the text instead", "error"),
  );
}

/** Shows freshly created credentials once, with copy and JSON download. */
export function CredentialsModal({ creds, onClose }: { creds: { accessKey: string; secretKey: string; expiration?: string | null }; onClose: () => void }) {
  const json = JSON.stringify({ url: `${location.protocol}//${location.hostname}`, accessKey: creds.accessKey, secretKey: creds.secretKey, api: "s3v4", path: "auto" }, null, 2);
  const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
  return (
    <Modal
      title="New access key"
      onClose={() => {
        URL.revokeObjectURL(url);
        onClose();
      }}
      footer={
        <>
          <a class="btn btn-default" href={url} download={`credentials-${creds.accessKey}.json`}>
            Download JSON
          </a>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      <div class="notice notice-warn">The secret key is shown only now. Store it safely.</div>
      <dl class="kv">
        <dt>Access key</dt>
        <dd>
          <code data-testid="new-access-key">{creds.accessKey}</code>{" "}
          <Button small onClick={() => copy(creds.accessKey)}>
            Copy
          </Button>
        </dd>
        <dt>Secret key</dt>
        <dd>
          <code data-testid="new-secret-key">{creds.secretKey}</code>{" "}
          <Button small onClick={() => copy(creds.secretKey)}>
            Copy
          </Button>
        </dd>
        {creds.expiration && (
          <>
            <dt>Expires</dt>
            <dd>{new Date(creds.expiration).toLocaleString()}</dd>
          </>
        )}
      </dl>
    </Modal>
  );
}

export function StatusBadge({ on }: { on: boolean }) {
  return <span class={`badge ${on ? "badge-ok" : "badge-warn"}`}>{on ? "enabled" : "disabled"}</span>;
}
