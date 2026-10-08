// Shared bits for the bucket pages: optional-config loading, error notes, small editors.
import { ComponentChildren } from "preact";
import { useState } from "preact/hooks";
import { ApiError } from "../../lib/api";
import { Button, Select, TextInput } from "../../components/ui";

/** True when the server answered "this subresource is not implemented". */
export function isUnsupported(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 501 || e.code === "NotImplemented");
}

/** True for the "no such configuration" family of 404s. */
export function isMissing(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 404 && e.code !== "NoSuchBucket" || /^NoSuch.*Configuration|NotFound(Error)?$|^XMinioAdminNoSuch/.test(e.code));
}

/** Runs `fn`; a missing configuration yields null instead of an error. */
export async function optional<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch (e) {
    if (isMissing(e)) return null;
    throw e;
  }
}

export function ErrorNote({ error }: { error: Error }) {
  if (isUnsupported(error)) return <div class="notice notice-warn">Not supported by this server.</div>;
  return (
    <div class="notice notice-error" role="alert">
      {error.message}
    </div>
  );
}

/** Wraps an async loader state: error note, loading line, or content. */
export function Section({ state, children }: { state: { loading: boolean; error?: Error; data?: unknown }; children: () => ComponentChildren }) {
  if (state.error) return <ErrorNote error={state.error} />;
  if (state.data === undefined) return <div class="loading">Loading…</div>;
  return <>{children()}</>;
}

const UNITS: [string, number][] = [
  ["MiB", 1024 ** 2],
  ["GiB", 1024 ** 3],
  ["TiB", 1024 ** 4],
];

export function splitBytes(n: number): { value: string; unit: string } {
  if (!n) return { value: "", unit: "GiB" };
  for (let i = UNITS.length - 1; i >= 0; i--) if (n % UNITS[i][1] === 0) return { value: String(n / UNITS[i][1]), unit: UNITS[i][0] };
  return { value: (n / UNITS[0][1]).toFixed(2), unit: "MiB" };
}

export function joinBytes(value: string, unit: string): number {
  const v = Number(value);
  const m = UNITS.find(([u]) => u === unit)?.[1] ?? 1;
  return isFinite(v) && v > 0 ? Math.round(v * m) : 0;
}

export function QuotaInput({ value, unit, onValue, onUnit, label = "Quota" }: { value: string; unit: string; onValue: (v: string) => void; onUnit: (u: string) => void; label?: string }) {
  return (
    <div class="row">
      <TextInput label={label} type="number" min="0" value={value} onInput={onValue} hint="Leave empty for no quota." />
      <Select label="Unit" value={unit} onChange={onUnit} options={UNITS.map(([u]) => u)} />
    </div>
  );
}

/** Editable list of key/value pairs. */
export function PairsEditor({ pairs, onChange, keyLabel = "Key", valueLabel = "Value", addLabel = "Add tag" }: { pairs: [string, string][]; onChange: (p: [string, string][]) => void; keyLabel?: string; valueLabel?: string; addLabel?: string }) {
  const set = (i: number, j: 0 | 1, v: string) => onChange(pairs.map((p, k) => (k === i ? ((j === 0 ? [v, p[1]] : [p[0], v]) as [string, string]) : p)));
  return (
    <div class="bk-pairs">
      {pairs.map((p, i) => (
        <div class="row" key={i}>
          <TextInput label={`${keyLabel} ${i + 1}`} value={p[0]} onInput={(v) => set(i, 0, v)} />
          <TextInput label={`${valueLabel} ${i + 1}`} value={p[1]} onInput={(v) => set(i, 1, v)} />
          <Button small variant="ghost" aria-label={`Remove ${keyLabel.toLowerCase()} ${i + 1}`} onClick={() => onChange(pairs.filter((_, k) => k !== i))}>
            Remove
          </Button>
        </div>
      ))}
      <Button small onClick={() => onChange([...pairs, ["", ""]])}>
        {addLabel}
      </Button>
    </div>
  );
}

/** Comma/newline separated list input. */
export function ListInput({ label, value, onChange, hint }: { label: string; value: string[]; onChange: (v: string[]) => void; hint?: string }) {
  const [raw, setRaw] = useState(value.join(", "));
  return (
    <TextInput
      label={label}
      value={raw}
      hint={hint}
      onInput={(v) => {
        setRaw(v);
        onChange(v.split(/[,\n]/).map((s) => s.trim()).filter(Boolean));
      }}
    />
  );
}

export function numOrUndef(s: string): number | undefined {
  if (s.trim() === "") return undefined;
  const n = Number(s);
  return isFinite(n) && n >= 0 ? Math.floor(n) : undefined;
}

export const strOf = (n: number | undefined) => (n === undefined ? "" : String(n));
