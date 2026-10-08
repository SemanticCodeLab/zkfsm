// Shared UI primitives. Everything is keyboard reachable; dialogs trap focus and close on Escape.
import { ButtonHTMLAttributes, ComponentChildren, Fragment, InputHTMLAttributes } from "preact";
import { useCallback, useEffect, useRef, useState } from "preact/hooks";

export function cx(...c: (string | false | null | undefined)[]): string {
  return c.filter(Boolean).join(" ");
}

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "danger" | "ghost" | "default"; small?: boolean; type?: "button" | "submit" };
export function Button({ variant = "default", small, class: cls, type = "button", ...rest }: BtnProps) {
  return <button type={type} class={cx("btn", `btn-${variant}`, small && "btn-sm", cls as string)} {...rest} />;
}

export function PageHeader({ title, actions, children }: { title: ComponentChildren; actions?: ComponentChildren; children?: ComponentChildren }) {
  return (
    <header class="page-header">
      <div>
        <h1>{title}</h1>
        {children}
      </div>
      <div class="actions">{actions}</div>
    </header>
  );
}

export function Card({ title, actions, children, class: cls }: { title?: ComponentChildren; actions?: ComponentChildren; children: ComponentChildren; class?: string }) {
  return (
    <section class={cx("card", cls)}>
      {(title || actions) && (
        <div class="card-head">
          {title && <h2>{title}</h2>}
          <div class="actions">{actions}</div>
        </div>
      )}
      {children}
    </section>
  );
}

let fieldSeq = 0;
export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string | null; children: (id: string) => ComponentChildren }) {
  const id = useRef(`f${++fieldSeq}`).current;
  return (
    <div class={cx("field", error && "field-error")}>
      <label for={id}>{label}</label>
      {children(id)}
      {hint && !error && <div class="hint">{hint}</div>}
      {error && (
        <div class="error" role="alert">
          {error}
        </div>
      )}
    </div>
  );
}

export function TextInput({ label, value, onInput, hint, error, ...rest }: { label: string; value: string; onInput: (v: string) => void; hint?: string; error?: string | null } & Omit<InputHTMLAttributes<HTMLInputElement>, "onInput" | "value" | "label">) {
  return (
    <Field label={label} hint={hint} error={error}>
      {(id) => <input id={id} value={value} onInput={(e) => onInput((e.target as HTMLInputElement).value)} {...(rest as Record<string, unknown>)} />}
    </Field>
  );
}

export function Select({ label, value, onChange, options, hint }: { label: string; value: string; onChange: (v: string) => void; options: (string | [string, string])[]; hint?: string }) {
  return (
    <Field label={label} hint={hint}>
      {(id) => (
        <select id={id} value={value} onChange={(e) => onChange((e.target as HTMLSelectElement).value)}>
          {options.map((o) => {
            const [v, l] = Array.isArray(o) ? o : [o, o];
            return (
              <option key={v} value={v}>
                {l}
              </option>
            );
          })}
        </select>
      )}
    </Field>
  );
}

export function Toggle({ label, checked, onChange, disabled }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <label class="toggle">
      <input type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange((e.target as HTMLInputElement).checked)} />
      <span class="track" aria-hidden="true" />
      <span>{label}</span>
    </label>
  );
}

const focusable = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

export function Modal({ title, onClose, children, footer, wide }: { title: string; onClose: () => void; children: ComponentChildren; footer?: ComponentChildren; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current!;
    (el.querySelector("[autofocus]") as HTMLElement | null)?.focus() ?? (el.querySelector(focusable) as HTMLElement | null)?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      } else if (e.key === "Tab") {
        const f = Array.from(el.querySelectorAll<HTMLElement>(focusable));
        if (!f.length) return;
        const first = f[0];
        const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    el.addEventListener("keydown", key);
    return () => {
      el.removeEventListener("keydown", key);
      prev?.focus();
    };
  }, []);
  return (
    <div class="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div class={cx("modal", wide && "modal-wide")} role="dialog" aria-modal="true" aria-label={title} ref={ref}>
        <div class="modal-head">
          <h2>{title}</h2>
          <button type="button" class="icon-btn" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </div>
        <div class="modal-body">{children}</div>
        {footer && <div class="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Confirm({ title, message, confirmLabel = "Delete", onConfirm, onClose }: { title: string; message: ComponentChildren; confirmLabel?: string; onConfirm: () => Promise<void> | void; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="danger"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await onConfirm();
                onClose();
              } catch (e) {
                toastError(e);
              } finally {
                setBusy(false);
              }
            }}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <p>{message}</p>
    </Modal>
  );
}

// Toasts: a tiny global store.
export interface Toast {
  id: number;
  kind: "ok" | "error" | "info";
  text: string;
}
let toasts: Toast[] = [];
const listeners = new Set<(t: Toast[]) => void>();
let toastSeq = 0;
export function toast(text: string, kind: Toast["kind"] = "ok") {
  const t = { id: ++toastSeq, kind, text };
  toasts = [...toasts, t];
  listeners.forEach((l) => l(toasts));
  setTimeout(() => {
    toasts = toasts.filter((x) => x.id !== t.id);
    listeners.forEach((l) => l(toasts));
  }, kind === "error" ? 8000 : 4000);
}
export function toastError(e: unknown) {
  toast(e instanceof Error ? e.message : String(e), "error");
}
export function Toasts() {
  const [list, setList] = useState(toasts);
  useEffect(() => {
    listeners.add(setList);
    return () => void listeners.delete(setList);
  }, []);
  return (
    <div class="toasts" role="status" aria-live="polite">
      {list.map((t) => (
        <div key={t.id} class={cx("toast", `toast-${t.kind}`)}>
          {t.text}
        </div>
      ))}
    </div>
  );
}

/** Loads data; `reload` re-runs the loader. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [state, setState] = useState<{ data?: T; error?: Error; loading: boolean }>({ loading: true });
  const seq = useRef(0);
  const reload = useCallback(() => {
    const n = ++seq.current;
    setState((s) => ({ ...s, loading: true }));
    fn().then(
      (data) => n === seq.current && setState({ data, loading: false }),
      (error) => n === seq.current && setState({ error, loading: false }),
    );
  }, deps);
  useEffect(reload, [reload]);
  return { ...state, reload };
}

export function Loading({ state, children }: { state: { loading: boolean; error?: Error; data?: unknown }; children: () => ComponentChildren }) {
  if (state.error)
    return (
      <div class="notice notice-error" role="alert">
        {state.error.message}
      </div>
    );
  if (state.data === undefined) return <div class="loading">Loading…</div>;
  return <>{children()}</>;
}

export function Empty({ children }: { children: ComponentChildren }) {
  return <div class="empty">{children}</div>;
}

export function Badge({ kind = "default", children }: { kind?: "ok" | "warn" | "error" | "default"; children: ComponentChildren }) {
  return <span class={cx("badge", `badge-${kind}`)}>{children}</span>;
}

export function Tabs({ tabs, active, onChange }: { tabs: [string, string][]; active: string; onChange: (k: string) => void }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  return (
    <div class="tabs" role="tablist">
      {tabs.map(([k, label], i) => (
        <button
          key={k}
          ref={(el) => void (refs.current[i] = el)}
          role="tab"
          type="button"
          aria-selected={active === k}
          tabIndex={active === k ? 0 : -1}
          class={cx("tab", active === k && "active")}
          onClick={() => onChange(k)}
          onKeyDown={(e) => {
            const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
            if (!d) return;
            const n = (i + d + tabs.length) % tabs.length;
            onChange(tabs[n][0]);
            refs.current[n]?.focus();
          }}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

/** JSON editor: textarea with validation, format button and line count. */
export function JsonEditor({ label, value, onChange, rows = 16 }: { label: string; value: string; onChange: (v: string) => void; rows?: number }) {
  let err: string | null = null;
  try {
    if (value.trim()) JSON.parse(value);
  } catch (e) {
    err = (e as Error).message;
  }
  return (
    <Field label={label} error={err}>
      {(id) => (
        <div class="json-editor">
          <textarea
            id={id}
            class="mono"
            rows={rows}
            spellcheck={false}
            value={value}
            onInput={(e) => onChange((e.target as HTMLTextAreaElement).value)}
            onKeyDown={(e) => {
              if (e.key === "Tab" && !e.shiftKey && !e.ctrlKey) {
                const t = e.target as HTMLTextAreaElement;
                if (t.selectionStart === t.selectionEnd && e.altKey) return;
              }
            }}
          />
          <div class="json-tools">
            <Button
              small
              disabled={!!err}
              onClick={() => {
                try {
                  onChange(JSON.stringify(JSON.parse(value), null, 2));
                } catch {
                  /* invalid */
                }
              }}
            >
              Format
            </Button>
            <span class="hint">{value.split("\n").length} lines</span>
          </div>
        </div>
      )}
    </Field>
  );
}

export function Progress({ value, label }: { value: number; label?: string }) {
  return (
    <div class="progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(value)} aria-label={label}>
      <div class="bar" style={{ width: `${value}%` }} />
    </div>
  );
}

export function KeyValue({ rows }: { rows: [string, ComponentChildren][] }) {
  return (
    <dl class="kv">
      {rows.map(([k, v]) => (
        <Fragment key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </Fragment>
      ))}
    </dl>
  );
}
