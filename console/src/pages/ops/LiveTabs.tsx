// Live trace and server log views, streamed through the console proxy.
import { useEffect, useRef, useState } from "preact/hooks";
import { Badge, Button, Card, Empty, Select, TextInput, Toggle } from "../../components/ui";
import { errText, isUnavailable, Unavailable } from "./common";
import { atLeast, follow, LOG_LEVELS, LogLevel, LogRow, parseLog, parseTrace, Ring, TRACE_TYPES, TraceFilter, traceQuery, TraceRow } from "./live";

const CAP = 1000;
type Conn = "connecting" | "live" | "paused" | "ended" | "error" | "unavailable";

/** Follows `op` while not paused; restarts when `key` changes. Rows go into a bounded ring. */
function useLive<T>(op: string, query: Record<string, string>, key: string, parse: (l: string) => T | null, paused: boolean) {
  const ring = useRef(new Ring<T>(CAP));
  const [rows, setRows] = useState<T[]>([]);
  const [conn, setConn] = useState<Conn>("connecting");
  const [err, setErr] = useState("");
  useEffect(() => {
    if (paused) {
      setConn("paused");
      return;
    }
    const ctl = new AbortController();
    let pending = false;
    const flush = () => {
      pending = false;
      setRows(ring.current.toArray());
    };
    setConn("connecting");
    // Paint the "live" state once the response head has arrived.
    follow(
      op,
      query,
      (lines) => {
        setConn("live");
        const got = lines.map(parse).filter((x): x is T => x !== null);
        if (!got.length) return;
        ring.current.push(...got);
        if (!pending) {
          pending = true;
          requestAnimationFrame(flush);
        }
      },
      ctl.signal,
    ).then(
      () => !ctl.signal.aborted && setConn("ended"),
      (e) => {
        if (ctl.signal.aborted) return;
        setErr(errText(e));
        setConn(isUnavailable(e) ? "unavailable" : "error");
      },
    );
    const t = setTimeout(() => setConn((c) => (c === "connecting" ? "live" : c)), 1500);
    return () => {
      clearTimeout(t);
      ctl.abort();
    };
  }, [op, key, paused]);
  const clear = () => {
    ring.current.clear();
    setRows([]);
  };
  return { rows, conn, err, clear, dropped: ring.current.dropped };
}

function ConnBadge({ conn }: { conn: Conn }) {
  const kind = conn === "live" ? "ok" : conn === "error" ? "error" : conn === "connecting" ? "default" : "warn";
  return (
    <span aria-live="polite">
      <Badge kind={kind}>{conn}</Badge>
    </span>
  );
}

function time(s: string): string {
  const d = new Date(s);
  return isNaN(d.getTime()) ? s : d.toLocaleTimeString(undefined, { hour12: false }) + `.${String(d.getMilliseconds()).padStart(3, "0")}`;
}

export function TraceTab() {
  const [f, setF] = useState<TraceFilter>({ types: ["s3"], errorsOnly: false, thresholdMs: 0 });
  const [thr, setThr] = useState("");
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState("");
  const q = traceQuery(f);
  const live = useLive<TraceRow>("/trace", q, JSON.stringify(q), parseTrace, paused);
  const toggleType = (t: string, on: boolean) => setF({ ...f, types: on ? [...f.types, t] : f.types.filter((x) => x !== t) });
  const s = search.trim().toLowerCase();
  const rows = live.rows.filter((r) => !s || r.api.toLowerCase().includes(s) || r.path.toLowerCase().includes(s));
  if (live.conn === "unavailable") return <Unavailable title="Request trace is not available on this server.">{live.err}</Unavailable>;
  return (
    <Card
      title="Live trace"
      actions={
        <>
          <ConnBadge conn={live.conn} />
          <Button small onClick={() => setPaused(!paused)} aria-pressed={paused}>
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button small onClick={live.clear}>
            Clear
          </Button>
        </>
      }
    >
      <fieldset class="ops-types">
        <legend>Call types</legend>
        {TRACE_TYPES.map(([k, label]) => (
          <label key={k}>
            <input type="checkbox" checked={f.types.includes(k)} onChange={(e) => toggleType(k, (e.target as HTMLInputElement).checked)} />
            {label}
          </label>
        ))}
      </fieldset>
      <div class="ops-toolbar">
        <Toggle label="Errors only" checked={f.errorsOnly} onChange={(v) => setF({ ...f, errorsOnly: v })} />
        <TextInput
          label="Minimum duration (ms)"
          type="number"
          min={0}
          value={thr}
          onInput={setThr}
          onBlur={() => setF({ ...f, thresholdMs: Math.max(0, Number(thr) || 0) })}
          onKeyDown={(e) => e.key === "Enter" && setF({ ...f, thresholdMs: Math.max(0, Number(thr) || 0) })}
        />
        <TextInput label="Search" type="search" value={search} onInput={setSearch} placeholder="API or path" />
        <span class="hint">
          {rows.length} shown, last {CAP} kept{live.dropped ? `, ${live.dropped} older dropped` : ""}
        </span>
      </div>
      {live.conn === "error" && (
        <div class="notice notice-error" role="alert">
          {live.err}
        </div>
      )}
      {rows.length ? (
        <div class="ops-scroll ops-live">
          <table aria-label="Trace entries">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Type</th>
                <th scope="col">API</th>
                <th scope="col">Path</th>
                <th scope="col" class="num">Status</th>
                <th scope="col" class="num">Duration</th>
                <th scope="col">Node</th>
              </tr>
            </thead>
            <tbody>
              {rows
                .slice()
                .reverse()
                .map((r, i) => (
                  <tr key={rows.length - i} class={r.error || r.status >= 400 ? "ops-row-err" : undefined}>
                    <td class="ops-mono">{time(r.time)}</td>
                    <td>{r.type}</td>
                    <td class="ops-mono">{r.api}</td>
                    <td class="ops-mono" title={r.error || undefined}>
                      {r.method && `${r.method} `}
                      {r.path}
                    </td>
                    <td class="ops-num">{r.status ? <Badge kind={r.status >= 500 ? "error" : r.status >= 400 ? "warn" : "ok"}>{r.status}</Badge> : r.error ? <Badge kind="error">error</Badge> : "-"}</td>
                    <td class="ops-num">{r.durMs < 1 ? `${(r.durMs * 1000).toFixed(0)} µs` : `${r.durMs.toFixed(1)} ms`}</td>
                    <td class="ops-mono">{r.node}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>{paused ? "Paused." : "Waiting for requests…"}</Empty>
      )}
    </Card>
  );
}

export function LogsTab() {
  const [level, setLevel] = useState<LogLevel>("DEBUG");
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState("");
  const live = useLive<LogRow>("/log", { limit: "200" }, "log", parseLog, paused);
  const s = search.trim().toLowerCase();
  const rows = live.rows.filter((r) => atLeast(r.level, level) && (!s || r.message.toLowerCase().includes(s)));
  if (live.conn === "unavailable") return <Unavailable title="Server log is not available on this server.">{live.err}</Unavailable>;
  return (
    <Card
      title="Live server log"
      actions={
        <>
          <ConnBadge conn={live.conn} />
          <Button small onClick={() => setPaused(!paused)} aria-pressed={paused}>
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button small onClick={live.clear}>
            Clear
          </Button>
        </>
      }
    >
      <div class="ops-toolbar">
        <Select label="Minimum level" value={level} onChange={(v) => setLevel(v as LogLevel)} options={LOG_LEVELS.map((l) => [l, l.charAt(0) + l.slice(1).toLowerCase()] as [string, string])} />
        <TextInput label="Search" type="search" value={search} onInput={setSearch} placeholder="message text" />
        <span class="hint">
          {rows.length} shown, last {CAP} kept
        </span>
      </div>
      {live.conn === "error" && (
        <div class="notice notice-error" role="alert">
          {live.err}
        </div>
      )}
      {rows.length ? (
        <div class="ops-scroll ops-live">
          <table aria-label="Log entries">
            <thead>
              <tr>
                <th scope="col">Time</th>
                <th scope="col">Level</th>
                <th scope="col">Node</th>
                <th scope="col">Message</th>
              </tr>
            </thead>
            <tbody>
              {rows
                .slice()
                .reverse()
                .map((r, i) => (
                  <tr key={rows.length - i}>
                    <td class="ops-mono">{time(r.time)}</td>
                    <td>
                      <Badge kind={r.level === "ERROR" ? "error" : r.level === "WARNING" ? "warn" : "default"}>{r.level}</Badge>
                    </td>
                    <td class="ops-mono">{r.node}</td>
                    <td class="ops-mono">{r.message}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty>{paused ? "Paused." : "Waiting for log entries…"}</Empty>
      )}
    </Card>
  );
}
