import { useEffect, useMemo, useState } from "preact/hooks";
import { cluster, raw } from "../lib/api";
import { date } from "../lib/format";
import { href, navigate, useRoute } from "../lib/router";
import { Badge, Button, Card, Empty, KeyValue, Loading, PageHeader, Tabs, TextInput, toast, toastError, useAsync } from "../components/ui";
import { ClusterInfoX, Unavailable } from "./ops/common";
import { BgHealCard, ScannerCard } from "./ops/HealPanels";
import { LogsTab, TraceTab } from "./ops/LiveTabs";
import { PoolsTab } from "./ops/PoolsTab";
import { MetricCharts, useLiveMetrics } from "./ops/metrics";
import { labelText, parseFamilies } from "./ops/prom";
import "./ops/ops.css";

const tabs: [string, string][] = [
  ["metrics", "Metrics"],
  ["heal", "Heal"],
  ["pools", "Pools"],
  ["trace", "Trace"],
  ["logs", "Logs"],
  ["audit", "Audit"],
];

function MetricsTab() {
  const live = useLiveMetrics();
  const [filter, setFilter] = useState("");
  const fams = useMemo(() => parseFamilies(live.text), [live.text]);
  const f = filter.trim().toLowerCase();
  const rows = fams.flatMap((fam) => fam.samples.map((s) => ({ fam, s }))).filter(({ fam, s }) => !f || s.name.toLowerCase().includes(f) || fam.help.toLowerCase().includes(f) || labelText(s.labels).toLowerCase().includes(f));
  return (
    <>
      <Card title="Live charts" actions={<Button small onClick={() => live.setPaused(!live.paused)} aria-pressed={live.paused}>{live.paused ? "Resume" : "Pause"}</Button>}>
        <p class="hint">Sampled every 5 seconds; the last 5 minutes are kept.</p>
        <MetricCharts live={live} />
      </Card>
      <Card title="All metrics" actions={<a class="btn btn-sm" href="/api/v1/metrics" target="_blank" rel="noopener">Raw text</a>}>
        <div class="ops-toolbar">
          <TextInput label="Filter" type="search" value={filter} onInput={setFilter} placeholder="name, label or help text" />
          <span class="hint" aria-live="polite">
            {rows.length} sample{rows.length === 1 ? "" : "s"}
          </span>
        </div>
        {live.latest === null ? (
          <div class="loading">Loading…</div>
        ) : rows.length ? (
          <div class="ops-scroll">
            <table>
              <thead>
                <tr>
                  <th scope="col">Metric</th>
                  <th scope="col">Type</th>
                  <th scope="col" class="num">
                    Value
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ fam, s }, i) => (
                  <tr key={i}>
                    <td class="ops-mono" title={fam.help || undefined}>
                      {s.name}
                      {labelText(s.labels)}
                    </td>
                    <td>{fam.type}</td>
                    <td class="ops-num">{Number.isInteger(s.value) ? s.value.toLocaleString() : s.value.toPrecision(6)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>No metric matches the filter.</Empty>
        )}
      </Card>
    </>
  );
}

function HealTab() {
  const info = useAsync(() => cluster.info() as unknown as Promise<ClusterInfoX>);
  const [busy, setBusy] = useState(false);
  const running = info.data?.heal?.running;
  useEffect(() => {
    if (!running) return;
    const id = setInterval(info.reload, 3000);
    return () => clearInterval(id);
  }, [running]);
  const start = async () => {
    setBusy(true);
    try {
      await raw("/api/v1/heal", { method: "POST" });
      toast("Heal pass started");
      setTimeout(info.reload, 800);
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Loading state={info}>
      {() => {
        const c = info.data!;
        const h = c.heal;
        if (!h || c.features?.heal === false) return <Unavailable title="Heal is not available on this server." />;
        return (
          <>
          <Card
            title="Heal status"
            actions={
              <>
                <Button onClick={info.reload}>Refresh</Button>
                <Button variant="primary" onClick={start} disabled={busy || h.running}>
                  {h.running ? "Heal running…" : "Start heal"}
                </Button>
              </>
            }
          >
            <KeyValue
              rows={[
                ["State", <Badge kind={h.running ? "warn" : "ok"}>{h.running ? "running" : "idle"}</Badge>],
                ["Last scan", date(h.lastScan)],
                ["Passes", (h.passes ?? 0).toLocaleString()],
                ["Objects scanned", h.scanned.toLocaleString()],
                ["Healed", h.healed.toLocaleString()],
                ["Failed", h.failed ? <Badge kind="error">{h.failed}</Badge> : "0"],
                ["Lost", h.lost ? <Badge kind="error">{h.lost}</Badge> : String(h.lost ?? 0)],
              ]}
            />
            <p class="hint">A heal pass scans every object and rebuilds missing or corrupt shards from parity. Background passes also run on a schedule.</p>
          </Card>
          <BgHealCard />
          <ScannerCard />
          </>
        );
      }}
    </Loading>
  );
}

function AuditTab() {
  return (
    <Card title="Audit log">
      <p>Audit records are delivered to audit targets (webhook, Kafka, NATS and others) rather than stored by the server.</p>
      <p>
        <a class="btn btn-primary" href={href("/events", { tab: "audit" })}>
          Manage audit targets
        </a>
      </p>
    </Card>
  );
}

export function Monitoring() {
  const route = useRoute();
  const tab = tabs.some(([k]) => k === route.params.get("tab")) ? route.params.get("tab")! : "metrics";
  return (
    <>
      <PageHeader title="Monitoring" />
      <Tabs tabs={tabs} active={tab} onChange={(k) => navigate("/monitoring", { tab: k })} />
      <div role="tabpanel" aria-label={tabs.find(([k]) => k === tab)![1]}>
        {tab === "metrics" && <MetricsTab />}
        {tab === "heal" && <HealTab />}
        {tab === "pools" && <PoolsTab />}
        {tab === "trace" && <TraceTab />}
        {tab === "logs" && <LogsTab />}
        {tab === "audit" && <AuditTab />}
      </div>
    </>
  );
}
