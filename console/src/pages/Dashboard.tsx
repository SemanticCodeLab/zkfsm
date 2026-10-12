import { cluster } from "../lib/api";
import { bytes, duration, pct } from "../lib/format";
import { href } from "../lib/router";
import { Badge, Button, Card, Empty, Loading, PageHeader, Progress, useAsync } from "../components/ui";
import { ClusterInfoX, driveKind } from "./ops/common";
import { MetricCharts, useLiveMetrics } from "./ops/metrics";
import "./ops/ops.css";

function Tile({ label, value, sub, bar }: { label: string; value: string | number; sub?: string; bar?: number }) {
  return (
    <section class="card stat" aria-label={label}>
      <div class="label">{label}</div>
      <div class="value">{value}</div>
      {sub && <div class="sub">{sub}</div>}
      {bar !== undefined && <Progress value={bar} label={`${label} ${Math.round(bar)}%`} />}
    </section>
  );
}

export function UsedBar({ used, total }: { used: number; total: number }) {
  const p = pct(used, total);
  return (
    <div class="ops-cell-bar">
      <Progress value={p} label={`${Math.round(p)}% used`} />
      <span>
        {bytes(used)} / {bytes(total)}
      </span>
    </div>
  );
}

export function Dashboard() {
  const info = useAsync(() => cluster.info() as unknown as Promise<ClusterInfoX>);
  const live = useLiveMetrics();
  return (
    <>
      <PageHeader
        title="Dashboard"
        actions={
          <Button onClick={info.reload} disabled={info.loading}>
            Refresh
          </Button>
        }
      />
      <Loading state={info}>
        {() => {
          const c = info.data!;
          const offline = c.drives.filter((d) => d.state !== "ok");
          const cap = c.capacity;
          return (
            <>
              {offline.length > 0 && (
                <div class="notice notice-warn" role="alert">
                  <strong>
                    {offline.length} of {c.drives.length} drive{c.drives.length === 1 ? "" : "s"} not healthy.
                  </strong>{" "}
                  Data stays available while each erasure set keeps enough drives online. <a href={href("/monitoring", { tab: "heal" })}>Open heal status</a>
                </div>
              )}
              <div class="ops-tiles">
                <Tile label="Capacity" value={`${Math.round(pct(cap.usedBytes, cap.totalBytes))}%`} sub={`${bytes(cap.usedBytes)} used of ${bytes(cap.totalBytes)}, ${bytes(cap.freeBytes)} free`} bar={pct(cap.usedBytes, cap.totalBytes)} />
                <Tile label="Buckets" value={c.usage.buckets.toLocaleString()} />
                <Tile label="Objects" value={c.usage.objects.toLocaleString()} />
                <Tile label="Data stored" value={bytes(c.usage.bytes)} />
                <Tile label="Uptime" value={duration(c.uptimeSeconds)} />
                <Tile label="Protection" value={c.protection} sub={`${c.mode} mode, region ${c.region}`} />
                <Tile label="Version" value={c.version} />
              </div>
              <Card title="Live metrics" actions={<Button small onClick={() => live.setPaused(!live.paused)} aria-pressed={live.paused}>{live.paused ? "Resume" : "Pause"}</Button>}>
                <MetricCharts live={live} />
              </Card>
              {c.mode === "cluster" && (
                <Card title={`Nodes (${c.nodes.length})`}>
                  {c.nodes.length ? (
                    <table>
                      <thead>
                        <tr>
                          <th scope="col">Address</th>
                          <th scope="col">State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {c.nodes.map((n) => (
                          <tr key={n.address}>
                            <td>{n.address}</td>
                            <td>
                              <Badge kind={n.state === "online" || n.state === "ok" ? "ok" : "error"}>{n.state}</Badge>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <Empty>No nodes reported.</Empty>
                  )}
                </Card>
              )}
              <div class="grid-2">
                <Card title="Pools">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Pool</th>
                        <th scope="col" class="num">Drives</th>
                        <th scope="col" class="num">Online</th>
                        <th scope="col" class="num">Set size</th>
                        <th scope="col">Health</th>
                      </tr>
                    </thead>
                    <tbody>
                      {c.pools.map((p) => (
                        <tr key={p.index}>
                          <td>Pool {p.index}</td>
                          <td class="ops-num">{p.drives}</td>
                          <td class="ops-num">{p.online}</td>
                          <td class="ops-num">{p.setSize}</td>
                          <td>
                            <Badge kind={p.online === p.drives ? "ok" : p.online === 0 ? "error" : "warn"}>{p.online === p.drives ? "healthy" : p.online === 0 ? "offline" : "degraded"}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Card>
                <Card title="Heal">
                  {c.heal ? (
                    <p>
                      <Badge kind={c.heal.running ? "warn" : "ok"}>{c.heal.running ? "running" : "idle"}</Badge> {c.heal.scanned.toLocaleString()} scanned, {c.heal.healed} healed, {c.heal.failed} failed. <a href={href("/monitoring", { tab: "heal" })}>Details</a>
                    </p>
                  ) : (
                    <Empty>Heal status is not reported by this server.</Empty>
                  )}
                </Card>
              </div>
              <Card title={`Drives (${c.drives.length})`}>
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Path</th>
                      <th scope="col">Pool / set</th>
                      <th scope="col">State</th>
                      <th scope="col">Usage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {c.drives.map((d) => (
                      <tr key={d.path}>
                        <td class="ops-mono">{d.path}</td>
                        <td>
                          {d.pool}
                          {d.set !== undefined && ` / ${d.set}`}
                        </td>
                        <td>
                          <Badge kind={driveKind(d.state)}>{d.state}</Badge>
                        </td>
                        <td>
                          <UsedBar used={d.totalBytes - d.freeBytes} total={d.totalBytes} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
            </>
          );
        }}
      </Loading>
    </>
  );
}
