// Pools: per-pool usage and state, decommission start/cancel, rebalance start/stop.
import { useEffect, useState } from "preact/hooks";
import { cluster } from "../../lib/api";
import { bytes, date } from "../../lib/format";
import { Badge, Button, Card, Confirm, KeyValue, Loading, Progress, toast, useAsync } from "../../components/ui";
import { ClusterInfoX, isUnavailable, Unavailable } from "./common";
import { drainProgress, pools, PoolState, poolState, PoolStatus, poolUsed, rebalanceRunning, rebalanceState, RebalanceStatus } from "./pools";

const stateKind: Record<PoolState, "ok" | "warn" | "error" | "default"> = { active: "ok", draining: "warn", decommissioned: "default", failed: "error", canceled: "warn" };

function pct(x: number): string {
  return `${(x * 100).toFixed(1)}%`;
}

export function PoolsTab() {
  const info = useAsync(() => cluster.info() as unknown as Promise<ClusterInfoX>);
  const list = useAsync(() => pools.list());
  const rebal = useAsync(() => pools.rebalanceStatus());
  const [confirm, setConfirm] = useState<{ kind: "decom" | "cancel" | "rebalance-stop"; pool?: PoolStatus } | null>(null);
  const [busy, setBusy] = useState(false);
  const draining = list.data?.some((p) => poolState(p) === "draining") ?? false;
  const running = rebalanceRunning(rebal.data ?? null);
  useEffect(() => {
    if (!draining && !running) return;
    const id = setInterval(() => {
      list.reload();
      rebal.reload();
    }, 2000);
    return () => clearInterval(id);
  }, [draining, running]);
  const refresh = () => {
    list.reload();
    rebal.reload();
    info.reload();
  };
  const startRebalance = async () => {
    setBusy(true);
    try {
      const r = await pools.rebalanceStart();
      toast(`Rebalance started (${r.id.slice(0, 8)})`);
      refresh();
    } catch (e) {
      toast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };

  if (list.error && isUnavailable(list.error))
    return <Unavailable title="Pool management is not available on this server.">Decommission and rebalance need a server started with pools (one or more --data pool arguments per node).</Unavailable>;
  const active = list.data?.filter((p) => poolState(p) !== "decommissioned").length ?? 0;
  return (
    <>
      <Loading state={list}>
        {() => (
          <Card title="Pools" actions={<Button onClick={refresh}>Refresh</Button>}>
            <table>
              <thead>
                <tr>
                  <th scope="col">Pool</th>
                  <th scope="col" class="num">Drives</th>
                  <th scope="col">Usage</th>
                  <th scope="col">State</th>
                  <th scope="col">Decommission</th>
                  <th scope="col">
                    <span class="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {list.data!.map((p) => {
                  const st = poolState(p);
                  const d = p.decommissionInfo;
                  const ip = info.data?.pools.find((x) => x.index === p.id);
                  return (
                    <tr key={p.id} data-pool={p.id}>
                      <td>
                        <div>Pool {p.id + 1}</div>
                        <div class="hint ops-mono ops-cmdline" title={p.cmdline}>
                          {p.cmdline}
                        </div>
                      </td>
                      <td class="ops-num">{ip ? `${ip.online}/${ip.drives}` : "-"}</td>
                      <td class="ops-usage">
                        <Progress value={poolUsed(p) * 100} label={`Pool ${p.id + 1} usage`} />
                        <span class="hint">
                          {bytes(d.totalSize - d.currentSize)} of {bytes(d.totalSize)} ({pct(poolUsed(p))})
                        </span>
                      </td>
                      <td>
                        <Badge kind={stateKind[st]}>{st}</Badge>
                      </td>
                      <td>
                        {st === "active" ? (
                          "-"
                        ) : (
                          <div class="ops-decom">
                            {st === "draining" && <Progress value={drainProgress(p) * 100} label={`Pool ${p.id + 1} drain progress`} />}
                            <span class="hint">
                              {d.objectsDecommissioned.toLocaleString()} objects, {bytes(d.bytesDecommissioned)} moved
                              {d.objectsDecommissionedFailed ? `, ${d.objectsDecommissionedFailed} failed` : ""}; started {date(d.startTime)}
                            </span>
                          </div>
                        )}
                      </td>
                      <td class="actions">
                        {st === "draining" ? (
                          <Button small onClick={() => setConfirm({ kind: "cancel", pool: p })}>
                            Cancel decommission
                          </Button>
                        ) : st !== "decommissioned" ? (
                          <Button small variant="danger" disabled={draining || running || active < 2} onClick={() => setConfirm({ kind: "decom", pool: p })}>
                            Decommission
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <p class="hint">Decommissioning moves every object off a pool so it can be removed from the server command line. Only one pool drains at a time, and not during a rebalance.</p>
          </Card>
        )}
      </Loading>
      <Card
        title="Rebalance"
        actions={
          running ? (
            <Button variant="danger" onClick={() => setConfirm({ kind: "rebalance-stop" })}>
              Stop rebalance
            </Button>
          ) : (
            <Button variant="primary" disabled={busy || draining || active < 2} onClick={startRebalance}>
              Start rebalance
            </Button>
          )
        }
      >
        <Loading state={rebal}>{() => <RebalanceView r={rebal.data ?? null} />}</Loading>
      </Card>
      {confirm?.kind === "decom" && (
        <Confirm
          title={`Decommission pool ${confirm.pool!.id + 1}?`}
          message={`Every object on pool ${confirm.pool!.id + 1} is moved to the other pools. Writes go to the other pools from now on. The drain can be cancelled while it runs.`}
          confirmLabel="Decommission"
          onConfirm={async () => {
            await pools.decommission(confirm.pool!.cmdline);
            toast(`Decommission of pool ${confirm.pool!.id + 1} started`);
            refresh();
          }}
          onClose={() => setConfirm(null)}
        />
      )}
      {confirm?.kind === "cancel" && (
        <Confirm
          title={`Cancel decommission of pool ${confirm.pool!.id + 1}?`}
          message="Objects already moved stay where they are; the pool takes new writes again."
          confirmLabel="Cancel decommission"
          onConfirm={async () => {
            await pools.cancel(confirm.pool!.cmdline);
            toast("Decommission cancelled");
            refresh();
          }}
          onClose={() => setConfirm(null)}
        />
      )}
      {confirm?.kind === "rebalance-stop" && (
        <Confirm
          title="Stop the rebalance?"
          message="Objects already moved stay where they are. A new rebalance can be started later."
          confirmLabel="Stop rebalance"
          onConfirm={async () => {
            await pools.rebalanceStop();
            toast("Rebalance stopped");
            refresh();
          }}
          onClose={() => setConfirm(null)}
        />
      )}
    </>
  );
}

function RebalanceView({ r }: { r: RebalanceStatus | null }) {
  const st = rebalanceState(r);
  if (!r)
    return (
      <>
        <KeyValue rows={[["State", <Badge>not started</Badge>]]} />
        <p class="hint">A rebalance moves objects from fuller pools to emptier ones, for example after adding a pool.</p>
      </>
    );
  return (
    <>
      <KeyValue
        rows={[
          ["State", <Badge kind={st === "running" ? "warn" : st === "failed" ? "error" : "ok"}>{st}</Badge>],
          ["ID", <span class="ops-mono">{r.ID}</span>],
          ["Stopped at", date(r.stoppedAt.startsWith("0001") ? null : r.stoppedAt)],
        ]}
      />
      <table>
        <thead>
          <tr>
            <th scope="col">Pool</th>
            <th scope="col">Used</th>
            <th scope="col">Status</th>
            <th scope="col" class="num">Objects moved</th>
            <th scope="col" class="num">Bytes moved</th>
            <th scope="col" class="num">Elapsed</th>
          </tr>
        </thead>
        <tbody>
          {r.pools.map((p) => (
            <tr key={p.id}>
              <td>Pool {p.id + 1}</td>
              <td class="ops-usage">
                <Progress value={p.used * 100} label={`Pool ${p.id + 1} used`} />
                <span class="hint">{pct(p.used)}</span>
              </td>
              <td>{p.status || "-"}</td>
              <td class="ops-num">{p.progress.objects.toLocaleString()}</td>
              <td class="ops-num">{bytes(p.progress.bytes)}</td>
              <td class="ops-num">{p.progress.elapsed ? `${Math.round(p.progress.elapsed / 1e9)} s` : "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
