// Background heal status per erasure set and scanner status (madmin admin API).
import { useEffect } from "preact/hooks";
import { admin } from "../../lib/api";
import { date } from "../../lib/format";
import { Badge, Button, Card, Empty, KeyValue, Loading, useAsync } from "../../components/ui";
import { isUnavailable, Unavailable } from "./common";

export interface BgHealStatus {
  offline_nodes: string[];
  ScannedItemsCount: number;
  HealDisks: string[];
  sets: { id: string; pool_index: number; set_index: number; heal_status: string; total_objects: number; disks: { endpoint: string; state: string; healing?: boolean }[] }[];
  sc_parity: Record<string, number>;
}

export interface ScannerMetrics {
  collected: string;
  current_cycle: number;
  current_started: string;
  cycle_complete_times: string[];
  ongoing_buckets: number;
  life_time_ops: Record<string, number>;
  active: string[];
}

/** One scanner sample: GET /metrics?types=1&n=1 (scanner type bit). */
export async function scannerStatus(): Promise<{ hosts: string[]; scanner: ScannerMetrics | null }> {
  const s = await admin<{ hosts: string[]; aggregated: { scanner?: ScannerMetrics } }>("/metrics", { query: { types: 1, n: 1 } });
  return { hosts: s?.hosts ?? [], scanner: s?.aggregated?.scanner ?? null };
}

export function BgHealCard() {
  const st = useAsync(() => admin<BgHealStatus>("/background-heal/status", { method: "POST" }));
  if (st.error && isUnavailable(st.error)) return null;
  return (
    <Card title="Background heal by set" actions={<Button onClick={st.reload}>Refresh</Button>}>
      <Loading state={st}>
        {() => {
          const h = st.data!;
          return (
            <>
              <KeyValue
                rows={[
                  ["Offline nodes", h.offline_nodes.length ? <Badge kind="error">{h.offline_nodes.join(", ")}</Badge> : "none"],
                  ["Drives healing", h.HealDisks.length ? h.HealDisks.join(", ") : "none"],
                  ["Items scanned", h.ScannedItemsCount.toLocaleString()],
                  ["Parity (standard)", String(h.sc_parity?.STANDARD ?? "-")],
                ]}
              />
              {h.sets.length ? (
                <table aria-label="Erasure sets">
                  <thead>
                    <tr>
                      <th scope="col">Set</th>
                      <th scope="col">Heal</th>
                      <th scope="col" class="num">Objects</th>
                      <th scope="col" class="num">Drives ok</th>
                    </tr>
                  </thead>
                  <tbody>
                    {h.sets.map((s) => {
                      const ok = s.disks.filter((d) => d.state === "ok").length;
                      return (
                        <tr key={s.id}>
                          <td>
                            Pool {s.pool_index + 1}, set {s.set_index + 1}
                          </td>
                          <td>
                            <Badge kind={s.heal_status === "running" ? "warn" : "ok"}>{s.heal_status}</Badge>
                          </td>
                          <td class="ops-num">{s.total_objects.toLocaleString()}</td>
                          <td class="ops-num">
                            {ok < s.disks.length ? <Badge kind="warn">{`${ok}/${s.disks.length}`}</Badge> : `${ok}/${s.disks.length}`}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              ) : (
                <Empty>No erasure sets.</Empty>
              )}
            </>
          );
        }}
      </Loading>
    </Card>
  );
}

export function ScannerCard() {
  const st = useAsync(scannerStatus);
  useEffect(() => {
    const id = setInterval(st.reload, 10000);
    return () => clearInterval(id);
  }, []);
  if (st.error && isUnavailable(st.error)) return <Unavailable title="Scanner status is not available on this server." />;
  return (
    <Card title="Scanner" actions={<Button onClick={st.reload}>Refresh</Button>}>
      <Loading state={st}>
        {() => {
          const s = st.data!.scanner;
          if (!s) return <Empty>No scanner data.</Empty>;
          const last = s.cycle_complete_times[s.cycle_complete_times.length - 1];
          const ops = s.life_time_ops ?? {};
          return (
            <KeyValue
              rows={[
                ["State", <Badge kind={s.active?.length || s.ongoing_buckets ? "warn" : "ok"}>{s.active?.length || s.ongoing_buckets ? "scanning" : "idle"}</Badge>],
                ["Current cycle", s.current_cycle.toLocaleString()],
                ["Cycle started", date(s.current_started)],
                ["Last cycle completed", date(last)],
                ["Active", s.active?.length ? s.active.join(", ") : "-"],
                ["Objects scanned", (ops.ScanObject ?? 0).toLocaleString()],
                ["Heal checks", (ops.HealCheck ?? 0).toLocaleString()],
                ["Objects repaired", (ops.HealObject ?? 0).toLocaleString()],
                ["Nodes reporting", st.data!.hosts.length ? st.data!.hosts.join(", ") : "-"],
              ]}
            />
          );
        }}
      </Loading>
    </Card>
  );
}
