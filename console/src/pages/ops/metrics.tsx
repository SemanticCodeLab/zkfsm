// Live metrics: samples cluster.metrics() on an interval and renders the charts.
import { useEffect, useRef, useState } from "preact/hooks";
import { cluster } from "../../lib/api";
import { derive, parseSamples, Point, pushBounded, Sample, Snapshot } from "./prom";
import { LineChart } from "./LineChart";

export const SAMPLE_MS = 5000;
export const MAX_POINTS = 60;

export interface Live {
  points: Point[];
  latest: Sample[] | null;
  text: string;
  error: string | null;
  paused: boolean;
  setPaused: (p: boolean) => void;
}

export function useLiveMetrics(): Live {
  const [points, setPoints] = useState<Point[]>([]);
  const [latest, setLatest] = useState<Sample[] | null>(null);
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);
  const prev = useRef<Snapshot | null>(null);
  useEffect(() => {
    if (paused) return;
    let alive = true;
    const tick = async () => {
      try {
        const body = await cluster.metrics();
        if (!alive) return;
        const snap = { t: Date.now(), samples: parseSamples(body) };
        if (prev.current) {
          const p = derive(prev.current, snap);
          setPoints((list) => pushBounded(list, p, MAX_POINTS));
        }
        prev.current = snap;
        setLatest(snap.samples);
        setText(body);
        setError(null);
      } catch (e) {
        if (alive) setError((e as Error).message);
      }
    };
    tick();
    const id = setInterval(tick, SAMPLE_MS);
    return () => {
      alive = false;
      clearInterval(id);
      prev.current = null;
    };
  }, [paused]);
  return { points, latest, text, error, paused, setPaused };
}

const ms = (v: number) => (v >= 1000 ? `${+(v / 1000).toFixed(2)}s` : `${+v.toFixed(v < 10 ? 2 : 0)}`);

export function MetricCharts({ live }: { live: Live }) {
  const times = live.points.map((p) => p.t);
  return (
    <>
      {live.error && (
        <div class="notice notice-error" role="alert">
          Metrics unavailable: {live.error}
        </div>
      )}
      <div class="ops-charts">
        <LineChart
          title="Requests per second"
          times={times}
          series={[
            { label: "2xx", values: live.points.map((p) => p.rates["2xx"]), color: 2 },
            { label: "4xx", values: live.points.map((p) => p.rates["4xx"]), color: 3 },
            { label: "5xx", values: live.points.map((p) => p.rates["5xx"]), color: 4 },
          ]}
        />
        <LineChart title="In-flight requests" times={times} series={[{ label: "inflight", values: live.points.map((p) => p.inflight), color: 1 }]} />
        <LineChart title="Average latency (ms)" times={times} format={ms} series={[{ label: "avg", values: live.points.map((p) => p.latencyMs), color: 1 }]} />
      </div>
    </>
  );
}
