import { describe, expect, it } from "vitest";
import { avgLatency, derive, labelText, parseFamilies, parseSamples, pushBounded, rate, total } from "./prom";
import { lerp, linePath, niceStep, shortNum, yScale } from "./scale";
import { arnFor, enabled, formatLine, formatValue, isPlaceholder, parseConfig, parseLine, targetKey, validId } from "./configkv";

const text = `# TYPE zkfsm_requests_total counter
zkfsm_requests_total{code="2xx"} 10
zkfsm_requests_total{code="4xx"} 2
zkfsm_requests_total{code="5xx"} 0
# TYPE zkfsm_requests_inflight gauge
zkfsm_requests_inflight 3
# TYPE zkfsm_request_duration_seconds histogram
zkfsm_request_duration_seconds_bucket{le="0.005"} 8
zkfsm_request_duration_seconds_bucket{le="+Inf"} 10
zkfsm_request_duration_seconds_sum 1.5
zkfsm_request_duration_seconds_count 10
# HELP zkfsm_tier_objects Objects on tiers
# TYPE zkfsm_tier_objects gauge
zkfsm_tier_objects{tier="WARM",path="a \\"b\\", c"} 4
garbage line here
`;

describe("prometheus parser", () => {
  it("parses samples, labels and special values", () => {
    const s = parseSamples(text);
    expect(s).toHaveLength(9);
    expect(s[0]).toEqual({ name: "zkfsm_requests_total", labels: { code: "2xx" }, value: 10 });
    expect(s.find((x) => x.labels.le === "+Inf")!.value).toBe(10);
    expect(parseSamples("a +Inf\nb -Inf\nc NaN").map((x) => x.value)).toEqual([Infinity, -Infinity, NaN]);
    expect(s.at(-1)!.labels).toEqual({ tier: "WARM", path: 'a "b", c' });
  });
  it("groups histogram series into one family with help and type", () => {
    const f = parseFamilies(text);
    const h = f.find((x) => x.name === "zkfsm_request_duration_seconds")!;
    expect(h.type).toBe("histogram");
    expect(h.samples).toHaveLength(4);
    expect(f.find((x) => x.name === "zkfsm_tier_objects")!.help).toBe("Objects on tiers");
  });
  it("sums with label filters", () => {
    const s = parseSamples(text);
    expect(total(s, "zkfsm_requests_total")).toBe(12);
    expect(total(s, "zkfsm_requests_total", { code: "4xx" })).toBe(2);
    expect(total(s, "missing")).toBe(0);
  });
  it("renders label text", () => {
    expect(labelText({})).toBe("");
    expect(labelText({ a: "1", b: "2" })).toBe('{a="1",b="2"}');
  });
});

describe("rates", () => {
  it("computes per-second counter rates and handles resets", () => {
    expect(rate(10, 20, 5)).toBe(2);
    expect(rate(100, 4, 2)).toBe(2);
    expect(rate(1, 2, 0)).toBe(0);
  });
  it("averages latency from histogram deltas", () => {
    expect(avgLatency(1, 10, 2, 14)).toBeCloseTo(0.25);
    expect(avgLatency(1, 10, 1, 10)).toBeNull();
    expect(avgLatency(5, 100, 0.5, 2)).toBeCloseTo(0.25);
  });
  it("derives a chart point from two snapshots", () => {
    const a = { t: 0, samples: parseSamples(text) };
    const b = { t: 5000, samples: parseSamples(text.replace('code="2xx"} 10', 'code="2xx"} 20').replace("_sum 1.5", "_sum 2.5").replace("_count 10", "_count 20")) };
    const p = derive(a, b);
    expect(p.rates["2xx"]).toBe(2);
    expect(p.rates["4xx"]).toBe(0);
    expect(p.inflight).toBe(3);
    expect(p.latencyMs).toBeCloseTo(100);
  });
  it("keeps a bounded window", () => {
    let l: number[] = [];
    for (let i = 0; i < 70; i++) l = pushBounded(l, i, 60);
    expect(l).toHaveLength(60);
    expect(l[0]).toBe(10);
  });
});

describe("chart scaling", () => {
  it("picks nice steps", () => {
    expect(niceStep(10, 4)).toBe(5);
    expect(niceStep(0.7, 4)).toBe(0.2);
    expect(niceStep(0, 4)).toBe(1);
  });
  it("builds a covering y scale from zero", () => {
    expect(yScale(7)).toEqual({ max: 8, ticks: [0, 2, 4, 6, 8] });
    expect(yScale(0).max).toBe(1);
    expect(yScale(0.3).ticks.at(-1)).toBeGreaterThanOrEqual(0.3);
  });
  it("maps and draws paths with gaps", () => {
    expect(lerp(5, 0, 10, 100, 0)).toBe(50);
    expect(lerp(5, 3, 3, 7, 9)).toBe(7);
    expect(linePath([{ x: 0, y: 1 }, { x: 1, y: 2 }, { x: 2, y: null }, { x: 3, y: 4 }])).toBe("M0.0,1.0L1.0,2.0M3.0,4.0");
  });
  it("formats tick labels", () => {
    expect(shortNum(1500)).toBe("1.5k");
    expect(shortNum(0)).toBe("0");
    expect(shortNum(0.25)).toBe("0.25");
    expect(shortNum(2e6)).toBe("2M");
  });
});

describe("config-kv", () => {
  it("parses quoted values, ids and empty values", () => {
    const e = parseLine('notify_webhook:probe enable=off endpoint="http://h/x y" auth_token=""')!;
    expect(e.subsys).toBe("notify_webhook");
    expect(e.id).toBe("probe");
    expect(e.kvs).toEqual([
      ["enable", "off"],
      ["endpoint", "http://h/x y"],
      ["auth_token", ""],
    ]);
    expect(enabled(e)).toBe(false);
  });
  it("parses multi-line output and skips comments", () => {
    const l = parseConfig('# c\nnotify_kafka brokers=a:9092\n\naudit_webhook:x enable=on\n');
    expect(l.map((e) => targetKey(e.subsys, e.id))).toEqual(["notify_kafka", "audit_webhook:x"]);
    expect(enabled(l[0])).toBe(true);
  });
  it("recognizes the unconfigured placeholder", () => {
    expect(isPlaceholder(parseLine('notify_webhook enable=off endpoint="" comment=""')!)).toBe(true);
    expect(isPlaceholder(parseLine('notify_webhook enable=off endpoint="http://x"')!)).toBe(false);
  });
  it("formats lines that round-trip", () => {
    const line = formatLine({ subsys: "notify_mqtt", id: "m1", kvs: [["enable", "on"], ["broker", "tcp://h:1883"], ["topic", "a b"], ["password", ""]] });
    expect(line).toBe('notify_mqtt:m1 enable=on broker=tcp://h:1883 topic="a b"');
    expect(parseLine(line)!.kvs[2]).toEqual(["topic", "a b"]);
    expect(formatLine({ subsys: "audit_kafka", id: "_", kvs: [["x", ""]] }, true)).toBe('audit_kafka x=""');
    expect(formatValue("")).toBe('""');
  });
  it("builds ARNs and validates ids", () => {
    expect(arnFor("us-east-1", "_", "webhook")).toBe("arn:minio:sqs:us-east-1:_:webhook");
    expect(arnFor("r", "a", "")).toBe("");
    expect(validId("ok-1.x_y")).toBe(true);
    expect(validId("bad id")).toBe(false);
  });
});
