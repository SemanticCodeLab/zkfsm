import { useEffect, useState } from "preact/hooks";
import { admin, ADMIN, s3Text } from "../lib/api";
import { date, duration } from "../lib/format";
import { Badge, Button, Card, Confirm, Empty, Field, KeyValue, Loading, Modal, PageHeader, Select, toast, toastError, useAsync } from "../components/ui";
import { isUnavailable, Unavailable } from "./ops/common";
import { JobItem, JobMetric, jobState, placeholders, progressRows, stateKind } from "./ops/batch";
import "./ops/ops.css";

const status = (id: string) => admin<{ LastMetric: JobMetric }>("/status-job", { query: { jobId: id } }).then((r) => r.LastMetric);

async function loadJobs(): Promise<{ job: JobItem; metric?: JobMetric }[]> {
  const list = (await admin<{ jobs: JobItem[] | null }>("/list-jobs")).jobs ?? [];
  return Promise.all(list.map(async (job) => ({ job, metric: await status(job.id).catch(() => undefined) })));
}

function StartJob({ types, onClose, onDone }: { types: string[]; onClose: () => void; onDone: () => void }) {
  const [type, setType] = useState(types[0]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const tpl = useAsync(() => s3Text(`${ADMIN}/generate-job`, { query: { jobType: type } }), [type]);
  useEffect(() => {
    if (tpl.data !== undefined) setText(tpl.data);
  }, [tpl.data]);
  const left = placeholders(text);
  const submit = async () => {
    setBusy(true);
    try {
      const r = await admin<JobItem>("/start-job", { method: "POST", headers: { "content-type": "application/yaml" }, body: text });
      toast(`Job ${r.id} started`);
      onDone();
      onClose();
    } catch (e) {
      toastError(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      wide
      title="Start batch job"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={submit} disabled={busy || !text.trim()}>
            Start job
          </Button>
        </>
      }
    >
      <Select label="Job type" value={type} onChange={setType} options={types} hint="replicate copies objects between buckets or servers, keyrotate reseals encrypted objects, expire deletes by rule." />
      <Field label="Job definition (YAML)" hint={left.length ? `Replace the template values: ${left.join(", ")}` : "The server validates the definition before starting."}>
        {(id) => <textarea id={id} class="mono" rows={18} spellcheck={false} value={text} onInput={(e) => setText((e.target as HTMLTextAreaElement).value)} />}
      </Field>
    </Modal>
  );
}

function JobStatus({ id, onClose }: { id: string; onClose: () => void }) {
  const st = useAsync(() => status(id), [id]);
  const def = useAsync(() => s3Text(`${ADMIN}/describe-job`, { query: { jobId: id } }).catch(() => ""), [id]);
  const state = jobState(st.data);
  useEffect(() => {
    if (state !== "running") return;
    const t = setInterval(st.reload, 2000);
    return () => clearInterval(t);
  }, [state]);
  return (
    <Modal wide title={`Job ${id}`} onClose={onClose} footer={<Button onClick={onClose}>Close</Button>}>
      <Loading state={st}>
        {() => {
          const m = st.data!;
          return (
            <KeyValue
              rows={[
                ["Type", m.jobType],
                ["State", <Badge kind={stateKind(state)}>{state}</Badge>],
                ["Started", date(m.startTime)],
                ["Last update", date(m.lastUpdate)],
                ["Retries", m.retryAttempts ?? 0],
                ...progressRows(m),
              ]}
            />
          );
        }}
      </Loading>
      {def.data ? <pre class="ops-scroll mono">{def.data}</pre> : null}
    </Modal>
  );
}

export function Batch() {
  const types = useAsync(() => admin<string[]>("/list-supported-job-types"));
  const jobs = useAsync(loadJobs);
  const [starting, setStarting] = useState(false);
  const [viewing, setViewing] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const anyRunning = (jobs.data ?? []).some((j) => jobState(j.metric) === "running");
  useEffect(() => {
    if (!anyRunning) return;
    const t = setInterval(jobs.reload, 3000);
    return () => clearInterval(t);
  }, [anyRunning]);
  if (types.error && isUnavailable(types.error))
    return (
      <>
        <PageHeader title="Batch Jobs" />
        <Unavailable title="Batch jobs are not available on this server.">Batch jobs run in single-node mode.</Unavailable>
      </>
    );
  return (
    <>
      <PageHeader
        title="Batch Jobs"
        actions={
          <Button variant="primary" onClick={() => setStarting(true)} disabled={!types.data?.length}>
            Start job
          </Button>
        }
      />
      <Card title="Jobs" actions={<Button small onClick={jobs.reload}>Refresh</Button>}>
        <p class="hint">Jobs run in the background and resume after a restart. Progress is checkpointed.</p>
        <Loading state={jobs}>
          {() =>
            jobs.data!.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Job</th>
                    <th scope="col">Type</th>
                    <th scope="col">State</th>
                    <th scope="col">Started by</th>
                    <th scope="col">Started</th>
                    <th scope="col">Elapsed</th>
                    <th scope="col">
                      <span class="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.data!.map(({ job, metric }) => {
                    const s = jobState(metric);
                    return (
                      <tr key={job.id}>
                        <td class="ops-mono">{job.id}</td>
                        <td>{job.type}</td>
                        <td>
                          <Badge kind={stateKind(s)}>{s}</Badge>
                        </td>
                        <td>{job.user || "-"}</td>
                        <td>{date(job.started)}</td>
                        <td>{job.elapsed ? duration(job.elapsed / 1e9) : "-"}</td>
                        <td>
                          <div class="actions">
                            <Button small onClick={() => setViewing(job.id)} aria-label={`Status of ${job.id}`}>
                              Status
                            </Button>
                            {s === "running" && (
                              <Button small variant="danger" onClick={() => setCancelling(job.id)} aria-label={`Cancel ${job.id}`}>
                                Cancel
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <Empty>No batch jobs yet.</Empty>
            )
          }
        </Loading>
      </Card>
      {starting && types.data && <StartJob types={types.data} onClose={() => setStarting(false)} onDone={jobs.reload} />}
      {viewing && <JobStatus id={viewing} onClose={() => setViewing(null)} />}
      {cancelling && (
        <Confirm
          title="Cancel job"
          message={
            <>
              Cancel job <strong>{cancelling}</strong>? Work already done is kept.
            </>
          }
          confirmLabel="Cancel job"
          onConfirm={async () => {
            await admin("/cancel-job", { method: "DELETE", query: { id: cancelling } });
            toast("Job cancelled");
            jobs.reload();
          }}
          onClose={() => setCancelling(null)}
        />
      )}
    </>
  );
}
