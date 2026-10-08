// Admin config-kv calls; request bodies are encrypted by the console proxy.
import { admin, s3Text, ADMIN } from "../../lib/api";
import { KvEntry, parseConfig } from "./configkv";

export interface KeyHelp {
  key: string;
  type: string;
  description: string;
  optional: boolean;
}
export interface SubsysHelp {
  subSys: string;
  description: string;
  multipleTargets: boolean;
  keysHelp: KeyHelp[];
}

export const notifySubsystems = ["webhook", "kafka", "amqp", "mqtt", "nats", "nsq", "redis", "postgres", "mysql", "elasticsearch", "pulsar"].map((t) => `notify_${t}`);
export const auditSubsystems = ["webhook", "kafka", "amqp", "mqtt", "nats", "nsq", "redis", "postgres", "mysql", "elasticsearch", "pulsar"].map((t) => `audit_${t}`);

export const getConfigText = (key: string) => s3Text(`${ADMIN}/get-config-kv`, { query: { key } });
export const getConfig = async (key: string): Promise<KvEntry[]> => parseConfig(await getConfigText(key));
export const helpConfig = (subSys: string) => admin<SubsysHelp>("/help-config-kv", { query: { subSys } });

const put = (op: string, text: string) => admin(op, { method: "PUT", encrypt: true, headers: { "content-type": "text/plain" }, body: text });
export const setConfig = (text: string) => put("/set-config-kv", text);
/** The server reads the del-config-kv body only on PUT through the proxy. */
export const delConfig = (text: string) => put("/del-config-kv", text);
