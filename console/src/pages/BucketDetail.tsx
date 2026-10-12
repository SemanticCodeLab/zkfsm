import { Button, PageHeader, Tabs } from "../components/ui";
import { href, navigate, useRoute } from "../lib/router";
import { CorsTab, EventsTab, LifecycleTab, ReplicationTab } from "./buckets/TabsRules";
import { EncryptionTab, LockTab, PolicyTab, QuotaTab, SummaryTab, TagsTab, VersioningTab, WebsiteTab } from "./buckets/TabsSimple";
import "./buckets/buckets.css";

const TABS: [string, string][] = [
  ["summary", "Summary"],
  ["versioning", "Versioning"],
  ["lock", "Object Lock"],
  ["quota", "Quota"],
  ["lifecycle", "Lifecycle"],
  ["policy", "Policy"],
  ["tags", "Tags"],
  ["replication", "Replication"],
  ["encryption", "Encryption"],
  ["cors", "CORS"],
  ["website", "Website"],
  ["events", "Events"],
];

export function BucketDetail({ bucket }: { bucket: string }) {
  const route = useRoute();
  const tab = TABS.some(([k]) => k === route.params.get("tab")) ? route.params.get("tab")! : "summary";
  const base = `/buckets/${encodeURIComponent(bucket)}`;
  const body = {
    summary: () => <SummaryTab bucket={bucket} />,
    versioning: () => <VersioningTab bucket={bucket} />,
    lock: () => <LockTab bucket={bucket} />,
    quota: () => <QuotaTab bucket={bucket} />,
    lifecycle: () => <LifecycleTab bucket={bucket} />,
    policy: () => <PolicyTab bucket={bucket} />,
    tags: () => <TagsTab bucket={bucket} />,
    replication: () => <ReplicationTab bucket={bucket} />,
    encryption: () => <EncryptionTab bucket={bucket} />,
    cors: () => <CorsTab bucket={bucket} />,
    website: () => <WebsiteTab bucket={bucket} />,
    events: () => <EventsTab bucket={bucket} />,
  }[tab]!;
  return (
    <>
      <nav class="breadcrumbs" aria-label="Breadcrumb">
        <a href={href("/buckets")}>Buckets</a>
        <span aria-hidden="true">/</span>
        <span>{bucket}</span>
      </nav>
      <PageHeader
        title={<span class="mono">{bucket}</span>}
        actions={
          <Button variant="primary" onClick={() => navigate(`/browser/${encodeURIComponent(bucket)}`)}>
            Browse objects
          </Button>
        }
      />
      <Tabs tabs={TABS} active={tab} onChange={(k) => navigate(base, { tab: k === "summary" ? undefined : k })} />
      <div class="bk-tab" role="tabpanel" key={tab}>
        {body()}
      </div>
    </>
  );
}
