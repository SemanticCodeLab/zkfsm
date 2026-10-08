import { Fragment, render } from "preact";
import { useEffect, useState } from "preact/hooks";
import "./style.css";
import { Session, session, setUnauthorizedHandler } from "./lib/api";
import { href, useRoute } from "./lib/router";
import { cx, Toasts } from "./components/ui";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Buckets } from "./pages/Buckets";
import { BucketDetail } from "./pages/BucketDetail";
import { Browser } from "./pages/Browser";
import { Users } from "./pages/Users";
import { Groups } from "./pages/Groups";
import { AccessKeys } from "./pages/AccessKeys";
import { Policies } from "./pages/Policies";
import { Identity } from "./pages/Identity";
import { Tenants } from "./pages/Tenants";
import { Monitoring } from "./pages/Monitoring";
import { Kms } from "./pages/Kms";
import { SiteReplication } from "./pages/SiteReplication";
import { Tiers } from "./pages/Tiers";
import { Events } from "./pages/Events";
import { Settings } from "./pages/Settings";
import { applyTheme, getTheme, setTheme, Theme } from "./lib/theme";

const nav: { section?: string; path: string; label: string }[] = [
  { path: "/", label: "Dashboard" },
  { section: "Storage", path: "/buckets", label: "Buckets" },
  { path: "/browser", label: "Object Browser" },
  { path: "/tiers", label: "Tiers" },
  { path: "/site-replication", label: "Site Replication" },
  { section: "Identity", path: "/iam/users", label: "Users" },
  { path: "/iam/groups", label: "Groups" },
  { path: "/iam/access-keys", label: "Access Keys" },
  { path: "/iam/policies", label: "Policies" },
  { path: "/iam/identity", label: "OpenID / LDAP" },
  { path: "/iam/tenants", label: "Tenants" },
  { section: "Operations", path: "/monitoring", label: "Monitoring" },
  { path: "/events", label: "Events" },
  { path: "/kms", label: "KMS Keys" },
  { path: "/settings", label: "Settings" },
];

function Page({ segs }: { segs: string[] }) {
  const [a, b, c] = segs;
  switch (a) {
    case undefined:
      return <Dashboard />;
    case "buckets":
      return b ? <BucketDetail bucket={b} /> : <Buckets />;
    case "browser":
      return <Browser bucket={b} />;
    case "iam":
      switch (b) {
        case "users":
          return <Users user={c} />;
        case "groups":
          return <Groups group={c} />;
        case "access-keys":
          return <AccessKeys />;
        case "policies":
          return <Policies policy={c} />;
        case "identity":
          return <Identity />;
        case "tenants":
          return <Tenants />;
      }
      break;
    case "monitoring":
      return <Monitoring />;
    case "kms":
      return <Kms />;
    case "site-replication":
      return <SiteReplication />;
    case "tiers":
      return <Tiers />;
    case "events":
      return <Events />;
    case "settings":
      return <Settings />;
  }
  return <div class="empty">Page not found.</div>;
}

function App() {
  const route = useRoute();
  const [sess, setSess] = useState<Session | null | undefined>(undefined);
  const [theme, setT] = useState<Theme>(getTheme());
  useEffect(() => {
    setUnauthorizedHandler(() => setSess(null));
    session.current().then(setSess, () => setSess(null));
  }, []);
  useEffect(() => applyTheme(theme), [theme]);
  if (sess === undefined) return <div class="loading">Loading…</div>;
  if (sess === null) return <Login onLogin={setSess} />;
  const active = (p: string) => (p === "/" ? route.path === "/" : route.path === p || route.path.startsWith(`${p}/`));
  return (
    <div class="shell">
      <a class="skip" href="#main" onClick={(e) => (e.preventDefault(), document.getElementById("main")?.focus())}>
        Skip to content
      </a>
      <nav class="sidebar" aria-label="Main">
        <div class="brand">zkfsm</div>
        <ul>
          {nav.map((n) => (
            <Fragment key={n.path}>
              {n.section && <li class="nav-section">{n.section}</li>}
              <li>
                <a href={href(n.path)} class={cx(active(n.path) && "active")} aria-current={active(n.path) ? "page" : undefined}>
                  {n.label}
                </a>
              </li>
            </Fragment>
          ))}
        </ul>
        <div class="sidebar-foot">
          <div class="who" title={sess.accessKey}>
            {sess.user}
          </div>
          <button
            type="button"
            class="btn btn-ghost btn-sm"
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            onClick={() => {
              const t = theme === "dark" ? "light" : "dark";
              setTheme(t);
              setT(t);
            }}
          >
            {theme === "dark" ? "Light" : "Dark"} theme
          </button>
          <button type="button" class="btn btn-ghost btn-sm" onClick={() => session.logout().finally(() => setSess(null))}>
            Log out
          </button>
        </div>
      </nav>
      <main id="main" tabIndex={-1}>
        <Page segs={route.segments} />
      </main>
      <Toasts />
    </div>
  );
}

render(<App />, document.getElementById("app")!);
