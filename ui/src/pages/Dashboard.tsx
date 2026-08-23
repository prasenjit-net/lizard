import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import ActivityFeed from "../components/ActivityFeed";
import Badge from "../components/Badge";
import StatCard from "../components/StatCard";
import { useLive } from "../context/LiveContext";
import { useToast } from "../context/ToastContext";
import { IconActivity, IconCpu, IconDatabase, IconShield, IconUsers } from "../icons";
import { api } from "../lib/api";
import { formatNumber, formatUptime } from "../lib/format";

export default function DashboardPage() {
  const { metrics, history, activities, status } = useLive();
  const { notifyError } = useToast();
  const cpuSeries = history.map((m) => m.cpu);
  const memSeries = history.map((m) => m.memory);

  // Same ["certificates"] query key the Certificates page uses — React
  // Query dedupes/shares the fetch rather than issuing a second request.
  const certsQuery = useQuery({ queryKey: ["certificates"], queryFn: api.listCertificates });
  const ordersQuery = useQuery({ queryKey: ["orders"], queryFn: api.listOrders });
  useEffect(() => {
    if (certsQuery.isError) notifyError(certsQuery.error);
  }, [certsQuery.isError, certsQuery.error, notifyError]);
  useEffect(() => {
    if (ordersQuery.isError) notifyError(ordersQuery.error);
  }, [ordersQuery.isError, ordersQuery.error, notifyError]);
  const certificates = certsQuery.data ?? [];
  const orders = ordersQuery.data ?? [];
  const validCerts = certificates.filter((cert) => cert.status === "valid").length;
  const revokedCerts = certificates.filter((cert) => cert.status === "revoked").length;
  const expiringCerts = certificates.filter((cert) => {
    const daysLeft = (new Date(cert.notAfter).getTime() - Date.now()) / 86_400_000;
    return cert.status === "valid" && daysLeft <= 30;
  }).length;
  const invalidOrders = orders.filter((order) => order.status === "invalid").length;
  const activeOrders = orders.filter((order) =>
    ["pending", "ready", "processing"].includes(order.status),
  ).length;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 min-[560px]:grid-cols-2 xl:grid-cols-5">
        <StatCard
          icon={<IconCpu size={18} />}
          label="CPU"
          value={metrics ? `${metrics.cpu.toFixed(0)}%` : "—"}
          sub="host usage"
          series={cpuSeries}
          max={100}
        />
        <StatCard
          icon={<IconDatabase size={18} />}
          label="Memory"
          value={metrics ? `${metrics.memory.toFixed(0)}%` : "—"}
          sub="host usage"
          series={memSeries}
          max={100}
          color="var(--chart-2)"
        />
        <StatCard
          icon={<IconActivity size={18} />}
          label="Requests / min"
          value={metrics ? formatNumber(metrics.requestsPerMin) : "—"}
          sub={metrics ? `${formatNumber(metrics.requestsTotal)} total` : "waiting for data"}
        />
        <StatCard
          icon={<IconUsers size={18} />}
          label="Clients online"
          value={metrics ? String(metrics.wsClients) : "—"}
          sub={metrics ? `server up ${formatUptime(metrics.uptimeSecs)}` : "waiting for data"}
        />
        <StatCard
          icon={<IconShield size={18} />}
          label="Certificates"
          value={certsQuery.data ? String(certificates.length) : "—"}
          sub={certsQuery.data ? `${validCerts} valid, ${revokedCerts} revoked` : "waiting for data"}
        />
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Attention</h2>
          <span className="card-hint">operator signals from live state and ACME records</span>
        </div>
        <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2 xl:grid-cols-4">
          <Link
            to="/certificates"
            className="rounded-lg border border-line bg-surface-2 px-3 py-2.5 transition-colors hover:border-line-strong hover:bg-surface"
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-sm font-medium">Expiring certificates</span>
              <Badge tone={expiringCerts > 0 ? "warn" : "ok"}>{expiringCerts}</Badge>
            </div>
            <p className="text-[0.78rem] text-ink-faint">Valid certificates expiring within 30 days.</p>
          </Link>
          <Link
            to="/orders"
            className="rounded-lg border border-line bg-surface-2 px-3 py-2.5 transition-colors hover:border-line-strong hover:bg-surface"
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-sm font-medium">Invalid orders</span>
              <Badge tone={invalidOrders > 0 ? "err" : "ok"}>{invalidOrders}</Badge>
            </div>
            <p className="text-[0.78rem] text-ink-faint">Failed ACME orders that may need challenge review.</p>
          </Link>
          <Link
            to="/orders"
            className="rounded-lg border border-line bg-surface-2 px-3 py-2.5 transition-colors hover:border-line-strong hover:bg-surface"
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-sm font-medium">Active orders</span>
              <Badge tone={activeOrders > 0 ? "info" : "neutral"}>{activeOrders}</Badge>
            </div>
            <p className="text-[0.78rem] text-ink-faint">Pending, ready, or processing orders in flight.</p>
          </Link>
          <Link
            to="/settings"
            className="rounded-lg border border-line bg-surface-2 px-3 py-2.5 transition-colors hover:border-line-strong hover:bg-surface"
          >
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="text-sm font-medium">Live connection</span>
              <Badge tone={status === "online" ? "ok" : "warn"}>{status}</Badge>
            </div>
            <p className="text-[0.78rem] text-ink-faint">WebSocket health for real-time dashboard updates.</p>
          </Link>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Activity</h2>
          <span className="card-hint">server events</span>
        </div>
        <ActivityFeed activities={activities} />
      </section>
    </div>
  );
}
