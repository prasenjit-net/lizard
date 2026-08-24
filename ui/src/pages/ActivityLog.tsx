import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import Badge from "../components/Badge";
import { useLive } from "../context/LiveContext";
import { useToast } from "../context/ToastContext";
import { IconActivity, IconSearch } from "../icons";
import { api, type ActivityLogEntry } from "../lib/api";
import { timeAgo } from "../lib/format";

type KindFilter = "all" | "account" | "order" | "certificate" | "ca";

const KIND_OPTIONS: { value: KindFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "account", label: "Accounts" },
  { value: "order", label: "Orders" },
  { value: "certificate", label: "Certificates" },
  { value: "ca", label: "CA" },
];

const KIND_TONE: Record<string, "neutral" | "accent" | "ok" | "warn" | "err" | "info"> = {
  account: "ok",
  order: "info",
  certificate: "accent",
  ca: "ok",
};

const AUDIT_KINDS = new Set(["account", "order", "certificate", "ca"]);

function matches(entry: ActivityLogEntry, search: string, kind: KindFilter) {
  const kindMatches = kind === "all" || entry.kind === kind;
  const term = search.trim().toLowerCase();
  if (!term) return kindMatches;
  return (
    kindMatches &&
    [entry.kind, entry.summary, entry.createdAt, String(entry.id)].some((value) =>
      value.toLowerCase().includes(term),
    )
  );
}

export default function ActivityLogPage() {
  const { notifyError } = useToast();
  const { activities } = useLive();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<KindFilter>("all");

  const activityQuery = useQuery({ queryKey: ["activity"], queryFn: api.listActivity });
  useEffect(() => {
    if (activityQuery.isError) notifyError(activityQuery.error);
  }, [activityQuery.isError, activityQuery.error, notifyError]);

  const latestActivity = activities[0] ?? null;
  const lastSeenTimestamp = useRef(latestActivity?.timestampMs ?? null);
  useEffect(() => {
    if (
      latestActivity &&
      AUDIT_KINDS.has(latestActivity.kind) &&
      latestActivity.timestampMs !== lastSeenTimestamp.current
    ) {
      lastSeenTimestamp.current = latestActivity.timestampMs;
      queryClient.invalidateQueries({ queryKey: ["activity"] });
    }
  }, [latestActivity, queryClient]);

  const entries = useMemo(
    () => (activityQuery.data ?? []).filter((entry) => matches(entry, search, kind)),
    [activityQuery.data, kind, search],
  );
  const totalEntries = activityQuery.data?.length ?? 0;

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="card-head">
          <h2>Activity Log</h2>
          <span className="card-hint">persistent audit trail for server-side modifications</span>
        </div>

        <div className="mb-3 flex flex-wrap items-center gap-2.5">
          <label className="relative block min-w-[220px] flex-1 sm:max-w-[420px]">
            <IconSearch
              size={15}
              className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ink-faint"
            />
            <input
              className="input py-1.5 pr-3 pl-9 text-[0.84rem]"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search summary, kind, or time"
              type="search"
            />
          </label>
          <label className="flex items-center gap-2 text-[0.8rem] text-ink-muted">
            <span className="font-mono text-[0.68rem] uppercase text-ink-faint">Kind</span>
            <select
              className="input w-auto py-1.5 pr-8 text-[0.84rem]"
              value={kind}
              onChange={(event) => setKind(event.target.value as KindFilter)}
            >
              {KIND_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <span className="ml-auto font-mono text-[0.72rem] text-ink-faint">
            {entries.length} / {totalEntries}
          </span>
        </div>

        {activityQuery.data === undefined ? (
          activityQuery.isError ? (
            <p className="py-2 text-[0.86rem] text-err">Could not load the activity log.</p>
          ) : (
            <div className="flex flex-col gap-3 py-2">
              <div className="skeleton" />
              <div className="skeleton" />
              <div className="skeleton" />
            </div>
          )
        ) : totalEntries === 0 ? (
          <p className="py-2 text-[0.86rem] text-ink-faint">
            Audit entries will appear here when accounts, orders, challenges, or certificates change.
          </p>
        ) : entries.length === 0 ? (
          <p className="py-2 text-[0.86rem] text-ink-faint">No activity entries match these filters.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-line">
            <table className="w-full min-w-[760px] border-collapse text-sm">
              <thead>
                <tr>
                  <th className="border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase">
                    Kind
                  </th>
                  <th className="border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase">
                    Summary
                  </th>
                  <th className="border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase">
                    Time
                  </th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
                    <td className="px-4 py-2.5">
                      <Badge tone={KIND_TONE[entry.kind] ?? "neutral"} dot>
                        {entry.kind}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-start gap-2">
                        <IconActivity size={15} className="mt-0.5 shrink-0 text-ink-faint" />
                        <span className="break-words">{entry.summary}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-[0.82rem] text-ink-muted">
                      <time title={new Date(entry.createdAt).toLocaleString()}>
                        {timeAgo(entry.timestampMs)}
                      </time>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
