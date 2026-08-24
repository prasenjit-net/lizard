// The CA admin view: the root certificate (for trust-store installation)
// plus every certificate this server has issued, with a revoke action and
// a click-to-expand detail row. Follows the same useQuery/useMutation-
// patches-the-cache pattern as TasksCard, and rides the existing /ws
// activity feed for live updates — order/challenge/finalize handlers
// already broadcast a "certificate" activity on every lifecycle event, so
// this just watches for those rather than needing its own WebSocket
// message type.
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import Badge from "../components/Badge";
import CertificateAttributes from "../components/CertificateAttributes";
import { useLive } from "../context/LiveContext";
import { useToast } from "../context/ToastContext";
import {
  IconChevronRight,
  IconCopy,
  IconDownload,
  IconSearch,
  IconTrash,
} from "../icons";
import {
  api,
  type Account,
  type AuthorizationInfo,
  type Certificate,
  type CertificateDetail,
  type ChallengeInfo,
  type Order,
  type OrderStatus,
} from "../lib/api";

type Tone = "neutral" | "accent" | "ok" | "warn" | "err" | "info";

const TH =
  "border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase";
const TD = "px-4 py-2.5";

// RFC 5280 §5.3.1 CRL reason codes — the only ones an ACME client can
// actually set via /acme/revoke-cert (the admin "Revoke" button in this
// UI doesn't collect a reason, so revocationReason is null more often
// than not).
const REVOCATION_REASONS: Record<number, string> = {
  0: "Unspecified",
  1: "Key compromise",
  2: "CA compromise",
  3: "Affiliation changed",
  4: "Superseded",
  5: "Cessation of operation",
  6: "Certificate hold",
  8: "Remove from CRL",
  9: "Privilege withdrawn",
  10: "AA compromise",
};

const EXPIRY_WARNING_DAYS = 30;

const ORDER_STATUS_TONE: Record<OrderStatus, Tone> = {
  pending: "neutral",
  ready: "info",
  processing: "info",
  valid: "ok",
  invalid: "err",
};

const AUTHZ_STATUS_TONE: Record<AuthorizationInfo["status"], Tone> = {
  pending: "neutral",
  valid: "ok",
  invalid: "err",
  expired: "warn",
};

const CHALLENGE_STATUS_TONE: Record<ChallengeInfo["status"], Tone> = {
  pending: "neutral",
  processing: "info",
  valid: "ok",
  invalid: "err",
};

function downloadTextFile(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

/** A truncated monospace id/thumbprint that copies its full value on click —
 * used in the Accounts table where every column is otherwise too long to
 * show in full. */
function CopyableId({ value }: { value: string }) {
  const { push } = useToast();
  const copy = async () => {
    await navigator.clipboard.writeText(value);
    push("success", "Copied to clipboard");
  };
  return (
    <button
      type="button"
      onClick={copy}
      title={`${value} — click to copy`}
      className="block max-w-[160px] cursor-pointer truncate font-mono text-[0.78rem] text-ink-muted hover:text-accent"
    >
      {value}
    </button>
  );
}

export function CaRootCard() {
  const { push, notifyError } = useToast();
  const caQuery = useQuery({ queryKey: ["ca"], queryFn: api.caInfo });

  useEffect(() => {
    if (caQuery.isError) notifyError(caQuery.error);
  }, [caQuery.isError, caQuery.error, notifyError]);

  const copy = async () => {
    if (!caQuery.data) return;
    await navigator.clipboard.writeText(caQuery.data.rootCertPem);
    push("success", "Root certificate copied to clipboard");
  };

  return (
    <section className="card">
      <div className="card-head">
        <h2>Certificate Authority</h2>
        <span className="card-hint">install this root in trust stores that should accept certificates this server issues</span>
      </div>
      {caQuery.data ? (
        <>
          <pre className="max-h-[220px] overflow-auto rounded-lg border border-line bg-surface-2 p-3 font-mono text-[0.76rem] leading-relaxed break-all whitespace-pre-wrap">
            {caQuery.data.rootCertPem}
          </pre>
          <div className="mt-3 rounded-lg border border-line bg-surface-2 p-3">
            <div className="mb-2 text-sm font-semibold">CA certificate attributes</div>
            <CertificateAttributes attributes={caQuery.data.attributes} />
          </div>
          <div className="mt-3 flex flex-wrap gap-2.5">
            <button className="btn btn-secondary" onClick={copy}>
              <IconCopy size={16} /> Copy
            </button>
            <button
              className="btn btn-secondary"
              onClick={() => downloadTextFile("root-cert.pem", caQuery.data.rootCertPem)}
            >
              <IconDownload size={16} /> Download
            </button>
          </div>
        </>
      ) : caQuery.isError ? (
        <p className="py-2 text-[0.86rem] text-err">Could not load the CA root certificate.</p>
      ) : (
        <div className="skeleton" style={{ height: 120 }} />
      )}
    </section>
  );
}

/** Tone + label for how close `notAfter` is, once it's actually known (the
 * list view doesn't carry it — only the expanded detail does). */
function expiryStatus(notAfter: string): { tone: "ok" | "warn" | "err"; label: string } {
  const daysLeft = (new Date(notAfter).getTime() - Date.now()) / 86_400_000;
  if (daysLeft < 0) return { tone: "err", label: "Expired" };
  if (daysLeft <= EXPIRY_WARNING_DAYS) {
    return { tone: "warn", label: `Expires in ${Math.ceil(daysLeft)}d` };
  }
  return { tone: "ok", label: `Expires in ${Math.ceil(daysLeft)}d` };
}

function matchesSearch(values: string[], search: string) {
  const term = search.trim().toLowerCase();
  if (!term) return true;
  return values.some((value) => value.toLowerCase().includes(term));
}

function SearchBox({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="relative block min-w-[220px] flex-1 sm:max-w-[360px]">
      <IconSearch
        size={15}
        className="pointer-events-none absolute top-1/2 left-3 -translate-y-1/2 text-ink-faint"
      />
      <input
        className="input py-1.5 pr-3 pl-9 text-[0.84rem]"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        type="search"
      />
    </label>
  );
}

function SelectFilter<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-[0.8rem] text-ink-muted">
      <span className="font-mono text-[0.68rem] uppercase text-ink-faint">{label}</span>
      <select
        className="input w-auto py-1.5 pr-8 text-[0.84rem]"
        value={value}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function CertificateDetailPanel({ id }: { id: string }) {
  const { push, notifyError } = useToast();
  const detailQuery = useQuery({
    queryKey: ["certificate", id],
    queryFn: () => api.getCertificate(id),
  });

  useEffect(() => {
    if (detailQuery.isError) notifyError(detailQuery.error);
  }, [detailQuery.isError, detailQuery.error, notifyError]);

  const copy = async (detail: CertificateDetail) => {
    await navigator.clipboard.writeText(detail.pemChain);
    push("success", "Certificate copied to clipboard");
  };

  if (detailQuery.isError) {
    return <p className="py-2 text-[0.86rem] text-err">Could not load this certificate.</p>;
  }
  const detail = detailQuery.data;
  if (!detail) {
    return (
      <div className="flex flex-col gap-2 py-1">
        <div className="skeleton" style={{ height: 16, width: 220 }} />
        <div className="skeleton" style={{ height: 100 }} />
      </div>
    );
  }

  const expiry = expiryStatus(detail.notAfter);

  return (
    <div className="flex flex-col gap-3 py-1">
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-x-6 gap-y-2 text-[0.82rem]">
        <div>
          <dt className="text-ink-faint">Not before</dt>
          <dd className="m-0">{new Date(detail.notBefore).toLocaleString()}</dd>
        </div>
        <div>
          <dt className="text-ink-faint">Not after</dt>
          <dd className="m-0 flex items-center gap-2">
            {new Date(detail.notAfter).toLocaleString()}
            {detail.status === "valid" ? <Badge tone={expiry.tone}>{expiry.label}</Badge> : null}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Account</dt>
          <dd className="m-0 truncate font-mono" title={detail.accountId}>
            <Link
              to="/accounts/$accountId"
              params={{ accountId: detail.accountId }}
              className="text-accent hover:underline"
            >
              {detail.accountId}
            </Link>
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Order</dt>
          <dd className="m-0 truncate font-mono" title={detail.orderId}>
            <Link
              to="/orders/$orderId"
              params={{ orderId: detail.orderId }}
              className="text-accent hover:underline"
            >
              {detail.orderId}
            </Link>
          </dd>
        </div>
        {detail.status === "revoked" ? (
          <div>
            <dt className="text-ink-faint">Revocation reason</dt>
            <dd className="m-0">
              {detail.revocationReason !== null
                ? (REVOCATION_REASONS[detail.revocationReason] ?? `Code ${detail.revocationReason}`)
                : "Not specified"}
            </dd>
          </div>
        ) : null}
      </dl>

      <pre className="max-h-[220px] overflow-auto rounded-lg border border-line bg-surface-2 p-3 font-mono text-[0.76rem] leading-relaxed break-all whitespace-pre-wrap">
        {detail.pemChain}
      </pre>
      <div className="flex flex-wrap gap-2.5">
        <button className="btn btn-secondary btn-sm" onClick={() => copy(detail)}>
          <IconCopy size={14} /> Copy
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={() => downloadTextFile(`${detail.serial.replace(/:/g, "")}.pem`, detail.pemChain)}
        >
          <IconDownload size={14} /> Download
        </button>
      </div>
    </div>
  );
}

type CertificateStatusFilter = "all" | Certificate["status"] | "expiring";
type CertificateSort = "newest" | "expires";

export function CertificatesCard() {
  const { notifyError, push } = useToast();
  const queryClient = useQueryClient();
  const { activities } = useLive();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<CertificateStatusFilter>("all");
  const [sort, setSort] = useState<CertificateSort>("newest");

  const certsQuery = useQuery({ queryKey: ["certificates"], queryFn: api.listCertificates });

  useEffect(() => {
    if (certsQuery.isError) notifyError(certsQuery.error);
  }, [certsQuery.isError, certsQuery.error, notifyError]);

  // Every order/challenge/finalize/revoke handler already broadcasts a
  // "certificate" activity — refetch whenever a genuinely new one shows
  // up, rather than adding a second WebSocket message shape just for
  // this page.
  const latestCertActivity = useMemo(
    () => activities.find((activity) => activity.kind === "certificate") ?? null,
    [activities],
  );
  const lastSeenTimestamp = useRef(latestCertActivity?.timestampMs ?? null);
  useEffect(() => {
    if (latestCertActivity && latestCertActivity.timestampMs !== lastSeenTimestamp.current) {
      lastSeenTimestamp.current = latestCertActivity.timestampMs;
      queryClient.invalidateQueries({ queryKey: ["certificates"] });
    }
  }, [latestCertActivity, queryClient]);

  const revokeMutation = useMutation({
    mutationFn: api.revokeCertificate,
    onSuccess: (_result, id) => {
      queryClient.setQueryData<Certificate[]>(["certificates"], (current) =>
        (current ?? []).map((cert) =>
          cert.id === id
            ? { ...cert, status: "revoked", revokedAt: new Date().toISOString() }
            : cert,
        ),
      );
      queryClient.invalidateQueries({ queryKey: ["certificate", id] });
      push("info", "Certificate revoked");
    },
    onError: notifyError,
  });

  const revoke = (cert: Certificate, event: MouseEvent) => {
    event.stopPropagation();
    const label = cert.identifiers.join(", ") || cert.id;
    if (!window.confirm(`Revoke the certificate for ${label}? This cannot be undone.`)) return;
    revokeMutation.mutate(cert.id);
  };

  const certificates = useMemo(() => {
    const rows = certsQuery.data ?? [];
    return rows
      .filter((cert) => {
        const expiry = expiryStatus(cert.notAfter);
        const statusMatches =
          status === "all" ||
          cert.status === status ||
          (status === "expiring" && cert.status === "valid" && expiry.tone !== "ok");
        return (
          statusMatches &&
          matchesSearch([cert.id, cert.orderId, cert.serial, ...cert.identifiers], search)
        );
      })
      .sort((a, b) => {
        if (sort === "expires") {
          return new Date(a.notAfter).getTime() - new Date(b.notAfter).getTime();
        }
        return new Date(b.issuedAt).getTime() - new Date(a.issuedAt).getTime();
      });
  }, [certsQuery.data, search, sort, status]);
  const totalCertificates = certsQuery.data?.length ?? 0;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Certificates</h2>
        <span className="card-hint">issued by this server — search, sort, or click a row for details</span>
      </div>
      {certsQuery.data === undefined ? (
        certsQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load certificates.</p>
        ) : (
          <div className="flex flex-col gap-3 py-2">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        )
      ) : totalCertificates === 0 ? (
        <p className="py-2 text-[0.86rem] text-ink-faint">
          No certificates issued yet — they'll show up here as ACME clients finalize orders.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <SearchBox
              value={search}
              onChange={setSearch}
              placeholder="Search domain, serial, or order"
            />
            <SelectFilter
              label="Status"
              value={status}
              onChange={setStatus}
              options={[
                { value: "all", label: "All" },
                { value: "valid", label: "Valid" },
                { value: "revoked", label: "Revoked" },
                { value: "expiring", label: "Expiring soon" },
              ]}
            />
            <SelectFilter
              label="Sort"
              value={sort}
              onChange={setSort}
              options={[
                { value: "newest", label: "Newest" },
                { value: "expires", label: "Expires first" },
              ]}
            />
            <span className="ml-auto font-mono text-[0.72rem] text-ink-faint">
              {certificates.length} / {totalCertificates}
            </span>
          </div>
          {certificates.length === 0 ? (
            <p className="py-2 text-[0.86rem] text-ink-faint">No certificates match these filters.</p>
          ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full min-w-[760px] border-collapse text-sm">
            <thead>
              <tr>
                <th className={TH} />
                <th className={TH}>Identifiers</th>
                <th className={TH}>Status</th>
                <th className={TH}>Serial</th>
                <th className={TH}>Account</th>
                <th className={TH}>Issued</th>
                <th className={TH}>Expires</th>
                <th className={`${TH} text-right`}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {certificates.map((cert) => {
                const expanded = expandedId === cert.id;
                return (
                  <Fragment key={cert.id}>
                    <tr
                      className="cursor-pointer border-b border-line last:border-b-0 hover:bg-surface-2"
                      onClick={() => setExpandedId(expanded ? null : cert.id)}
                      aria-expanded={expanded}
                    >
                      <td className={`${TD} w-8`}>
                        <IconChevronRight
                          size={14}
                          className={`text-ink-faint transition-transform ${expanded ? "rotate-90" : ""}`}
                        />
                      </td>
                      <td className={TD}>
                        {cert.identifiers.map((name) => (
                          <Link
                            key={name}
                            to="/certificates/$certificateId"
                            params={{ certificateId: cert.id }}
                            onClick={(event) => event.stopPropagation()}
                            className="block font-mono text-[0.82rem] text-accent hover:underline"
                          >
                            {name}
                          </Link>
                        ))}
                      </td>
                      <td className={TD}>
                        <Badge tone={cert.status === "valid" ? "ok" : "err"} dot>
                          {cert.status}
                        </Badge>
                      </td>
                      <td className={`${TD} font-mono text-[0.78rem] text-ink-faint`}>
                        {cert.serial}
                      </td>
                      <td className={TD}>
                        <Link
                          to="/accounts/$accountId"
                          params={{ accountId: cert.accountId }}
                          onClick={(event) => event.stopPropagation()}
                          className="block max-w-[150px] truncate font-mono text-[0.78rem] text-accent hover:underline"
                          title={cert.accountId}
                        >
                          {cert.accountId}
                        </Link>
                      </td>
                      <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                        {new Date(cert.issuedAt).toLocaleString()}
                      </td>
                      <td className={TD}>
                        <Badge tone={expiryStatus(cert.notAfter).tone}>
                          {expiryStatus(cert.notAfter).label}
                        </Badge>
                      </td>
                      <td className={`${TD} text-right`}>
                        {cert.status === "valid" ? (
                          <button
                            className="icon-btn danger"
                            onClick={(event) => revoke(cert, event)}
                            disabled={revokeMutation.isPending}
                            aria-label="Revoke certificate"
                            title="Revoke certificate"
                          >
                            <IconTrash size={16} />
                          </button>
                        ) : (
                          <span className="text-[0.78rem] text-ink-faint">
                            {cert.revokedAt ? new Date(cert.revokedAt).toLocaleString() : "—"}
                          </span>
                        )}
                      </td>
                    </tr>
                    {expanded ? (
                      <tr className="border-b border-line bg-surface-2/40 last:border-b-0">
                        <td className={TD} />
                        <td className={TD} colSpan={7}>
                          <CertificateDetailPanel id={cert.id} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
          )}
        </div>
      )}
    </section>
  );
}

function OrderDetailPanel({ order }: { order: Order }) {
  const { notifyError } = useToast();
  const detailQuery = useQuery({
    queryKey: ["order", order.id],
    queryFn: () => api.getOrder(order.id),
  });

  useEffect(() => {
    if (detailQuery.isError) notifyError(detailQuery.error);
  }, [detailQuery.isError, detailQuery.error, notifyError]);

  if (detailQuery.isError) {
    return <p className="py-2 text-[0.86rem] text-err">Could not load this order.</p>;
  }
  const detail = detailQuery.data;
  if (!detail) {
    return (
      <div className="flex flex-col gap-2 py-1">
        <div className="skeleton" style={{ height: 16, width: 220 }} />
        <div className="skeleton" style={{ height: 60 }} />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3 py-1">
      {detail.error ? (
        <div className="rounded-lg border border-err-soft bg-err-soft/40 px-3 py-2 text-[0.8rem] text-err">
          <div className="font-mono text-[0.7rem] font-semibold uppercase">{detail.error.type}</div>
          <div>{detail.error.detail}</div>
        </div>
      ) : null}
      <div className="flex flex-col gap-2">
        {detail.authorizations.map((authz) => (
          <div key={authz.id} className="rounded-lg border border-line bg-surface p-3">
            <div className="flex items-center gap-2.5">
              <span className="font-mono text-[0.82rem]">{authz.identifier}</span>
              <Badge tone={AUTHZ_STATUS_TONE[authz.status]} dot>
                {authz.status}
              </Badge>
              <span className="ml-auto font-mono text-[0.72rem] text-ink-faint">
                expires {new Date(authz.expires).toLocaleString()}
              </span>
            </div>
            <div className="mt-2 flex flex-col gap-1.5 border-t border-line pt-2">
              {authz.challenges.map((challenge) => (
                <div key={challenge.id} className="flex flex-col gap-1 text-[0.8rem]">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-ink-muted">{challenge.type}</span>
                    <Badge tone={CHALLENGE_STATUS_TONE[challenge.status]}>{challenge.status}</Badge>
                    {challenge.validatedAt ? (
                      <span className="font-mono text-[0.72rem] text-ink-faint">
                        validated {new Date(challenge.validatedAt).toLocaleString()}
                      </span>
                    ) : null}
                  </div>
                  {challenge.error ? (
                    <div className="ml-1 rounded-md border border-err-soft bg-err-soft/40 px-2.5 py-1.5 text-[0.76rem] text-err">
                      <span className="font-mono text-[0.68rem] font-semibold uppercase">
                        {challenge.error.type}
                      </span>{" "}
                      {challenge.error.detail}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

type OrderStatusFilter = "all" | OrderStatus;

export function OrdersCard() {
  const { notifyError } = useToast();
  const queryClient = useQueryClient();
  const { activities } = useLive();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<OrderStatusFilter>("all");

  const ordersQuery = useQuery({ queryKey: ["orders"], queryFn: api.listOrders });

  useEffect(() => {
    if (ordersQuery.isError) notifyError(ordersQuery.error);
  }, [ordersQuery.isError, ordersQuery.error, notifyError]);

  // Orders change on the same lifecycle events certificates do (new order,
  // challenge validated, finalize, revoke) — reuse the "certificate"
  // activity feed rather than adding another WebSocket message shape.
  const latestActivity = useMemo(
    () => activities.find((activity) => activity.kind === "certificate") ?? null,
    [activities],
  );
  const lastSeenTimestamp = useRef(latestActivity?.timestampMs ?? null);
  useEffect(() => {
    if (latestActivity && latestActivity.timestampMs !== lastSeenTimestamp.current) {
      lastSeenTimestamp.current = latestActivity.timestampMs;
      queryClient.invalidateQueries({ queryKey: ["orders"] });
    }
  }, [latestActivity, queryClient]);

  const orders = useMemo(() => {
    const rows = ordersQuery.data ?? [];
    return rows.filter(
      (order) =>
        (status === "all" || order.status === status) &&
        matchesSearch(
          [order.id, order.accountId, order.certificateId ?? "", ...order.identifiers],
          search,
        ),
    );
  }, [ordersQuery.data, search, status]);
  const totalOrders = ordersQuery.data?.length ?? 0;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Orders</h2>
        <span className="card-hint">every order this server has seen — click a row for challenge details</span>
      </div>
      {ordersQuery.data === undefined ? (
        ordersQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load orders.</p>
        ) : (
          <div className="flex flex-col gap-3 py-2">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        )
      ) : totalOrders === 0 ? (
        <p className="py-2 text-[0.86rem] text-ink-faint">
          No orders yet — they'll show up here as soon as an ACME client requests one.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <SearchBox
              value={search}
              onChange={setSearch}
              placeholder="Search domain, order, or account"
            />
            <SelectFilter
              label="Status"
              value={status}
              onChange={setStatus}
              options={[
                { value: "all", label: "All" },
                { value: "pending", label: "Pending" },
                { value: "ready", label: "Ready" },
                { value: "processing", label: "Processing" },
                { value: "valid", label: "Valid" },
                { value: "invalid", label: "Invalid" },
              ]}
            />
            <span className="ml-auto font-mono text-[0.72rem] text-ink-faint">
              {orders.length} / {totalOrders}
            </span>
          </div>
          {orders.length === 0 ? (
            <p className="py-2 text-[0.86rem] text-ink-faint">No orders match these filters.</p>
          ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr>
                <th className={TH} />
                <th className={TH}>Identifiers</th>
                <th className={TH}>Status</th>
                <th className={TH}>Created</th>
                <th className={TH}>Expires</th>
                <th className={TH}>Certificate</th>
              </tr>
            </thead>
            <tbody>
              {orders.map((order) => {
                const expanded = expandedId === order.id;
                return (
                  <Fragment key={order.id}>
                    <tr
                      className="cursor-pointer border-b border-line last:border-b-0 hover:bg-surface-2"
                      onClick={() => setExpandedId(expanded ? null : order.id)}
                      aria-expanded={expanded}
                    >
                      <td className={`${TD} w-8`}>
                        <IconChevronRight
                          size={14}
                          className={`text-ink-faint transition-transform ${expanded ? "rotate-90" : ""}`}
                        />
                      </td>
                      <td className={TD}>
                        {order.identifiers.map((name) => (
                          <div key={name} className="font-mono text-[0.82rem]">
                            {name}
                          </div>
                        ))}
                      </td>
                      <td className={TD}>
                        <Badge tone={ORDER_STATUS_TONE[order.status]} dot>
                          {order.status}
                        </Badge>
                      </td>
                      <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                        {new Date(order.createdAt).toLocaleString()}
                      </td>
                      <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                        {new Date(order.expires).toLocaleString()}
                      </td>
                      <td className={`${TD} font-mono text-[0.78rem] text-ink-faint`}>
                        {order.certificateId ? (
                          <Link
                            to="/certificates/$certificateId"
                            params={{ certificateId: order.certificateId }}
                            onClick={(event) => event.stopPropagation()}
                            className="text-accent hover:underline"
                          >
                            {order.certificateId}
                          </Link>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                    {expanded ? (
                      <tr className="border-b border-line bg-surface-2/40 last:border-b-0">
                        <td className={TD} />
                        <td className={TD} colSpan={5}>
                          <OrderDetailPanel order={order} />
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
          )}
        </div>
      )}
    </section>
  );
}

type AccountStatusFilter = "all" | "valid" | "deactivated";

export function AccountsCard() {
  const { notifyError } = useToast();
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<AccountStatusFilter>("all");
  const accountsQuery = useQuery({ queryKey: ["accounts"], queryFn: api.listAccounts });

  useEffect(() => {
    if (accountsQuery.isError) notifyError(accountsQuery.error);
  }, [accountsQuery.isError, accountsQuery.error, notifyError]);

  const accounts = useMemo(() => {
    const rows = accountsQuery.data ?? [];
    return rows.filter(
      (account) =>
        (status === "all" || account.status === status) &&
        matchesSearch([account.id, account.jwkThumbprint, ...account.contact], search),
    );
  }, [accountsQuery.data, search, status]);
  const totalAccounts = accountsQuery.data?.length ?? 0;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Accounts</h2>
        <span className="card-hint">ACME accounts registered with this server</span>
      </div>
      {accountsQuery.data === undefined ? (
        accountsQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load accounts.</p>
        ) : (
          <div className="flex flex-col gap-3 py-2">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        )
      ) : totalAccounts === 0 ? (
        <p className="py-2 text-[0.86rem] text-ink-faint">
          No accounts yet — they'll show up here as soon as an ACME client registers.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <SearchBox
              value={search}
              onChange={setSearch}
              placeholder="Search account, thumbprint, or contact"
            />
            <SelectFilter
              label="Status"
              value={status}
              onChange={setStatus}
              options={[
                { value: "all", label: "All" },
                { value: "valid", label: "Valid" },
                { value: "deactivated", label: "Deactivated" },
              ]}
            />
            <span className="ml-auto font-mono text-[0.72rem] text-ink-faint">
              {accounts.length} / {totalAccounts}
            </span>
          </div>
          {accounts.length === 0 ? (
            <p className="py-2 text-[0.86rem] text-ink-faint">No accounts match these filters.</p>
          ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr>
                <th className={TH}>Id</th>
                <th className={TH}>Thumbprint</th>
                <th className={TH}>Status</th>
                <th className={TH}>Contact</th>
                <th className={TH}>Created</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((account: Account) => (
                <tr key={account.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
                  <td className={TD}>
                    <Link
                      to="/accounts/$accountId"
                      params={{ accountId: account.id }}
                      className="block max-w-[160px] truncate font-mono text-[0.78rem] text-accent hover:underline"
                      title={account.id}
                    >
                      {account.id}
                    </Link>
                  </td>
                  <td className={TD}>
                    <CopyableId value={account.jwkThumbprint} />
                  </td>
                  <td className={TD}>
                    <Badge tone={account.status === "valid" ? "ok" : "neutral"} dot>
                      {account.status}
                    </Badge>
                  </td>
                  <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                    {account.contact.length > 0 ? account.contact.join(", ") : "—"}
                  </td>
                  <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                    {new Date(account.createdAt).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
          )}
        </div>
      )}
    </section>
  );
}

export default function CertificatesPage() {
  return (
    <div className="flex flex-col gap-4">
      <CertificatesCard />
    </div>
  );
}
