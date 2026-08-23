// The CA admin view: the root certificate (for trust-store installation)
// plus every certificate this server has issued, with a revoke action and
// a click-to-expand detail row. Follows the same useQuery/useMutation-
// patches-the-cache pattern as TasksCard, and rides the existing /ws
// activity feed for live updates — order/challenge/finalize handlers
// already broadcast a "certificate" activity on every lifecycle event, so
// this just watches for those rather than needing its own WebSocket
// message type.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import Badge from "../components/Badge";
import { useLive } from "../context/LiveContext";
import { useToast } from "../context/ToastContext";
import {
  IconChevronRight,
  IconCopy,
  IconDownload,
  IconTrash,
} from "../icons";
import { api, type Certificate, type CertificateDetail } from "../lib/api";

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

function downloadTextFile(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function CaRootCard() {
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
            {detail.accountId}
          </dd>
        </div>
        <div>
          <dt className="text-ink-faint">Order</dt>
          <dd className="m-0 truncate font-mono" title={detail.orderId}>
            {detail.orderId}
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

function CertificatesCard() {
  const { notifyError, push } = useToast();
  const queryClient = useQueryClient();
  const { activities } = useLive();
  const [expandedId, setExpandedId] = useState<string | null>(null);

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

  const certificates = certsQuery.data;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Certificates</h2>
        <span className="card-hint">issued by this server — click a row for details</span>
      </div>
      {certificates === undefined ? (
        certsQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load certificates.</p>
        ) : (
          <div className="flex flex-col gap-3 py-2">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        )
      ) : certificates.length === 0 ? (
        <p className="py-2 text-[0.86rem] text-ink-faint">
          No certificates issued yet — they'll show up here as ACME clients finalize orders.
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr>
                <th className={TH} />
                <th className={TH}>Identifiers</th>
                <th className={TH}>Status</th>
                <th className={TH}>Serial</th>
                <th className={TH}>Issued</th>
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
                          <div key={name} className="font-mono text-[0.82rem]">
                            {name}
                          </div>
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
                      <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                        {new Date(cert.issuedAt).toLocaleString()}
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
                        <td className={TD} colSpan={5}>
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
    </section>
  );
}

export default function CertificatesPage() {
  return (
    <div className="flex flex-col gap-4">
      <CaRootCard />
      <CertificatesCard />
    </div>
  );
}
