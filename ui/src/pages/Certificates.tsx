// The CA admin view: the root certificate (for trust-store installation)
// plus every certificate this server has issued, with a revoke action.
// Follows the same useQuery/useMutation-patches-the-cache pattern as
// TasksCard, and rides the existing /ws activity feed for live updates —
// order/challenge/finalize handlers already broadcast a "certificate"
// activity on every lifecycle event, so this just watches for those
// rather than needing its own WebSocket message type.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef } from "react";
import Badge from "../components/Badge";
import { useLive } from "../context/LiveContext";
import { useToast } from "../context/ToastContext";
import { IconCopy, IconDownload, IconTrash } from "../icons";
import { api, type Certificate } from "../lib/api";

const TH =
  "border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase";
const TD = "px-4 py-2.5";

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

function CertificatesCard() {
  const { notifyError, push } = useToast();
  const queryClient = useQueryClient();
  const { activities } = useLive();

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
      push("info", "Certificate revoked");
    },
    onError: notifyError,
  });

  const revoke = (cert: Certificate) => {
    const label = cert.identifiers.join(", ") || cert.id;
    if (!window.confirm(`Revoke the certificate for ${label}? This cannot be undone.`)) return;
    revokeMutation.mutate(cert.id);
  };

  const certificates = certsQuery.data;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Certificates</h2>
        <span className="card-hint">issued by this server</span>
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
                <th className={TH}>Identifiers</th>
                <th className={TH}>Status</th>
                <th className={TH}>Serial</th>
                <th className={TH}>Issued</th>
                <th className={`${TH} text-right`}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {certificates.map((cert) => (
                <tr key={cert.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
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
                  <td className={`${TD} font-mono text-[0.78rem] text-ink-faint`}>{cert.serial}</td>
                  <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                    {new Date(cert.issuedAt).toLocaleString()}
                  </td>
                  <td className={`${TD} text-right`}>
                    {cert.status === "valid" ? (
                      <button
                        className="icon-btn danger"
                        onClick={() => revoke(cert)}
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
              ))}
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
