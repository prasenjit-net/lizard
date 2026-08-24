import { Link, useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import type { ReactNode } from "react";
import Badge from "../components/Badge";
import CertificateAttributes from "../components/CertificateAttributes";
import { useToast } from "../context/ToastContext";
import { IconCopy, IconDownload } from "../icons";
import { api, type CertificateDetail } from "../lib/api";

const EXPIRY_WARNING_DAYS = 30;

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

function downloadTextFile(filename: string, contents: string) {
  const blob = new Blob([contents], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function expiryStatus(notAfter: string): { tone: "ok" | "warn" | "err"; label: string } {
  const daysLeft = (new Date(notAfter).getTime() - Date.now()) / 86_400_000;
  if (daysLeft < 0) return { tone: "err", label: "Expired" };
  if (daysLeft <= EXPIRY_WARNING_DAYS) return { tone: "warn", label: `Expires in ${Math.ceil(daysLeft)}d` };
  return { tone: "ok", label: `Expires in ${Math.ceil(daysLeft)}d` };
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-ink-faint">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

function CertificateContent({ detail }: { detail: CertificateDetail }) {
  const { push } = useToast();
  const expiry = expiryStatus(detail.notAfter);
  const copy = async () => {
    await navigator.clipboard.writeText(detail.pemChain);
    push("success", "Certificate copied to clipboard");
  };

  return (
    <div className="flex flex-col gap-4">
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-x-6 gap-y-3 text-[0.84rem]">
        <DetailRow label="Status">
          <Badge tone={detail.status === "valid" ? expiry.tone : "err"} dot>
            {detail.status === "valid" ? expiry.label : "revoked"}
          </Badge>
        </DetailRow>
        <DetailRow label="Serial">
          <code>{detail.serial}</code>
        </DetailRow>
        <DetailRow label="Identifiers">
          <div className="flex flex-col gap-1">
            {detail.identifiers.map((identifier) => (
              <code key={identifier}>{identifier}</code>
            ))}
          </div>
        </DetailRow>
        <DetailRow label="Account">
          <Link to="/accounts/$accountId" params={{ accountId: detail.accountId }} className="font-mono text-accent hover:underline">
            {detail.accountId}
          </Link>
        </DetailRow>
        <DetailRow label="Order">
          <Link to="/orders/$orderId" params={{ orderId: detail.orderId }} className="font-mono text-accent hover:underline">
            {detail.orderId}
          </Link>
        </DetailRow>
        <DetailRow label="Not before">{new Date(detail.notBefore).toLocaleString()}</DetailRow>
        <DetailRow label="Not after">{new Date(detail.notAfter).toLocaleString()}</DetailRow>
        <DetailRow label="Issued">{new Date(detail.issuedAt).toLocaleString()}</DetailRow>
        {detail.revokedAt ? (
          <DetailRow label="Revoked">{new Date(detail.revokedAt).toLocaleString()}</DetailRow>
        ) : null}
        {detail.status === "revoked" ? (
          <DetailRow label="Revocation reason">
            {detail.revocationReason !== null
              ? (REVOCATION_REASONS[detail.revocationReason] ?? `Code ${detail.revocationReason}`)
              : "Not specified"}
          </DetailRow>
        ) : null}
      </dl>

      <section className="rounded-lg border border-line bg-surface-2 p-3">
        <div className="mb-2 text-sm font-semibold">X.509 attributes</div>
        <CertificateAttributes attributes={detail.attributes} />
      </section>

      <section className="rounded-lg border border-line bg-surface-2 p-3">
        <div className="mb-2 text-sm font-semibold">PEM chain</div>
        <pre className="max-h-[360px] overflow-auto rounded-lg border border-line bg-surface p-3 font-mono text-[0.76rem] leading-relaxed break-all whitespace-pre-wrap">
          {detail.pemChain}
        </pre>
        <div className="mt-3 flex flex-wrap gap-2.5">
          <button className="btn btn-secondary btn-sm" onClick={copy}>
            <IconCopy size={14} /> Copy
          </button>
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => downloadTextFile(`${detail.serial.replace(/:/g, "")}.pem`, detail.pemChain)}
          >
            <IconDownload size={14} /> Download
          </button>
        </div>
      </section>
    </div>
  );
}

export default function CertificateDetailPage() {
  const { certificateId } = useParams({ from: "/certificates/$certificateId" });
  const { notifyError } = useToast();
  const certQuery = useQuery({
    queryKey: ["certificate", certificateId],
    queryFn: () => api.getCertificate(certificateId),
  });

  useEffect(() => {
    if (certQuery.isError) notifyError(certQuery.error);
  }, [certQuery.isError, certQuery.error, notifyError]);

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="card-head">
          <h2>Certificate Detail</h2>
          <span className="card-hint">validity, ownership, identifiers, and PEM chain</span>
        </div>
        {certQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load this certificate.</p>
        ) : certQuery.data ? (
          <CertificateContent detail={certQuery.data} />
        ) : (
          <div className="flex flex-col gap-3">
            <div className="skeleton" />
            <div className="skeleton" />
            <div className="skeleton" style={{ height: 180 }} />
          </div>
        )}
      </section>
    </div>
  );
}
