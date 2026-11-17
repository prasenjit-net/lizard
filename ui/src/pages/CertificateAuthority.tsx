import { useQuery } from "@tanstack/react-query";
import Badge from "../components/Badge";
import { useConfig } from "../context/ConfigContext";
import { api } from "../lib/api";
import { CaRootCard } from "./Certificates";

function SetupRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line py-2 text-sm last:border-b-0">
      <span className="text-ink-muted">{label}</span>
      <code className="text-right [overflow-wrap:anywhere]">{value}</code>
    </div>
  );
}

/** The certificate this server serves its own HTTPS with. Shares the "ca"
 * query with CaRootCard, so it costs no extra request. */
function ServerTlsCard() {
  const caQuery = useQuery({ queryKey: ["ca"], queryFn: api.caInfo });
  const tls = caQuery.data?.serverTls;

  return (
    <section className="card">
      <div className="card-head">
        <h2>Server TLS</h2>
        <span className="card-hint">the certificate this server serves over HTTPS, issued by the root above</span>
      </div>
      {!caQuery.data ? (
        <div className="skeleton" style={{ height: 80 }} />
      ) : tls ? (
        <dl className="flex flex-col">
          <SetupRow label="Status" value="HTTPS only" />
          <div className="flex items-start justify-between gap-4 border-b border-line py-2 text-sm">
            <span className="text-ink-muted">Subject alternative names</span>
            <div className="flex flex-wrap justify-end gap-1.5">
              {tls.sans.map((san) => (
                <Badge key={san} tone="info">
                  {san}
                </Badge>
              ))}
            </div>
          </div>
          <SetupRow label="Serial" value={tls.serial} />
          <div className="flex items-center justify-between gap-4 py-2 text-sm">
            <span className="text-ink-muted">Expires</span>
            <span className="flex items-center gap-2">
              <code>{new Date(tls.notAfter).toLocaleString()}</code>
              <Badge tone={tls.renewalDue ? "warn" : "ok"} dot>
                {tls.renewalDue ? "renewal due" : "auto-renews"}
              </Badge>
            </span>
          </div>
        </dl>
      ) : (
        <p className="py-1 text-[0.86rem] text-ink-muted">
          TLS is disabled — this server is speaking plain HTTP. Set <code>[tls].enabled = true</code>{" "}
          (or pass <code>--tls</code>) to serve HTTPS with a certificate issued by this CA.
        </p>
      )}
    </section>
  );
}

export default function CertificateAuthorityPage() {
  const config = useConfig();

  return (
    <div className="flex max-w-[960px] flex-col gap-4">
      <CaRootCard />
      <ServerTlsCard />
      <section className="card">
        <div className="card-head">
          <h2>Trust Setup</h2>
          <span className="card-hint">root CA details from current server configuration</span>
        </div>
        <dl className="mb-3 flex flex-col">
          <SetupRow label="Certificate validity" value={`${config.ca.certValidityDays} days`} />
          <SetupRow label="Root CA validity" value={`${config.ca.rootValidityYears} years`} />
          <SetupRow label="ACME directory" value={`${window.location.origin}/directory`} />
        </dl>
        <div className="rounded-lg border border-info-soft bg-info-soft/40 px-3 py-2 text-[0.82rem] leading-relaxed text-info">
          Install the downloaded root certificate into the trust stores used by clients that
          consume certificates from this server.
        </div>
      </section>
    </div>
  );
}
