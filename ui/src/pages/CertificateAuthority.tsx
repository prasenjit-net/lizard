import { useConfig } from "../context/ConfigContext";
import { CaRootCard } from "./Certificates";

function SetupRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-line py-2 text-sm last:border-b-0">
      <span className="text-ink-muted">{label}</span>
      <code className="text-right [overflow-wrap:anywhere]">{value}</code>
    </div>
  );
}

export default function CertificateAuthorityPage() {
  const config = useConfig();

  return (
    <div className="flex max-w-[960px] flex-col gap-4">
      <CaRootCard />
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
