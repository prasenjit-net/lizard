import type { ReactNode } from "react";
import type { CertAttributes } from "../lib/api";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-ink-faint">{label}</dt>
      <dd className="m-0 min-w-0 [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

function DetailBlock({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-surface p-3">
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function ValueList({ values, empty = "Not present" }: { values: string[]; empty?: string }) {
  if (values.length === 0) return <span className="text-ink-faint">{empty}</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {values.map((value) => (
        <code key={value}>{value}</code>
      ))}
    </div>
  );
}

export default function CertificateAttributes({ attributes }: { attributes: CertAttributes | null }) {
  if (!attributes) {
    return <p className="py-2 text-[0.82rem] text-ink-faint">Certificate attributes could not be parsed.</p>;
  }
  const parsed = attributes.parsedExtensions;

  return (
    <div className="flex flex-col gap-3">
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-x-6 gap-y-3 text-[0.84rem]">
        <Field label="Subject DN">{attributes.subject}</Field>
        <Field label="Issuer DN">{attributes.issuer}</Field>
        <Field label="Version">{attributes.version}</Field>
        <Field label="Serial">{attributes.serial}</Field>
        <Field label="Not before">{attributes.notBefore}</Field>
        <Field label="Not after">{attributes.notAfter}</Field>
        <Field label="Signature algorithm">{attributes.signatureAlgorithm}</Field>
        <Field label="Public key algorithm">{attributes.publicKeyAlgorithm}</Field>
        <Field label="Subject alternative names">
          <ValueList values={attributes.subjectAltNames} empty="—" />
        </Field>
      </dl>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
        <DetailBlock title="Authority Key Identifier">
          {parsed.authorityKeyIdentifier ? (
            <dl className="grid gap-2 text-[0.82rem]">
              <Field label="Key identifier">{parsed.authorityKeyIdentifier.keyIdentifier ?? "—"}</Field>
              <Field label="Authority cert issuer">
                <ValueList values={parsed.authorityKeyIdentifier.authorityCertIssuer} />
              </Field>
              <Field label="Authority cert serial">
                {parsed.authorityKeyIdentifier.authorityCertSerial ?? "—"}
              </Field>
            </dl>
          ) : (
            <p className="m-0 text-[0.82rem] text-ink-faint">Not present.</p>
          )}
        </DetailBlock>

        <DetailBlock title="Subject Alternative Name">
          {parsed.subjectAlternativeName ? (
            <ValueList values={parsed.subjectAlternativeName.names} />
          ) : (
            <p className="m-0 text-[0.82rem] text-ink-faint">Not present.</p>
          )}
        </DetailBlock>

        <DetailBlock title="Key Usage">
          {parsed.keyUsage ? (
            <div className="flex flex-col gap-2">
              <ValueList values={parsed.keyUsage.flags} />
              <dl className="grid grid-cols-2 gap-2 text-[0.78rem] text-ink-muted">
                <Field label="Digital signature">{parsed.keyUsage.digitalSignature ? "yes" : "no"}</Field>
                <Field label="Key encipherment">{parsed.keyUsage.keyEncipherment ? "yes" : "no"}</Field>
                <Field label="Certificate signing">{parsed.keyUsage.keyCertSign ? "yes" : "no"}</Field>
                <Field label="CRL signing">{parsed.keyUsage.crlSign ? "yes" : "no"}</Field>
              </dl>
            </div>
          ) : (
            <p className="m-0 text-[0.82rem] text-ink-faint">Not present.</p>
          )}
        </DetailBlock>

        <DetailBlock title="Extended Key Usage">
          {parsed.extendedKeyUsage ? (
            <div className="flex flex-col gap-2">
              <ValueList values={parsed.extendedKeyUsage.usages} />
              <dl className="grid grid-cols-2 gap-2 text-[0.78rem] text-ink-muted">
                <Field label="Server auth">{parsed.extendedKeyUsage.serverAuth ? "yes" : "no"}</Field>
                <Field label="Client auth">{parsed.extendedKeyUsage.clientAuth ? "yes" : "no"}</Field>
                <Field label="Code signing">{parsed.extendedKeyUsage.codeSigning ? "yes" : "no"}</Field>
                <Field label="OCSP signing">{parsed.extendedKeyUsage.ocspSigning ? "yes" : "no"}</Field>
              </dl>
            </div>
          ) : (
            <p className="m-0 text-[0.82rem] text-ink-faint">Not present.</p>
          )}
        </DetailBlock>

        <DetailBlock title="Subject Key Identifier">
          {parsed.subjectKeyIdentifier ? (
            <code>{parsed.subjectKeyIdentifier}</code>
          ) : (
            <p className="m-0 text-[0.82rem] text-ink-faint">Not present.</p>
          )}
        </DetailBlock>

        <DetailBlock title="Basic Constraints">
          {parsed.basicConstraints ? (
            <dl className="grid gap-2 text-[0.82rem]">
              <Field label="CA">{parsed.basicConstraints.ca ? "yes" : "no"}</Field>
              <Field label="Path length constraint">
                {parsed.basicConstraints.pathLenConstraint ?? "none"}
              </Field>
            </dl>
          ) : (
            <p className="m-0 text-[0.82rem] text-ink-faint">Not present.</p>
          )}
        </DetailBlock>
      </div>

      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[680px] border-collapse text-sm">
          <thead>
            <tr>
              <th className="border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase">
                Extension
              </th>
              <th className="border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase">
                Critical
              </th>
              <th className="border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase">
                Value
              </th>
            </tr>
          </thead>
          <tbody>
            {attributes.extensions.map((extension) => (
              <tr key={extension.oid} className="border-b border-line last:border-b-0">
                <td className="px-4 py-2.5">
                  <div className="font-mono text-[0.78rem]">{extension.oid}</div>
                  <div className="text-[0.76rem] text-ink-faint">{extension.name}</div>
                </td>
                <td className="px-4 py-2.5 text-[0.82rem] text-ink-muted">
                  {extension.critical ? "yes" : "no"}
                </td>
                <td className="px-4 py-2.5 font-mono text-[0.76rem] text-ink-muted [overflow-wrap:anywhere]">
                  {extension.value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
