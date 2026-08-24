import { Link, useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import Badge from "../components/Badge";
import { useToast } from "../context/ToastContext";
import { api, type OrderStatus } from "../lib/api";

type Tone = "neutral" | "accent" | "ok" | "warn" | "err" | "info";

const TH =
  "border-b border-line bg-surface-2 px-4 py-2.5 text-left font-mono text-[0.68rem] font-semibold tracking-wider text-ink-faint uppercase";
const TD = "px-4 py-2.5";

const ORDER_STATUS_TONE: Record<OrderStatus, Tone> = {
  pending: "neutral",
  ready: "info",
  processing: "info",
  valid: "ok",
  invalid: "err",
};

function expiryStatus(notAfter: string): { tone: "ok" | "warn" | "err"; label: string } {
  const daysLeft = (new Date(notAfter).getTime() - Date.now()) / 86_400_000;
  if (daysLeft < 0) return { tone: "err", label: "Expired" };
  if (daysLeft <= 30) return { tone: "warn", label: `Expires in ${Math.ceil(daysLeft)}d` };
  return { tone: "ok", label: `Expires in ${Math.ceil(daysLeft)}d` };
}

export default function AccountDetailPage() {
  const { accountId } = useParams({ from: "/accounts/$accountId" });
  const { notifyError } = useToast();
  const accountsQuery = useQuery({ queryKey: ["accounts"], queryFn: api.listAccounts });
  const ordersQuery = useQuery({ queryKey: ["orders"], queryFn: api.listOrders });
  const certsQuery = useQuery({ queryKey: ["certificates"], queryFn: api.listCertificates });

  useEffect(() => {
    if (accountsQuery.isError) notifyError(accountsQuery.error);
  }, [accountsQuery.isError, accountsQuery.error, notifyError]);
  useEffect(() => {
    if (ordersQuery.isError) notifyError(ordersQuery.error);
  }, [ordersQuery.isError, ordersQuery.error, notifyError]);
  useEffect(() => {
    if (certsQuery.isError) notifyError(certsQuery.error);
  }, [certsQuery.isError, certsQuery.error, notifyError]);

  const account = accountsQuery.data?.find((entry) => entry.id === accountId);
  const accountOrders = useMemo(
    () => (ordersQuery.data ?? []).filter((order) => order.accountId === accountId),
    [accountId, ordersQuery.data],
  );
  const accountCerts = useMemo(
    () => (certsQuery.data ?? []).filter((cert) => cert.accountId === accountId),
    [accountId, certsQuery.data],
  );

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="card-head">
          <h2>Account Detail</h2>
          <span className="card-hint">registered ACME account, orders, and issued certificates</span>
        </div>
        {accountsQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load this account.</p>
        ) : accountsQuery.data === undefined ? (
          <div className="flex flex-col gap-3">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        ) : !account ? (
          <p className="py-2 text-[0.86rem] text-err">Account {accountId} does not exist.</p>
        ) : (
          <dl className="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-x-6 gap-y-3 text-[0.84rem]">
            <div>
              <dt className="text-ink-faint">Status</dt>
              <dd className="m-0">
                <Badge tone={account.status === "valid" ? "ok" : "neutral"} dot>
                  {account.status}
                </Badge>
              </dd>
            </div>
            <div>
              <dt className="text-ink-faint">Account ID</dt>
              <dd className="m-0 font-mono [overflow-wrap:anywhere]">{account.id}</dd>
            </div>
            <div>
              <dt className="text-ink-faint">JWK thumbprint</dt>
              <dd className="m-0 font-mono [overflow-wrap:anywhere]">{account.jwkThumbprint}</dd>
            </div>
            <div>
              <dt className="text-ink-faint">Contact</dt>
              <dd className="m-0">{account.contact.length > 0 ? account.contact.join(", ") : "—"}</dd>
            </div>
            <div>
              <dt className="text-ink-faint">Terms agreed</dt>
              <dd className="m-0">{account.tosAgreed ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt className="text-ink-faint">Created</dt>
              <dd className="m-0">{new Date(account.createdAt).toLocaleString()}</dd>
            </div>
          </dl>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Orders</h2>
          <span className="card-hint">all orders created by this account</span>
        </div>
        {ordersQuery.data === undefined ? (
          <div className="flex flex-col gap-3">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        ) : accountOrders.length === 0 ? (
          <p className="py-2 text-[0.86rem] text-ink-faint">No orders for this account.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-line">
            <table className="w-full min-w-[640px] border-collapse text-sm">
              <thead>
                <tr>
                  <th className={TH}>Identifiers</th>
                  <th className={TH}>Status</th>
                  <th className={TH}>Created</th>
                  <th className={TH}>Expires</th>
                  <th className={TH}>Certificate</th>
                </tr>
              </thead>
              <tbody>
                {accountOrders.map((order) => (
                  <tr key={order.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
                    <td className={TD}>
                      <Link
                        to="/orders/$orderId"
                        params={{ orderId: order.id }}
                        className="font-mono text-accent hover:underline"
                      >
                        {order.identifiers.join(", ")}
                      </Link>
                    </td>
                    <td className={TD}>
                      <Badge tone={ORDER_STATUS_TONE[order.status]} dot>{order.status}</Badge>
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
                          className="text-accent hover:underline"
                        >
                          {order.certificateId}
                        </Link>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Certificates</h2>
          <span className="card-hint">all certificates issued for this account</span>
        </div>
        {certsQuery.data === undefined ? (
          <div className="flex flex-col gap-3">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        ) : accountCerts.length === 0 ? (
          <p className="py-2 text-[0.86rem] text-ink-faint">No certificates for this account.</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-line">
            <table className="w-full min-w-[720px] border-collapse text-sm">
              <thead>
                <tr>
                  <th className={TH}>Identifiers</th>
                  <th className={TH}>Status</th>
                  <th className={TH}>Serial</th>
                  <th className={TH}>Issued</th>
                  <th className={TH}>Expires</th>
                </tr>
              </thead>
              <tbody>
                {accountCerts.map((cert) => (
                  <tr key={cert.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
                    <td className={TD}>
                      <Link
                        to="/certificates/$certificateId"
                        params={{ certificateId: cert.id }}
                        className="font-mono text-accent hover:underline"
                      >
                        {cert.identifiers.join(", ")}
                      </Link>
                    </td>
                    <td className={TD}>
                      <Badge tone={cert.status === "valid" ? "ok" : "err"} dot>{cert.status}</Badge>
                    </td>
                    <td className={`${TD} font-mono text-[0.78rem] text-ink-faint`}>{cert.serial}</td>
                    <td className={`${TD} text-[0.82rem] text-ink-muted`}>
                      {new Date(cert.issuedAt).toLocaleString()}
                    </td>
                    <td className={TD}>
                      <Badge tone={expiryStatus(cert.notAfter).tone}>{expiryStatus(cert.notAfter).label}</Badge>
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
