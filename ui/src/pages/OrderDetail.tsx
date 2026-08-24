import { Link, useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import Badge from "../components/Badge";
import { useToast } from "../context/ToastContext";
import { IconCheckCircle, IconClock, IconFileText, IconShield, IconXCircle } from "../icons";
import {
  api,
  type AuthorizationInfo,
  type ChallengeInfo,
  type OrderDetail,
  type OrderStatus,
} from "../lib/api";

type Tone = "neutral" | "accent" | "ok" | "warn" | "err" | "info";

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

function TimelineStep({
  done,
  current,
  failed,
  label,
  detail,
}: {
  done?: boolean;
  current?: boolean;
  failed?: boolean;
  label: string;
  detail: string;
}) {
  const icon = failed ? (
    <IconXCircle size={17} />
  ) : done ? (
    <IconCheckCircle size={17} />
  ) : (
    <IconClock size={17} />
  );
  const tone = failed ? "text-err" : done ? "text-ok" : current ? "text-info" : "text-ink-faint";
  return (
    <li className="flex gap-3 border-b border-line py-3 last:border-b-0">
      <span className={`mt-0.5 ${tone}`}>{icon}</span>
      <div className="min-w-0">
        <div className="text-sm font-medium">{label}</div>
        <div className="text-[0.8rem] text-ink-faint">{detail}</div>
      </div>
    </li>
  );
}

function orderTimeline(order: OrderDetail) {
  const allAuthzValid = order.authorizations.length > 0 && order.authorizations.every((a) => a.status === "valid");
  const anyChallengeProcessing = order.authorizations.some((authz) =>
    authz.challenges.some((challenge) => challenge.status === "processing"),
  );
  const issued = order.status === "valid" && Boolean(order.certificateId);
  const failed = order.status === "invalid";
  return [
    {
      label: "Order created",
      detail: new Date(order.createdAt).toLocaleString(),
      done: true,
    },
    {
      label: "Authorizations",
      detail: allAuthzValid ? "All identifiers authorized" : "Waiting for identifier authorization",
      done: allAuthzValid,
      current: !allAuthzValid && !failed,
      failed,
    },
    {
      label: "Challenge validation",
      detail: anyChallengeProcessing
        ? "Validation in progress"
        : allAuthzValid
          ? "Challenge validation complete"
          : "No successful challenge yet",
      done: allAuthzValid,
      current: anyChallengeProcessing,
      failed,
    },
    {
      label: "Certificate issued",
      detail: order.certificateId ?? "No certificate issued yet",
      done: issued,
      current: order.status === "ready" || order.status === "processing",
      failed,
    },
  ];
}

export default function OrderDetailPage() {
  const { orderId } = useParams({ from: "/orders/$orderId" });
  const { notifyError } = useToast();
  const orderQuery = useQuery({ queryKey: ["order", orderId], queryFn: () => api.getOrder(orderId) });

  useEffect(() => {
    if (orderQuery.isError) notifyError(orderQuery.error);
  }, [orderQuery.isError, orderQuery.error, notifyError]);

  const order = orderQuery.data;

  return (
    <div className="flex flex-col gap-4">
      <section className="card">
        <div className="card-head">
          <h2>Order Detail</h2>
          <span className="card-hint">lifecycle, authorizations, and challenge results</span>
        </div>
        {orderQuery.isError ? (
          <p className="py-2 text-[0.86rem] text-err">Could not load this order.</p>
        ) : !order ? (
          <div className="flex flex-col gap-3">
            <div className="skeleton" />
            <div className="skeleton" />
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-[repeat(auto-fit,minmax(210px,1fr))] gap-x-6 gap-y-2 text-[0.84rem]">
              <div>
                <dt className="text-ink-faint">Status</dt>
                <dd className="m-0">
                  <Badge tone={ORDER_STATUS_TONE[order.status]} dot>{order.status}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Account</dt>
                <dd className="m-0 truncate font-mono">
                  <Link to="/accounts/$accountId" params={{ accountId: order.accountId }} className="text-accent hover:underline">
                    {order.accountId}
                  </Link>
                </dd>
              </div>
              <div>
                <dt className="text-ink-faint">Expires</dt>
                <dd className="m-0">{new Date(order.expires).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-ink-faint">Issued certificate</dt>
                <dd className="m-0 truncate font-mono">
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
                </dd>
              </div>
            </div>

            <div className="rounded-lg border border-line bg-surface-2 p-3">
              <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
                <IconFileText size={16} /> Timeline
              </div>
              <ol>
                {orderTimeline(order).map((step) => (
                  <TimelineStep key={step.label} {...step} />
                ))}
              </ol>
            </div>

            {order.error ? (
              <div className="rounded-lg border border-err-soft bg-err-soft/40 px-3 py-2 text-[0.82rem] text-err">
                <div className="font-mono text-[0.7rem] font-semibold uppercase">{order.error.type}</div>
                <div>{order.error.detail}</div>
              </div>
            ) : null}

            <div className="flex flex-col gap-3">
              {order.authorizations.map((authz) => (
                <section key={authz.id} className="rounded-lg border border-line bg-surface p-3">
                  <div className="mb-2 flex flex-wrap items-center gap-2.5">
                    <span className="font-mono text-[0.86rem]">{authz.identifier}</span>
                    <Badge tone={AUTHZ_STATUS_TONE[authz.status]} dot>{authz.status}</Badge>
                    <span className="ml-auto font-mono text-[0.72rem] text-ink-faint">
                      expires {new Date(authz.expires).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex flex-col gap-2 border-t border-line pt-2">
                    {authz.challenges.map((challenge, index) => (
                      <div key={challenge.id} className="rounded-lg bg-surface-2 px-3 py-2 text-[0.82rem]">
                        <div className="mb-1 flex flex-wrap items-center gap-2.5">
                          <IconShield size={15} className="text-ink-faint" />
                          <span className="font-mono">Attempt {index + 1}</span>
                          <span className="font-mono text-ink-muted">{challenge.type}</span>
                          <Badge tone={CHALLENGE_STATUS_TONE[challenge.status]}>{challenge.status}</Badge>
                          {challenge.validatedAt ? (
                            <span className="font-mono text-[0.72rem] text-ink-faint">
                              validated {new Date(challenge.validatedAt).toLocaleString()}
                            </span>
                          ) : null}
                        </div>
                        {challenge.error ? (
                          <div className="rounded-md border border-err-soft bg-err-soft/40 px-2.5 py-1.5 text-[0.76rem] text-err">
                            <span className="font-mono text-[0.68rem] font-semibold uppercase">
                              {challenge.error.type}
                            </span>{" "}
                            {challenge.error.detail}
                          </div>
                        ) : (
                          <p className="m-0 text-[0.76rem] text-ink-faint">No error recorded.</p>
                        )}
                      </div>
                    ))}
                  </div>
                </section>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
