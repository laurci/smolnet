import { useMutation, useQuery } from "@tanstack/react-query";

async function state(code: string) {
  const response = await fetch(`/api/connect/${encodeURIComponent(code)}`);

  if (!response.ok) throw new Error("unknown code");

  return (await response.json()) as { pending: boolean };
}

async function approve(code: string) {
  const response = await fetch(`/api/connect/${encodeURIComponent(code)}/approve`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({}),
  });

  if (!response.ok) throw new Error(await response.text());
}

export function Activate() {
  const code = new URLSearchParams(window.location.search).get("code") ?? "";

  const status = useQuery({
    queryKey: ["connect", code],
    queryFn: () => state(code),
    enabled: code.length > 0,
    retry: false,
  });

  const confirm = useMutation({
    mutationFn: () => approve(code),
    onSuccess: () => status.refetch(),
  });

  if (!code) {
    return <div className="empty">No code in the link.</div>;
  }

  if (status.isPending) return <div className="meta">checking…</div>;

  if (status.error) {
    return <div className="empty">That code is unknown or has expired.</div>;
  }

  if (!status.data.pending || confirm.isSuccess) {
    return (
      <div className="secret">
        <strong>Machine connected.</strong>
        <div className="meta" style={{ marginTop: "0.5rem" }}>
          You can close this tab — the terminal has picked it up.
        </div>
      </div>
    );
  }

  return (
    <>
      <h2>Connect a machine</h2>
      <p className="meta">
        A terminal is asking to join your network. Check the code matches what it printed.
      </p>

      <div className="secret">
        <code style={{ fontSize: "1.6rem", letterSpacing: "0.15em" }}>{code}</code>
      </div>

      <div className="row">
        <button onClick={() => confirm.mutate()} disabled={confirm.isPending}>
          {confirm.isPending ? "Connecting…" : "Connect it"}
        </button>
      </div>

      {confirm.error && <p className="meta">{String(confirm.error)}</p>}
    </>
  );
}
