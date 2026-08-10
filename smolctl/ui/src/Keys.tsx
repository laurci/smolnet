import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "./api";

export function Keys() {
  const queries = useQueryClient();
  const [label, setLabel] = useState("");
  const [issued, setIssued] = useState<string | null>(null);

  const { data, isPending } = useQuery({ queryKey: ["keys"], queryFn: api.keys });

  const create = useMutation({
    mutationFn: () => api.createKey(label),
    onSuccess: (key) => {
      setIssued(key.secret);
      setLabel("");
      queries.invalidateQueries({ queryKey: ["keys"] });
    },
  });

  const revoke = useMutation({
    mutationFn: api.revokeKey,
    onSuccess: () => queries.invalidateQueries({ queryKey: ["keys"] }),
  });

  const keys = data ?? [];

  return (
    <>
      <p className="meta">
        Keys are for programs embedding the library. Machines connected with{" "}
        <code>smol login</code> manage their own session and are not listed here.
      </p>

      <h2>New auth key</h2>
      <div className="row">
        <input
          value={label}
          placeholder="what is it for?"
          onChange={(event) => setLabel(event.target.value)}
        />
        <button onClick={() => create.mutate()} disabled={create.isPending}>
          Create
        </button>
      </div>

      {issued && (
        <div className="secret">
          <div className="meta">
            Copy this now — it is stored hashed and will never be shown again.
          </div>
          <code>{issued}</code>
          <div className="row" style={{ marginTop: "0.75rem" }}>
            <button onClick={() => navigator.clipboard?.writeText(issued)}>Copy</button>
            <button onClick={() => setIssued(null)}>Done</button>
          </div>
        </div>
      )}

      <h2>Keys</h2>
      {isPending ? (
        <div className="meta">loading…</div>
      ) : keys.length === 0 ? (
        <div className="empty">No auth keys yet.</div>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Label</th>
              <th>Bound to</th>
              <th>State</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key.id}>
                <td>{key.label ?? <span className="meta">unlabelled</span>}</td>
                <td className="mono meta">
                  {key.device ? key.device.slice(0, 8) : "not used yet"}
                </td>
                <td>
                  {key.revoked ? <span className="meta">revoked</span> : "active"}
                </td>
                <td style={{ textAlign: "right" }}>
                  {!key.revoked && (
                    <button
                      onClick={() => revoke.mutate(key.id)}
                      disabled={revoke.isPending}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
