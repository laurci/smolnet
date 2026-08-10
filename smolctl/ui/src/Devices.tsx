import { useQuery } from "@tanstack/react-query";

import { api, type Device } from "./api";
import { usePresence } from "./presence";

function seen(at: number | null) {
  if (!at) return "never";

  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - at);

  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;

  return `${Math.floor(seconds / 86400)}d ago`;
}

function label(device: Device) {
  return device.name ?? device.hostname ?? device.id.slice(0, 8);
}

export function Devices() {
  usePresence();

  const { data, isPending } = useQuery({ queryKey: ["devices"], queryFn: api.devices });

  if (isPending) return <div className="meta">loading…</div>;

  const devices = data ?? [];

  if (devices.length === 0) {
    return (
      <div className="empty">
        No devices yet. Run <code>smol login</code> then <code>sudo smol start</code> on a machine.
      </div>
    );
  }

  return (
    <>
      <h2>
        {devices.filter((device) => device.online).length} of {devices.length} online
      </h2>
      <table>
        <thead>
          <tr>
            <th>Device</th>
            <th>Address</th>
            <th>OS</th>
            <th>Version</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {devices.map((device) => (
            <tr key={device.id}>
              <td>
                <span className={`dot ${device.online ? "on" : "off"}`} />
                {label(device)}{" "}
                {device.ephemeral && <span className="tag">ephemeral</span>}
              </td>
              <td className="mono">{device.ip}</td>
              <td className="meta">{device.os ?? "—"}</td>
              <td className="meta mono">{device.version ?? "—"}</td>
              <td className="meta">{device.online ? "now" : seen(device.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
