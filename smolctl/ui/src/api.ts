export type Me = {
  email: string;
  name: string | null;
  network: string;
  subnet: string;
};

export type Device = {
  id: string;
  name: string | null;
  hostname: string | null;
  os: string | null;
  version: string | null;
  ip: string;
  online: boolean;
  ephemeral: boolean;
  last_seen: number | null;
};

export type AuthKey = {
  id: string;
  label: string | null;
  device: string | null;
  created_at: number;
  expires_at: number | null;
  revoked: boolean;
};

export class NotSignedIn extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...init });

  if (response.status === 401) {
    throw new NotSignedIn("not signed in");
  }

  if (!response.ok) {
    throw new Error(await response.text());
  }

  return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
}

export const api = {
  me: () => request<Me>("/api/me"),
  devices: () => request<Device[]>("/api/devices"),
  keys: () => request<AuthKey[]>("/api/keys"),
  createKey: (label: string) =>
    request<{ id: string; secret: string }>("/api/keys", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: label || null }),
    }),
  revokeKey: (id: string) => request<void>(`/api/keys/${id}`, { method: "DELETE" }),
};
