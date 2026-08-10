-- Identity is the device id. Everything a connection carries — the mesh node,
-- hostname, version, presence — is mutable state hanging off that identity, and
-- is deliberately unconstrained: a device reconnects as a new mesh node every
-- time it starts, so a node is never an identifier.

CREATE TABLE users (
    id          TEXT PRIMARY KEY,
    subject     TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    name        TEXT,
    created_at  INTEGER NOT NULL
);

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    owner       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE connects (
    code        TEXT PRIMARY KEY,
    secret      TEXT NOT NULL,
    owner       TEXT REFERENCES users(id) ON DELETE CASCADE,
    issued      TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE networks (
    id          TEXT PRIMARY KEY,
    owner       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subnet      TEXT NOT NULL,
    prefix      INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    owner       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    network     TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    name        TEXT,
    ip          TEXT NOT NULL,
    ephemeral   INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,

    node        TEXT,
    hostname    TEXT,
    os          TEXT,
    version     TEXT,
    online      INTEGER NOT NULL DEFAULT 0,
    last_seen   INTEGER,

    UNIQUE (network, ip)
);

CREATE UNIQUE INDEX devices_by_name ON devices(network, name) WHERE name IS NOT NULL;

CREATE TABLE auth_keys (
    id          TEXT PRIMARY KEY,
    digest      TEXT NOT NULL UNIQUE,
    owner       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    network     TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL DEFAULT 'key',
    label       TEXT,
    device      TEXT REFERENCES devices(id) ON DELETE SET NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX sessions_by_owner ON sessions(owner);
CREATE INDEX networks_by_owner ON networks(owner);
CREATE INDEX devices_by_owner ON devices(owner);
CREATE INDEX keys_by_owner ON auth_keys(owner, kind);
