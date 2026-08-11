use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tower_http::services::{ServeDir, ServeFile};

use crate::server::store::{Device, Store, User};
use crate::token::{self, Identity};

const SESSION_COOKIE: &str = "smol_session";
const SESSION_TTL: i64 = 60 * 60 * 24 * 30;
const JOIN_TOKEN_TTL: u64 = 60 * 60 * 24;

pub struct Console {
    pub store: Store,
    pub secret: Vec<u8>,
    pub client_id: String,
    pub client_secret: String,
    pub public_url: String,
    pub assets: Option<PathBuf>,
    pub presence: broadcast::Sender<Presence>,
    /// The control port's certificate, handed to a device along with its join
    /// token so it has something to pin before it dials.
    pub certificate: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Presence {
    pub device: String,
    pub name: Option<String>,
    pub hostname: Option<String>,
    pub ip: String,
    pub online: bool,
}

impl Console {
    pub fn new(
        store: Store,
        secret: Vec<u8>,
        client_id: String,
        client_secret: String,
        public_url: String,
        assets: Option<PathBuf>,
        certificate: String,
    ) -> (Arc<Console>, broadcast::Sender<Presence>) {
        let (presence, _) = broadcast::channel(256);

        let console = Arc::new(Console {
            store,
            secret,
            client_id,
            client_secret,
            public_url,
            assets,
            presence: presence.clone(),
            certificate,
        });

        (console, presence)
    }

    fn redirect_uri(&self) -> String {
        format!("{}/auth/google/callback", self.public_url.trim_end_matches('/'))
    }
}

fn session_of(headers: &HeaderMap) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;

    cookies.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;

        (name == SESSION_COOKIE).then(|| value.to_owned())
    })
}

async fn user_of(console: &Console, headers: &HeaderMap) -> Option<User> {
    let raw = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let Some(session) = session_of(headers) else {
        tracing::info!(
            cookie_header_len = raw.len(),
            cookie_names = %raw
                .split(';')
                .filter_map(|pair| pair.trim().split_once('='))
                .map(|(name, _)| name)
                .collect::<Vec<_>>()
                .join(","),
            "a request arrived with no session cookie"
        );

        return None;
    };

    match console.store.session_owner(&session).await {
        Ok(Some(user)) => Some(user),
        Ok(None) => {
            tracing::info!(session = %&session[..8.min(session.len())], "session cookie did not match a live session");
            None
        }
        Err(e) => {
            tracing::warn!("session lookup failed: {e}");
            None
        }
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "not signed in" })))
        .into_response()
}

fn failed(message: impl std::fmt::Display) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": message.to_string() })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokens {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleProfile {
    sub: String,
    email: String,
    name: Option<String>,
}

async fn sign_in(State(console): State<Arc<Console>>) -> Redirect {
    let target = format!(
        "https://accounts.google.com/o/oauth2/v2/auth\
         ?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile\
         &access_type=online&prompt=select_account",
        urlencode(&console.client_id),
        urlencode(&console.redirect_uri())
    );

    Redirect::temporary(&target)
}

fn urlencode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

async fn callback(
    State(console): State<Arc<Console>>,
    Query(query): Query<Callback>,
) -> Result<Response, Response> {
    if let Some(error) = query.error {
        return Err((StatusCode::BAD_REQUEST, format!("google refused: {error}")).into_response());
    }

    let code = query
        .code
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no authorization code").into_response())?;

    let client = reqwest::Client::new();

    let tokens: GoogleTokens = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code.as_str()),
            ("client_id", console.client_id.as_str()),
            ("client_secret", console.client_secret.as_str()),
            ("redirect_uri", &console.redirect_uri()),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| failed(format!("could not reach google: {e}")))?
        .json()
        .await
        .map_err(|e| failed(format!("google returned no token: {e}")))?;

    let profile: GoogleProfile = client
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(&tokens.access_token)
        .send()
        .await
        .map_err(|e| failed(format!("could not read the profile: {e}")))?
        .json()
        .await
        .map_err(|e| failed(format!("the profile was malformed: {e}")))?;

    let user = console
        .store
        .upsert_user(&profile.sub, &profile.email, profile.name.as_deref())
        .await
        .map_err(failed)?;

    console
        .store
        .default_network(&user.id)
        .await
        .map_err(failed)?;

    let session = console
        .store
        .open_session(&user.id, SESSION_TTL)
        .await
        .map_err(failed)?;

    let cookie = format!(
        "{SESSION_COOKIE}={session}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age={SESSION_TTL}"
    );

    Ok((
        StatusCode::SEE_OTHER,
        [(header::SET_COOKIE, cookie), (header::LOCATION, "/".to_owned())],
    )
        .into_response())
}

async fn sign_out(State(console): State<Arc<Console>>, headers: HeaderMap) -> Response {
    if let Some(session) = session_of(&headers) {
        let _ = console.store.close_session(&session).await;
    }

    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0");

    (StatusCode::SEE_OTHER, [(header::SET_COOKIE, cookie), (header::LOCATION, "/".to_owned())])
        .into_response()
}

#[derive(Serialize)]
struct Me {
    email: String,
    name: Option<String>,
    network: String,
    subnet: String,
}

async fn me(State(console): State<Arc<Console>>, headers: HeaderMap) -> Response {
    let Some(user) = user_of(&console, &headers).await else {
        return unauthorized();
    };

    match console.store.default_network(&user.id).await {
        Ok(network) => Json(Me {
            email: user.email,
            name: user.name,
            network: network.id,
            subnet: format!("{}/{}", network.subnet, network.prefix),
        })
        .into_response(),
        Err(e) => failed(e),
    }
}

#[derive(Serialize)]
struct DeviceView {
    id: String,
    name: Option<String>,
    hostname: Option<String>,
    os: Option<String>,
    version: Option<String>,
    ip: String,
    online: bool,
    ephemeral: bool,
    last_seen: Option<i64>,
}

impl From<Device> for DeviceView {
    fn from(device: Device) -> DeviceView {
        DeviceView {
            id: device.id,
            name: device.name,
            hostname: device.hostname,
            os: device.os,
            version: device.version,
            ip: device.ip.to_string(),
            online: device.online,
            ephemeral: device.ephemeral,
            last_seen: device.last_seen,
        }
    }
}

async fn devices(State(console): State<Arc<Console>>, headers: HeaderMap) -> Response {
    let Some(user) = user_of(&console, &headers).await else {
        return unauthorized();
    };

    match console.store.devices(&user.id).await {
        Ok(devices) => {
            let view: Vec<DeviceView> = devices.into_iter().map(DeviceView::from).collect();

            Json(view).into_response()
        }
        Err(e) => failed(e),
    }
}

#[derive(Serialize)]
struct KeyView {
    id: String,
    label: Option<String>,
    device: Option<String>,
    created_at: i64,
    expires_at: Option<i64>,
    revoked: bool,
}

async fn keys(State(console): State<Arc<Console>>, headers: HeaderMap) -> Response {
    let Some(user) = user_of(&console, &headers).await else {
        return unauthorized();
    };

    match console.store.keys(&user.id).await {
        Ok(keys) => {
            let view: Vec<KeyView> = keys
                .into_iter()
                .map(|key| KeyView {
                    id: key.id,
                    label: key.label,
                    device: key.device,
                    created_at: key.created_at,
                    expires_at: key.expires_at,
                    revoked: key.revoked,
                })
                .collect();

            Json(view).into_response()
        }
        Err(e) => failed(e),
    }
}

#[derive(Deserialize)]
pub struct NewKey {
    label: Option<String>,
}

async fn create_key(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Json(body): Json<NewKey>,
) -> Response {
    let Some(user) = user_of(&console, &headers).await else {
        return unauthorized();
    };

    let network = match console.store.default_network(&user.id).await {
        Ok(network) => network,
        Err(e) => return failed(e),
    };

    match console
        .store
        .mint_key(&user.id, &network.id, body.label.as_deref(), None)
        .await
    {
        Ok(minted) => Json(serde_json::json!({
            "id": minted.key.id,
            "secret": minted.secret,
            "label": minted.key.label,
        }))
        .into_response(),
        Err(e) => failed(e),
    }
}

async fn revoke_key(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = user_of(&console, &headers).await else {
        return unauthorized();
    };

    match console.store.revoke_key(&user.id, &id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => failed(e),
    }
}

#[derive(Deserialize)]
pub struct TokenRequest {
    key: Option<String>,
    device: Option<String>,
    node: String,
    name: Option<String>,
    exact: Option<bool>,
    ephemeral: Option<bool>,
}

#[derive(Deserialize)]
pub struct Verify {
    key: String,
}

async fn verify_key(State(console): State<Arc<Console>>, Json(body): Json<Verify>) -> Response {
    match console.store.key_holder(&body.key).await {
        Ok(Some(email)) => Json(serde_json::json!({ "ok": true, "account": email })).into_response(),
        Ok(None) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "that auth key is not valid" })),
        )
            .into_response(),
        Err(e) => failed(e),
    }
}

async fn issue_token(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Json(body): Json<TokenRequest>,
) -> Response {
    let node = body.node.clone();

    use crate::server::store::{Holder, Wanted};

    let holder = if let Some(key) = body.key.as_deref() {
        match console.store.key_owner(key).await {
            Ok(holder) => holder,
            Err(e) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    } else {
        let Some(user) = user_of(&console, &headers).await else {
            return unauthorized();
        };

        match console.store.default_network(&user.id).await {
            Ok(network) => Holder {
                owner: user.id,
                network: network.id,
                session: true,
                device: None,
            },
            Err(e) => return failed(e),
        }
    };

    let (owner, network) = (holder.owner.clone(), holder.network.clone());

    // A library auth key stands for exactly one device: it ignores what the
    // caller asks for and always lands on the device it is bound to. A cli
    // session speaks for the account, so it may name, reuse, or throw away as
    // many devices as it likes.
    let exact = body.exact.unwrap_or(true);
    let ephemeral = body.ephemeral.unwrap_or(false);

    let wanted = if holder.session {
        match (body.device.as_deref(), body.name.as_deref()) {
            (_, Some(name)) if ephemeral => Wanted::Named(name),
            (Some(device), Some(name)) if exact => Wanted::Rename { device, name },
            (_, Some(name)) if exact => Wanted::Named(name),
            (_, Some(name)) => Wanted::Suggested(name),
            (_, None) if ephemeral => Wanted::Throwaway,
            (Some(device), None) => Wanted::Existing(device),
            (None, None) => Wanted::Fresh,
        }
    } else {
        match holder.device.as_deref() {
            Some(device) => Wanted::Existing(device),
            None => match body.name.as_deref() {
                Some(name) => Wanted::Named(name),
                None => Wanted::Fresh,
            },
        }
    };

    let outcome = console
        .store
        .resolve_device(&owner, &network, wanted, &node)
        .await;

    let device = match outcome {
        Ok(device) => device,
        Err(e) => return failed(e),
    };

    if let Some(key) = body.key.as_deref() {
        let _ = console.store.bind_key(key, &device.id).await;
    }

    let Ok(network) = device.network.parse() else {
        return failed("the device is on a network the mesh cannot address");
    };

    let Ok(parsed) = node.parse() else {
        return (StatusCode::BAD_REQUEST, "node is not a valid mesh id").into_response();
    };

    let identity = Identity {
        network,
        node: parsed,
        device: device.id.clone(),
    };

    match token::mint(&console.secret, identity, JOIN_TOKEN_TTL) {
        Ok((jwt, claims)) => Json(serde_json::json!({
            "token": jwt,
            "device": device.id,
            "ip": device.ip.to_string(),
            "expires": claims.exp,
            // This request came over the console's own https, so it is the one
            // channel a device can learn the control port's certificate from
            // without having to trust the network it is about to dial over.
            "ca": console.certificate,
        }))
        .into_response(),
        Err(e) => failed(e),
    }
}

const CONNECT_TTL: i64 = 60 * 10;

#[derive(Deserialize)]
pub struct Claim {
    code: String,
    secret: String,
}

#[derive(Deserialize)]
pub struct Approve {
    label: Option<String>,
}

async fn start_connect(State(console): State<Arc<Console>>) -> Response {
    match console.store.start_connect(CONNECT_TTL).await {
        Ok((code, secret)) => Json(serde_json::json!({
            "code": code,
            "secret": secret,
            "url": format!("{}/activate?code={}", console.public_url.trim_end_matches('/'), code),
            "expires_in": CONNECT_TTL,
        }))
        .into_response(),
        Err(e) => failed(e),
    }
}

async fn claim_connect(
    State(console): State<Arc<Console>>,
    Json(body): Json<Claim>,
) -> Response {
    match console.store.claim_connect(&body.code, &body.secret).await {
        Ok(Some(key)) => Json(serde_json::json!({ "key": key })).into_response(),
        Ok(None) => (StatusCode::ACCEPTED, Json(serde_json::json!({ "status": "pending" })))
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "that code is unknown or expired" })),
        )
            .into_response(),
    }
}

async fn approve_connect(
    State(console): State<Arc<Console>>,
    headers: HeaderMap,
    Path(code): Path<String>,
    Json(body): Json<Approve>,
) -> Response {
    let Some(user) = user_of(&console, &headers).await else {
        return unauthorized();
    };

    match console
        .store
        .approve_connect(&code, &user.id, body.label.as_deref())
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "that code is already used or expired" })),
        )
            .into_response(),
        Err(e) => failed(e),
    }
}

async fn connect_state(
    State(console): State<Arc<Console>>,
    Path(code): Path<String>,
) -> Response {
    match console.store.pending_connect(&code).await {
        Ok(pending) => Json(serde_json::json!({ "pending": pending })).into_response(),
        Err(e) => failed(e),
    }
}

async fn events(State(console): State<Arc<Console>>, upgrade: WebSocketUpgrade) -> Response {
    let feed = console.presence.subscribe();

    upgrade.on_upgrade(move |socket| stream_presence(socket, feed))
}

async fn stream_presence(mut socket: WebSocket, mut feed: broadcast::Receiver<Presence>) {
    loop {
        tokio::select! {
            update = feed.recv() => match update {
                Ok(update) => {
                    let Ok(text) = serde_json::to_string(&update) else {
                        continue;
                    };

                    if socket.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(_)) => {}
                _ => break,
            },
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                if socket.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn never_cache(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;

    response.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );

    response
        .headers_mut()
        .insert(header::PRAGMA, axum::http::HeaderValue::from_static("no-cache"));

    response
}

pub fn router(console: Arc<Console>) -> Router {
    let api = Router::new()
        .route("/me", get(me))
        .route("/devices", get(devices))
        .route("/keys", get(keys).post(create_key))
        .route("/keys/{id}", axum::routing::delete(revoke_key))
        .route("/token", post(issue_token))
        .route("/verify", post(verify_key))
        .route("/connect", post(start_connect))
        .route("/connect/claim", post(claim_connect))
        .route("/connect/{code}", get(connect_state))
        .route("/connect/{code}/approve", post(approve_connect))
        .route("/events", get(events))
        .layer(axum::middleware::from_fn(never_cache));

    let mut app = Router::new()
        .route("/auth/google", get(sign_in))
        .route("/auth/google/callback", get(callback))
        .route("/auth/logout", post(sign_out).get(sign_out))
        .layer(axum::middleware::from_fn(never_cache))
        .nest("/api", api);

    if let Some(assets) = console.assets.clone() {
        let index = assets.join("index.html");

        app = app.fallback_service(ServeDir::new(assets).fallback(ServeFile::new(index)));
    }

    app.with_state(console)
}

pub async fn serve(console: Arc<Console>, listen: SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;

    tracing::info!(%listen, "console listening");

    axum::serve(listener, router(console)).await
}
