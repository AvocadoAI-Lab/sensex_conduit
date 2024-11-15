use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use governor::{
    clock::DefaultClock, state::{InMemoryState, NotKeyed},
    Quota,
    RateLimiter,
};
use native_tls::{Identity, TlsAcceptor};
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, io::prelude::*};
use std::{process::Command, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use uuid::Uuid;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Response {
    status: bool,
    data: String,
    session_id: String,
    timestamp: u64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    client_id: String,
    timestamp: u64,
    nonce: String,
    signature: String,
    session_id: Option<String>,
    wql_query: String,
}

#[derive(Debug)]
struct Session {
    client_id: String,
    created_at: SystemTime,
    last_activity: SystemTime,
    nonce_history: HashSet<String>,
}

struct ServerState {
    rate_limiter: RateLimiter<NotKeyed, InMemoryState, DefaultClock>,
    sessions: Mutex<HashMap<String, Session>>,
    client_keys: Mutex<HashMap<String, String>>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            rate_limiter: RateLimiter::direct(Quota::per_second(nonzero!(10u32))),
            sessions: Mutex::new(HashMap::new()),
            client_keys: Mutex::new(HashMap::new()),
        }
    }

    fn load_client_keys(&self) -> Result<()> {
        let mut keys = self.client_keys.lock().unwrap();
        keys.insert("client1".to_string(), "test_key_1".to_string());
        Ok(())
    }

    fn verify_signature(&self, client_id: &str, data: &str, signature: &str) -> Result<bool> {
        let keys = self.client_keys.lock().unwrap();
        if let Some(key) = keys.get(client_id) {
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            hasher.update(key.as_bytes());
            let expected = BASE64.encode(hasher.finalize());
            Ok(expected == signature)
        } else {
            Err("Unknown client".into())
        }
    }

    fn create_session(&self, client_id: String) -> String {
        let session_id = Uuid::new_v4().to_string();
        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(session_id.clone(), Session {
            client_id,
            created_at: SystemTime::now(),
            last_activity: SystemTime::now(),
            nonce_history: HashSet::new(),
        });
        session_id
    }

    fn validate_session(&self, session_id: &str, client_id: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            if session.client_id != client_id {
                return false;
            }
            let now = SystemTime::now();
            if now.duration_since(session.created_at).unwrap() > Duration::from_secs(3600) {
                return false;
            }
            session.last_activity = now;
            true
        } else {
            false
        }
    }

    fn cleanup_sessions(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        let now = SystemTime::now();
        sessions.retain(|_, session| {
            now.duration_since(session.last_activity).unwrap() <= Duration::from_secs(3600)
        });
    }

    fn verify_nonce(&self, session_id: &str, nonce: &str) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(session_id) {
            if session.nonce_history.contains(nonce) {
                false
            } else {
                session.nonce_history.insert(nonce.to_string());
                true
            }
        } else {
            false
        }
    }
}

fn load_or_generate_identity() -> Result<Identity> {
    let cert_path = Path::new("cert/identity.p12");
    
    if !cert_path.exists() {
        return Err("Certificate not found. Please run generate_cert.sh first".into());
    }
    
    let cert_data = fs::read(cert_path)
        .map_err(|e| format!("Failed to read certificate: {}", e))?;
    
    Identity::from_pkcs12(&cert_data, "password")
        .map_err(|e| format!("Failed to load certificate: {}", e))
}

fn verify_timestamp(timestamp: u64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    if timestamp > now {
        timestamp - now < 300
    } else {
        now - timestamp < 300
    }
}

fn sign_response(response: &str, key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(response.as_bytes());
    hasher.update(key.as_bytes());
    BASE64.encode(hasher.finalize())
}

async fn execute_curl_command(query: &str) -> Result<(bool, String)> {
    // 創建臨時文件來存儲查詢
    let temp_file = format!("temp_query_{}.json", Uuid::new_v4());
    fs::write(&temp_file, query)
        .map_err(|e| format!("Failed to write temp query file: {}", e))?;

    let output = Command::new("curl")
        .args(&[
            "-k",
            "-u", "admin:aD?VhljrN55GGbO?twN6IL+zCxKYKeNT",
            "https://localhost:9200/wazuh-alerts-4.x-*/_search?pretty",
            "-H", "Content-Type: application/json",
            "-d", &format!("@{}", temp_file)
        ])
        .output()
        .map_err(|e| e.to_string())?;

    // 刪除臨時文件
    let _ = fs::remove_file(&temp_file);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok((true, stdout))
    } else {
        Ok((false, format!("Error: {}\nDebug info: {}", stderr, stdout)))
    }
}

async fn handle_client(
    mut stream: tokio_native_tls::TlsStream<TcpStream>,
    state: Arc<ServerState>,
) -> Result<()> {
    println!("New client connected");
    
    state.rate_limiter.check()
        .map_err(|e| format!("Rate limit exceeded: {:?}", e))?;

    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    
    if n < 12 {
        return Err("Received data too short".into());
    }

    let auth_request: AuthRequest = serde_json::from_slice(&buf[..n])
        .map_err(|e| format!("Failed to parse request: {}", e))?;

    println!("Received request from client_id: {}", auth_request.client_id);
    
    if !verify_timestamp(auth_request.timestamp) {
        return Err("Invalid timestamp".into());
    }

    let session_id = if let Some(sid) = auth_request.session_id.clone() {
        println!("Validating existing session: {}", sid);
        if !state.validate_session(&sid, &auth_request.client_id) {
            println!("Creating new session as validation failed");
            state.create_session(auth_request.client_id.clone())
        } else {
            println!("Using existing session");
            sid
        }
    } else {
        println!("Creating new session");
        state.create_session(auth_request.client_id.clone())
    };

    println!("Using session_id: {}", session_id);

    if !state.verify_nonce(&session_id, &auth_request.nonce) {
        return Err("Nonce already used".into());
    }

    let data_to_verify = format!("{}:{}:{}", 
        auth_request.client_id,
        auth_request.timestamp,
        auth_request.nonce
    );

    if !state.verify_signature(&auth_request.client_id, &data_to_verify, &auth_request.signature)? {
        return Err("Invalid signature".into());
    }

    println!("Executing WQL query...");
    let (status, data) = execute_curl_command(&auth_request.wql_query).await?;
    println!("Query execution completed");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let response = Response {
        status,
        data,
        session_id: session_id.clone(),
        timestamp,
        signature: String::new(),
    };

    let response_json = serde_json::to_string(&response)
        .map_err(|e| e.to_string())?;

    let signature = sign_response(&response_json, "server_key");
    let response = Response {
        signature,
        ..response
    };

    let response_json = serde_json::to_string(&response)
        .map_err(|e| e.to_string())?;

    println!("Sending response ({} bytes)...", response_json.len());
    stream.write_all(response_json.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    println!("Response sent successfully");
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:8080".to_string());

    println!("Loading certificate...");
    let identity = load_or_generate_identity()?;
    
    println!("Setting up TLS acceptor...");
    let acceptor = TlsAcceptor::new(identity)
        .map_err(|e| e.to_string())?;
    let acceptor = TokioTlsAcceptor::from(acceptor);
    let acceptor = Arc::new(acceptor);

    println!("Initializing server state...");
    let state = Arc::new(ServerState::new());
    state.load_client_keys()?;

    println!("Starting server on {}...", addr);
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| e.to_string())?;
    println!("Server listening on {}", addr);

    let state_clone = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            state_clone.cleanup_sessions();
        }
    });

    while let Ok((socket, client_addr)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let state = state.clone();

        println!("New connection from: {}", client_addr);
        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(stream) => {
                    if let Err(e) = handle_client(stream, state).await {
                        eprintln!("Error handling client {}: {}", client_addr, e);
                    }
                }
                Err(e) => eprintln!("TLS error for {}: {}", client_addr, e),
            }
        });
    }

    Ok(())
}
