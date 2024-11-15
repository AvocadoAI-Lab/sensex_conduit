use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use native_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;
use tokio_native_tls::TlsConnector as TokioTlsConnector;
use uuid::Uuid;
use reqwest;
use std::collections::HashMap;
use dotenv::dotenv;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(1);
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
const SESSION_FILE: &str = "session.json";
const WQL_QUERIES_DIR: &str = "wql_queries";
const BUFFER_SIZE: usize = 8192;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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

#[derive(Debug, Serialize, Deserialize)]
struct SessionInfo {
    session_id: String,
    client_id: String,
    created_at: u64,
    last_used: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Group {
    id: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Agent {
    id: String,
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WazuhRequest {
    endpoint: String,
    token: String,
    params: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WazuhAuthRequest {
    endpoint: String,
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WazuhAuthResponse {
    token: Option<String>,
    error: Option<String>,
}

struct Client {
    client_id: String,
    client_key: String,
    server_key: String,
    session: Option<SessionInfo>,
    http_client: reqwest::Client,
    wazuh_endpoint: String,
    wazuh_token: Option<String>,
}

impl Client {
    fn new(client_id: String, client_key: String, server_key: String, wazuh_endpoint: String) -> Self {
        let session = Self::load_session(&client_id);
        let http_client = reqwest::Client::new();
        Self {
            client_id,
            client_key,
            server_key,
            session,
            http_client,
            wazuh_endpoint,
            wazuh_token: None,
        }
    }

    fn load_session(client_id: &str) -> Option<SessionInfo> {
        if let Ok(content) = fs::read_to_string(SESSION_FILE) {
            if let Ok(session) = serde_json::from_str::<SessionInfo>(&content) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                if now - session.created_at <= 3600 && session.client_id == client_id {
                    println!("Loaded existing session: {}", session.session_id);
                    return Some(session);
                }
            }
        }
        None
    }

    fn save_session(&self) -> Result<()> {
        if let Some(session) = &self.session {
            let content = serde_json::to_string_pretty(session)?;
            fs::write(SESSION_FILE, content)?;
            println!("Session saved: {}", session.session_id);
        }
        Ok(())
    }

    fn sign_request(&self, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hasher.update(self.client_key.as_bytes());
        BASE64.encode(hasher.finalize())
    }

    fn verify_response(&self, response_data: &str, signature: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(response_data.as_bytes());
        hasher.update(self.server_key.as_bytes());
        let expected = BASE64.encode(hasher.finalize());
        expected == signature
    }

    async fn stream_response(
        stream: &mut tokio_native_tls::TlsStream<TcpStream>,
    ) -> Result<String> {
        let mut response_data = Vec::new();
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let mut total_bytes = 0;
        
        print!("\rReceiving data: 0 bytes");
        std::io::stdout().flush()?;

        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    if total_bytes == 0 {
                        return Err("Connection closed by server".into());
                    }
                    break;
                },
                Ok(n) => {
                    response_data.extend_from_slice(&buffer[..n]);
                    total_bytes += n;
                    print!("\rReceiving data: {} bytes", total_bytes);
                    std::io::stdout().flush()?;
                }
                Err(e) => return Err(format!("Failed to read response: {}", e).into()),
            }
        }
        println!("\nReceived total: {} bytes", total_bytes);

        String::from_utf8(response_data)
            .map_err(|e| format!("Invalid UTF-8 sequence: {}", e).into())
    }

    async fn send_request(
        &mut self, 
        stream: &mut tokio_native_tls::TlsStream<TcpStream>,
        wql_query: String
    ) -> Result<Response> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        let nonce = Uuid::new_v4().to_string();
        
        let data_to_sign = format!("{}:{}:{}", 
            self.client_id,
            timestamp,
            nonce
        );

        let signature = self.sign_request(&data_to_sign);

        let request = AuthRequest {
            client_id: self.client_id.clone(),
            timestamp,
            nonce,
            signature,
            session_id: self.session.as_ref().map(|s| s.session_id.clone()),
            wql_query,
        };

        let request_json = serde_json::to_string(&request)?;
        println!("Sending request...");
        stream.write_all(request_json.as_bytes()).await?;
        stream.flush().await?;

        println!("Waiting for response...");
        let response_str = Self::stream_response(stream).await?;
        
        let mut response: Response = serde_json::from_str(&response_str)?;
        
        let signature = response.signature.clone();
        response.signature = String::new();
        let response_data = serde_json::to_string(&response)?;
        
        if !self.verify_response(&response_data, &signature) {
            return Err("Invalid response signature".into());
        }

        response.signature = signature;

        self.session = Some(SessionInfo {
            session_id: response.session_id.clone(),
            client_id: self.client_id.clone(),
            created_at: timestamp,
            last_used: timestamp,
        });
        self.save_session()?;

        Ok(response)
    }

    async fn authenticate(&mut self, username: &str, password: &str) -> Result<()> {
        let auth_request = WazuhAuthRequest {
            endpoint: self.wazuh_endpoint.clone(),
            username: username.to_string(),
            password: password.to_string(),
        };

        let response = self.http_client.post("http://localhost:3001/auth")
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&auth_request)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;

        println!("Auth response status: {}", status);
        println!("Auth response body: {}", body);

        if status.is_success() {
            let auth_response: WazuhAuthResponse = serde_json::from_str(&body)?;
            if let Some(token) = auth_response.token {
                self.wazuh_token = Some(token);
                Ok(())
            } else {
                Err("Authentication failed: No token received".into())
            }
        } else {
            Err(format!("Authentication failed: {}", body).into())
        }
    }

    async fn fetch_groups(&self) -> Result<Vec<Group>> {
        for attempt in 1..=MAX_RETRIES {
            let wazuh_request = WazuhRequest {
                endpoint: self.wazuh_endpoint.clone(),
                token: self.wazuh_token.clone().unwrap(),
                params: HashMap::new(),
            };

            let response = self.http_client.post("http://localhost:3001/groups")
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&wazuh_request)
                .send()
                .await?;
            
            let status = response.status();
            let body = response.text().await?;
            
            println!("Response status: {}", status);
            println!("Response body: {}", body);
            
            if status.is_success() {
                let json: serde_json::Value = serde_json::from_str(&body)?;
                if let Some(affected_items) = json["data"]["affected_items"].as_array() {
                    let groups: Vec<Group> = affected_items
                        .iter()
                        .filter_map(|item| {
                            Some(Group {
                                id: item["name"].as_str()?.to_string(),
                                name: item["name"].as_str()?.to_string(),
                            })
                        })
                        .collect();
                    println!("Parsed {} groups", groups.len());
                    return Ok(groups);
                } else {
                    println!("Unexpected response structure: {:?}", json);
                }
            } else {
                println!("Request failed with status: {}", status);
            }
            
            if attempt < MAX_RETRIES {
                println!("Retrying in {} seconds...", RETRY_DELAY.as_secs());
                sleep(RETRY_DELAY).await;
            }
        }
        
        Err(format!("Failed to fetch groups after {} attempts", MAX_RETRIES).into())
    }

    async fn fetch_agents(&self, group_id: &str) -> Result<Vec<Agent>> {
        for attempt in 1..=MAX_RETRIES {
            let mut params = HashMap::new();
            params.insert("group_id".to_string(), group_id.to_string());

            let wazuh_request = WazuhRequest {
                endpoint: self.wazuh_endpoint.clone(),
                token: self.wazuh_token.clone().unwrap(),
                params,
            };

            let response = self.http_client.post(&format!("http://localhost:3001/groups/{}/agents", group_id))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&wazuh_request)
                .send()
                .await?;
            
            let status = response.status();
            let body = response.text().await?;
            
            println!("Response status: {}", status);
            println!("Response body: {}", body);
            
            if status.is_success() {
                let json: serde_json::Value = serde_json::from_str(&body)?;
                if let Some(affected_items) = json["data"]["affected_items"].as_array() {
                    let agents: Vec<Agent> = affected_items
                        .iter()
                        .filter_map(|item| {
                            Some(Agent {
                                id: item["id"].as_str()?.to_string(),
                                name: item["name"].as_str()?.to_string(),
                            })
                        })
                        .collect();
                    println!("Parsed {} agents for group {}", agents.len(), group_id);
                    return Ok(agents);
                } else {
                    println!("Unexpected response structure: {:?}", json);
                }
            } else {
                println!("Request failed with status: {}", status);
            }
            
            if attempt < MAX_RETRIES {
                println!("Retrying in {} seconds...", RETRY_DELAY.as_secs());
                sleep(RETRY_DELAY).await;
            }
        }
        
        Err(format!("Failed to fetch agents for group {} after {} attempts", group_id, MAX_RETRIES).into())
    }
}

fn get_wql_query_files() -> Result<Vec<PathBuf>> {
    let mut query_files = Vec::new();
    for entry in fs::read_dir(WQL_QUERIES_DIR)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            query_files.push(path);
        }
    }
    Ok(query_files)
}

async fn connect_with_retry(
    addr: &str,
    connector: &TokioTlsConnector,
) -> Result<tokio_native_tls::TlsStream<TcpStream>> {
    let mut last_error = None;
    for _ in 0..MAX_RETRIES {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                return Ok(connector.connect("localhost", stream).await?);
            }
            Err(e) => {
                last_error = Some(e);
                sleep(RETRY_DELAY).await;
            }
        }
    }
    Err(format!("Failed to connect after {} retries: {:?}", MAX_RETRIES, last_error.unwrap()).into())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();

    let server_addr = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: client <server_address:port>");
        eprintln!("Example: client 192.168.1.100:8080");
        process::exit(1);
    });

    println!("Loading WQL query files...");
    let query_files = get_wql_query_files()?;
    if query_files.is_empty() {
        eprintln!("No WQL query files found in {} directory", WQL_QUERIES_DIR);
        process::exit(1);
    }

    let wazuh_url = env::var("WAZUH_URL").expect("WAZUH_URL must be set in .env file");
    let wazuh_username = env::var("WAZUH_USERNAME").expect("WAZUH_USERNAME must be set in .env file");
    let wazuh_password = env::var("WAZUH_PASSWORD").expect("WAZUH_PASSWORD must be set in .env file");

    let mut client = Client::new(
        "client1".to_string(),
        "test_key_1".to_string(),
        "server_key".to_string(),
        wazuh_url,
    );

    // Authenticate and get a token
    client.authenticate(&wazuh_username, &wazuh_password).await?;
    
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let connector = TokioTlsConnector::from(connector);
    
    let output_dir = "query_results";
    fs::create_dir_all(output_dir)?;

    println!("Fetching groups...");
    let groups = client.fetch_groups().await?;
    println!("Fetched {} groups", groups.len());

    for group in groups {
        // Create a directory for the group
        let group_dir = format!("{}/{}", output_dir, group.name.replace(" ", "_"));
        fs::create_dir_all(&group_dir)?;
        println!("Created directory for group: {}", group_dir);

        println!("Fetching agents for group: {}", group.name);
        let agents = client.fetch_agents(&group.id).await?;
        println!("Fetched {} agents for group {}", agents.len(), group.name);

        for agent in agents {
            for query_file in &query_files {
                println!("\nExecuting query for agent {}: {:?}", agent.name, query_file);
                
                let mut query_content = fs::read_to_string(&query_file)?;
                query_content = query_content.replace("{{agent_id}}", &agent.id);
                query_content = query_content.replace("{{agent_name}}", &agent.name);
                
                println!("Connecting to server at {}...", server_addr);
                let mut stream = connect_with_retry(&server_addr, &connector).await?;
                println!("TLS connection established");
                
                let response = client.send_request(&mut stream, query_content).await?;
                
                if response.status {
                    let query_name = query_file.file_stem().unwrap().to_string_lossy();
                    let output_file = format!("{}/{}_{}_{}.json", 
                        group_dir,
                        query_name,
                        agent.name.replace(" ", "_"),
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)?
                            .as_secs()
                    );
                    
                    fs::write(&output_file, &response.data)?;
                    println!("Query result saved to: {}", output_file);
                } else {
                    eprintln!("Query failed: {}", response.data);
                }
                
                sleep(RECONNECT_DELAY).await;
            }
        }
    }

    println!("\nAll queries completed");
    Ok(())
}
