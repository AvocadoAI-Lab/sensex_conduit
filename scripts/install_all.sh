#!/bin/bash

# 檢查是否為root用戶
if [ "$EUID" -ne 0 ]; then 
   echo "Please run as root"
   exit 1
fi

# 設置工作目錄
WORK_DIR="/home/zxzinn/wazuh-monitor"
cd $WORK_DIR

# 顏色定義
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 日誌函數
log_success() {
   echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
   echo -e "${RED}[ERROR]${NC} $1"
}

# 停止現有服務
echo "Stopping existing service..."
systemctl stop wazuh-monitor

# 安裝系統依賴
echo "Installing system dependencies..."
apt-get update
apt-get install -y \
   build-essential \
   pkg-config \
   libssl-dev \
   curl \
   inotify-tools \
   netcat-openbsd

# 安裝Rust（如果未安裝）
if ! command -v cargo &> /dev/null; then
   echo "Installing Rust..."
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source $HOME/.cargo/env
fi

# 創建必要的目錄
echo "Creating directories..."
mkdir -p $WORK_DIR/cert
mkdir -p $WORK_DIR/scripts

# 先編譯檢查依賴
export PATH="/root/.cargo/bin:$PATH"
echo "Building project to check dependencies..."
cargo build
if [ $? -ne 0 ]; then
   log_error "Initial build failed. Please check the error messages above."
   exit 1
fi
log_success "Initial build successful"

# 生成證書
echo "Generating certificates..."
cat > $WORK_DIR/scripts/generate_cert.sh << 'EOL'
#!/bin/bash
CERT_DIR="cert"
mkdir -p $CERT_DIR
openssl genrsa -out $CERT_DIR/key.pem 2048
openssl req -new -x509 -key $CERT_DIR/key.pem -out $CERT_DIR/cert.pem -days 365 -subj "/CN=localhost"
openssl pkcs12 -export -out $CERT_DIR/identity.p12 -inkey $CERT_DIR/key.pem -in $CERT_DIR/cert.pem -password pass:password
EOL
chmod +x $WORK_DIR/scripts/generate_cert.sh
./scripts/generate_cert.sh

# 創建監控腳本
echo "Creating monitor script..."
cat > $WORK_DIR/scripts/monitor.sh << 'EOL'
#!/bin/bash
WORK_DIR="/home/zxzinn/wazuh-monitor"
cd $WORK_DIR

# 設置 cargo 路徑
export PATH="/root/.cargo/bin:$PATH"

LOG_FILE="$WORK_DIR/monitor.log"

log() {
   echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

start_server() {
   log "Starting server..."
   if [ -f "./target/release/server" ]; then
       ./target/release/server 0.0.0.0:8080 >> $LOG_FILE 2>&1 &
       SERVER_PID=$!
       log "Server started with PID: $SERVER_PID"
   else
       log "Error: Server binary not found. Building first..."
       cargo build --release
       if [ $? -eq 0 ]; then
           ./target/release/server 0.0.0.0:8080 >> $LOG_FILE 2>&1 &
           SERVER_PID=$!
           log "Server started with PID: $SERVER_PID"
       else
           log "Error: Failed to build server"
           return 1
       fi
   fi
}

# 初始編譯
log "Initial build..."
cargo build --release
if [ $? -ne 0 ]; then
   log "Initial build failed"
   exit 1
fi

# 啟動服務器
start_server

# 監控文件變化
while true; do
   log "Monitoring for changes..."
   inotifywait -r -e modify,create,delete,move ./src
   log "Change detected, rebuilding..."

   if [ ! -z "$SERVER_PID" ]; then
       log "Stopping server with PID: $SERVER_PID"
       kill $SERVER_PID 2>/dev/null || true
   fi
   pkill -f "server 0.0.0.0:8080" || true

   cargo build --release
   if [ $? -eq 0 ]; then
       log "Build successful, restarting server..."
       start_server
   else
       log "Build failed, server not restarted"
   fi
done
EOL
chmod +x $WORK_DIR/scripts/monitor.sh

# 創建systemd服務文件
echo "Creating systemd service..."
cat > /etc/systemd/system/wazuh-monitor.service << EOL
[Unit]
Description=Wazuh Monitor Auto-reload Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WORK_DIR
ExecStart=$WORK_DIR/scripts/monitor.sh
Restart=always
Environment=RUST_BACKTRACE=1
Environment="PATH=/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
EOL

# 編譯發布版本
echo "Building release version..."
cargo build --release
if [ $? -ne 0 ]; then
   log_error "Release build failed"
   exit 1
fi
log_success "Release build successful"

# 設置防火牆規則
echo "Setting up firewall rules..."
if command -v ufw &> /dev/null; then
   ufw allow 8080/tcp
   ufw status
elif command -v firewall-cmd &> /dev/null; then
   firewall-cmd --permanent --add-port=8080/tcp
   firewall-cmd --reload
fi

# 重新加載systemd並啟動服務
echo "Starting service..."
systemctl daemon-reload
systemctl enable wazuh-monitor
systemctl restart wazuh-monitor

# 等待服務啟動
echo "Waiting for service to start..."
sleep 5

# 檢查服務狀態
if systemctl is-active --quiet wazuh-monitor; then
   log_success "Service started successfully"
   echo "You can check the logs using: journalctl -u wazuh-monitor -f"
   echo "Or check the monitor log: tail -f $WORK_DIR/monitor.log"
else
   log_error "Service failed to start"
   echo "Please check the logs using: journalctl -u wazuh-monitor -f"
   exit 1
fi

# 等待服務器完全啟動
echo "Waiting for server to initialize..."
sleep 5

# 檢查端口
echo "Checking port 8080..."
if nc -z localhost 8080; then
   log_success "Server is listening on port 8080"
   netstat -tulpn | grep 8080
else
   log_error "Server is not responding on port 8080"
   echo "Please check the logs for errors:"
   tail -n 20 $WORK_DIR/monitor.log
fi