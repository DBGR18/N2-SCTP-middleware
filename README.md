# Project: 5G N2 Zero Trust Proxy

## 1. 架構

資料路徑：

`UERANSIM gNB (SCTP) -> gnb_proxy -> QUIC mTLS -> middleware -> SCTP -> AMF`

控制路徑：

`gnb_proxy --(JWT + CSR over HTTPS)--> middleware /enroll --(signed cert)--> gnb_proxy`

### 1.1 dummy0 測試拓樸
本專案的預設 `config.yaml`（以及 `setup_dummy0.sh`）對應到一個「單機 dummy0」測試拓樸：

- `10.64.0.100:38412`：`gnb_proxy` 對 UERANSIM 提供的 **SCTP 監聽位址**（UERANSIM 的 `amf/ngap` 目標要指向這裡）
- `10.64.0.1:29502`：`middleware` 的 **QUIC/UDP 監聽位址**（資料平面）
- `10.64.0.1:8443`：`middleware` 的 **Enrollment HTTPS 監聽位址**（控制平面）
- `10.64.0.1:38413`：`middleware` 對外連 AMF 時使用的 **SCTP 本地 bind 位址/port**（用來固定來源位址）
- `10.0.0.1:38412`：`free5gc AMF` 的 **NGAP/SCTP 監聽位址**（middleware 會把 gNB 的 NGAP 轉送到這裡）

你可以把它理解成：dummy0 同時承載「gNB 端的入口位址 (10.64.0.100)」、「Proxy/Middleware 自己的位址 (10.64.0.1)」、以及「AMF 的 NGAP 位址 (10.0.0.1)」。

### 1.2 身份（Identity）與信任鏈（Trust Chain）

本專案把身份驗證拆成兩段：

1) **Enrollment（控制平面）**：用 JWT 驗證「你是否允許某個 gNB proxy 取得憑證」

2) **資料平面（QUIC mTLS）**：用 mTLS 驗證「連進來/連出去的雙方是否持有合法憑證」

信任鏈關係如下：

- `middleware` 是 CA：
  - 首次啟動會自動建立/載入 Root CA（`ca_cert_path`/`ca_key_path`）
  - 會自動建立/載入自己的 server certificate（`server_cert_path`/`server_key_path`）
- `gnb_proxy` 是 client：
  - 私鑰只在本地產生並保存（`client_key_path`）
  - 透過 CSR 向 `middleware /enroll` 申請並取得 client certificate（`client_cert_path`）
- 兩邊都以 `ca_cert_path` 當作信任根：
  - `gnb_proxy` 用 CA 來驗證 `middleware` 的 server cert（避免連到假冒的 middleware）
  - `middleware` 用 CA 來驗證 `gnb_proxy` 的 client cert（避免未授權 gNB 加入資料平面）

> 注意（dummy0 單機拓樸的特性）：本 README 的預設流程是「`middleware` 先啟動並在本機檔案系統生成 `ca_cert_path`，`gnb_proxy` 再讀取該 CA 憑證來建立信任」。
> 若你要做跨主機/跨節點部署，CA 憑證（或其指紋）應以 out-of-band 的方式預先分發/固定，避免信任根來源不明。

### 1.3 身份驗證與連線流程（總覽）

以「第一次啟動（還沒有 client cert）」為例，整個流程會長這樣：

1. `middleware` 啟動：初始化 Root CA 與 server cert，開始提供：
   - `https://10.64.0.1:8443/enroll`（JWT + CSR）
   - `quic://10.64.0.1:29502`（mTLS）
2. `gnb_proxy` 啟動：
   - 若本地沒有可用的 `client_cert_path`/`client_key_path`，就生成 ECDSA P-256 私鑰 + CSR
   - 用 `Authorization: Bearer <JWT>` 呼叫 `/enroll` 取得簽發後的 client cert
3. `gnb_proxy` 使用拿到的 client cert 與 CA，建立到 `middleware` 的 QUIC mTLS 連線
4. UERANSIM gNB 用 SCTP 連到 `gnb_proxy (10.64.0.100:38412)`
5. `gnb_proxy` 將 SCTP payload（含 stream/PPID metadata）封裝後送入 QUIC stream
6. `middleware` 從 QUIC stream 解封裝後，轉送到 AMF 的 NGAP/SCTP（`10.0.0.1:38412`），回程同理

## 2. 主要實作

- `cmd/middleware/main.go`
  - Root CA 自動初始化（不存在就生成）
  - `POST /enroll`：驗 JWT、驗 CSR、簽發 client certificate
  - QUIC mTLS server（`ClientAuth: RequireAndVerifyClientCert`）
  - QUIC stream 與 AMF SCTP 間雙向轉送

- `cmd/gnb_proxy/main.go`
  - 啟動時檢查 client cert 可用性（過期/缺失則重註冊）
  - 本地生成 ECDSA P-256 私鑰與 CSR
  - 帶 JWT 呼叫 enrollment API 取得簽發 cert
  - 與 middleware 建立 QUIC mTLS，轉送 UERANSIM SCTP 封包

## 3. 設定檔

`config.yaml` 已擴充以下欄位：

- Enrollment API
  - `enroll_listen_ip`
  - `enroll_listen_port`
  - `enroll_url`
- JWT
  - `jwt_secret`
  - `enrollment_jwt`
- PKI 路徑
  - `ca_cert_path`
  - `ca_key_path`
  - `server_cert_path`
  - `server_key_path`
  - `client_cert_path`
  - `client_key_path`
- QUIC 參數
  - `quic_idle_timeout_seconds`
  - `quic_keepalive_ms`

### 3.1 dummy0 拓樸下的設定對照

以下用預設 `config.yaml` 的值，說明每個欄位在「身份驗證與連線流程」中的角色：

- Enrollment（控制平面，HTTPS/TCP）
  - `enroll_listen_ip`/`enroll_listen_port`：`middleware` 監聽位址（例如 `10.64.0.1:8443`）
  - `enroll_url`：`gnb_proxy` 要打的完整 URL（例如 `https://10.64.0.1:8443/enroll`）
  - `jwt_secret`：`middleware` 用來驗證 JWT 的共享密鑰（HS256；demo 用，請自行更換）
  - `enrollment_jwt`：`gnb_proxy` 用來換取憑證的短效 token

- QUIC mTLS（資料平面，QUIC/UDP）
  - `middleware_listen_ip`/`middleware_listen_port`：`middleware` QUIC 監聽位址（例如 `10.64.0.1:29502`）
  - `gnb_local_ip`：`gnb_proxy` 對外發起 QUIC/UDP 時使用的本地位址（例如 `10.64.0.100`）
  - `middleware_tls_server_name`：
    - 留空時：用 IP SAN 驗證（通常配合 `middleware_listen_ip`）
    - 若你改成用 DNS 名稱（或想固定 SNI）：可在此指定

- SCTP 轉送（middleware <-> AMF）
  - `gnb_proxy_listen_ip`/`gnb_proxy_listen_port`：UERANSIM 要連的 gNB Proxy SCTP 入口（例如 `10.64.0.100:38412`）
  - `amf_target_ip`/`amf_target_port`：AMF 的 NGAP/SCTP 目標（例如 `10.0.0.1:38412`）
  - `middleware_sctp_local_ip`/`middleware_sctp_listen_port`：middleware 連到 AMF 時的本地 bind（例如 `10.64.0.1:38413`）

- PKI（憑證/私鑰檔案）
  - `ca_cert_path`/`ca_key_path`：Root CA（由 middleware 自動建立/載入）
  - `server_cert_path`/`server_key_path`：middleware server cert（由 middleware 自動建立/載入）
  - `client_cert_path`/`client_key_path`：gnb_proxy client cert/key（key 本地生成；cert 由 enrollment 取得）

## 4. 編譯

```bash
cd /home/dbgr/N2-encryption
go mod tidy
go build -o middleware ./cmd/middleware
go build -o gnb_proxy ./cmd/gnb_proxy
go build -o mock_gnb ./cmd/mock_gnb
```

## 5. 執行順序（實際對接 free5gc + UERANSIM）

1. 配置 dummy0（若你使用同樣測試拓樸）

```bash
cd /home/dbgr/N2-encryption
./setup_dummy0.sh
```

這一步的目的：在本機創造出 `10.64.0.1`、`10.64.0.100`、`10.0.0.1` 這些位址，讓你不用真的拉多網卡/多 namespace 也能做位址分離與連線驗證。

1. 產生短效 JWT（10 分鐘）

```bash
cd /home/dbgr/N2-encryption
./middleware -config ./config.yaml -generate-jwt
```

把輸出 token 寫進 `config.yaml` 的 `enrollment_jwt`，或以環境變數覆蓋：

```bash
export ENROLLMENT_JWT='<paste-token-here>'
```

JWT 只用於 Enrollment（換取 client cert），不會進入資料平面。資料平面完全靠 mTLS。

1. 啟動 middleware

```bash
cd /home/dbgr/N2-encryption
./middleware -config ./config.yaml
```

第一次啟動常見現象：

- `./pki/` 下會生成/更新 CA 與 server cert（依 `config.yaml` 的路徑）
- Enrollment API 開始監聽（HTTPS）
- QUIC server 開始監聽（UDP）

1. 啟動 gnb_proxy

```bash
cd /home/dbgr/N2-encryption
./gnb_proxy -config ./config.yaml
```

第一次啟動常見現象：

- 若 `client_cert_path`/`client_key_path` 不存在或不可用：會先走 Enrollment，拿到 client cert
- 接著建立 QUIC mTLS 連線（成功後才會穩定地轉送 NGAP）

1. 啟動 UERANSIM gNB

```bash
cd /home/dbgr/UERANSIM
./build/nr-gnb -c config/free5gc-gnb.yaml
```

### 5.1 身份驗證與連線流程（逐步對照 log）

以下用「第一次啟動」作為最完整的路徑，並指出每一段在 log 會看到什麼：

1) Enrollment：gnb_proxy 申請 client cert

- gnb_proxy → middleware（HTTPS `POST /enroll`）
  - gnb_proxy 帶 `Authorization: Bearer <enrollment_jwt>`
  - gnb_proxy body 送 CSR（PEM）
- middleware 端驗證：
  - 驗 JWT：簽章必須可用 `jwt_secret` 驗過，且 `exp` 未過期，且 claim `role=gnb`
  - 驗 CSR：格式正確（並用 CSR 內的 public key 進行簽發）
- 成功後：middleware 以 Root CA 簽發 client cert 並回傳（PEM）

你應該會看到類似：

- gnb_proxy：`Client certificate enrolled successfully`

2) QUIC mTLS：建立資料平面連線

- gnb_proxy → middleware（QUIC/UDP）
  - gnb_proxy 使用：`client_cert_path`/`client_key_path`
  - gnb_proxy 驗證 middleware：必須能用 `ca_cert_path` 驗證到 middleware 的 server cert
- middleware 端驗證 gnb_proxy：
  - `ClientAuth: RequireAndVerifyClientCert`
  - client cert 必須能鏈到 `ca_cert_path`（Root CA）

你應該會看到類似：

- gnb_proxy：`QUIC mTLS session established`
- middleware：`gNB QUIC connected`

3) SCTP <-> QUIC 轉送：讓 NGAP 真正過得去

- UERANSIM gNB（SCTP）→ gnb_proxy（`gnb_proxy_listen_ip:gnb_proxy_listen_port`）
- gnb_proxy 把 SCTP payload 封成 frame（含 stream/PPID + length）送入 QUIC stream
- middleware 解 frame 後，轉送到 AMF（SCTP `amf_target_ip:amf_target_port`）
  - middleware 連 AMF 時會用 `middleware_sctp_local_ip:middleware_sctp_listen_port` 當作本地 bind

你應該會看到類似：

- middleware：`forwarded ... bytes gNB->AMF`
- middleware：`forwarded ... bytes AMF->gNB`

## 6. free5gc / UERANSIM 設定重點

- `free5gc` AMF `ngapIpList` 需能被 middleware 轉送目標命中
- `UERANSIM` gNB `ngapIp`/`amf address` 要指向 gnb_proxy 監聽位址（例如 `10.64.0.100:38412`）

## 7. 驗證重點

成功路徑應可在 log 看到：

- gnb_proxy：`Client certificate enrolled successfully`
- gnb_proxy：`QUIC mTLS session established`
- middleware：`gNB QUIC connected`
- middleware：`forwarded ... bytes gNB->AMF` 與 `forwarded ... bytes AMF->gNB`

### 7.1 用「階段」判斷你卡在哪一關

當你在整鏈除錯時，建議用以下方式判斷問題屬於哪一層：

- 沒看到 `Client certificate enrolled successfully`
  - 通常是 Enrollment（JWT/HTTPS）
  - 先檢查：`enroll_url` 可達、JWT 未過期、`jwt_secret` 一致

- 有 enrolled 但沒有 `QUIC mTLS session established`
  - 通常是 QUIC mTLS（CA 不一致、server/client cert 不匹配、或位址/SAN 驗證不對）
  - 先檢查：`ca_cert_path` 是否同一份、`middleware_listen_ip:port` 是否正確

- 有 QUIC 連線但沒有 `forwarded ... bytes`
  - 通常是 SCTP 轉送（UERANSIM 沒連到 gnb_proxy、或 middleware 連不到 AMF NGAP）
  - 先檢查：UERANSIM 的 `amf/ngap` 是否指向 `10.64.0.100:38412`，以及 AMF 是否真的在 `10.0.0.1:38412` 監聽

