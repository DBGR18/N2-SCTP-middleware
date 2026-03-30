# N2 Encryption Middleware 實作說明

本文件為最新實作版本，涵蓋 Middleware、gnb_proxy、mock_gnb 的現況，以及目前實際使用的加密方法與封包處理細節。

## 1. 最新實作重點

- 已完成三段式代理鏈：UERANSIM gNB -> gnb_proxy -> middleware -> AMF
- 已修正 SCTP PPID 相容問題，AMF 不再出現 Received SCTP PPID != 60, discard this packet
- UERANSIM gNB 可完成 NG Setup（可在 UERANSIM log 看到 NG Setup Response received）
- dummy0 一鍵配置腳本可建立三個必要 IP：10.64.0.1、10.64.0.100、10.0.0.1

## 2. 專案結構

- cmd/middleware/main.go
  - 加密隧道伺服器（TCP）
  - 解析加密封包後轉送到 AMF（SCTP）
  - 將 AMF 回應重新加密回傳
- cmd/gnb_proxy/main.go
  - UERANSIM gNB 的本地 SCTP 代理
  - 將 UERANSIM 原生 SCTP NGAP 封包轉為加密隧道封包
  - 將 middleware 回應解封後再寫回 SCTP
- cmd/mock_gnb/main.go
  - 測試用途的 gNB 模擬器
- config.yaml
  - 網路位址、埠號、PSK、timeout、gnb_proxy 監聽位址
- setup_dummy0.sh
  - 建立並配置 dummy0

## 3. 端到端資料流

1. UERANSIM gNB 以 SCTP 連到 gnb_proxy（10.64.0.100:38412）
2. gnb_proxy 與 middleware 建立加密 TCP 連線（10.64.0.1:29502）
3. gnb_proxy 將 SCTP NGAP payload 封裝成 TunnelRequest 並加密傳送
4. middleware 解密後，將目的 VIP 10.64.0.1 轉譯成 AMF 10.0.0.1
5. middleware 以 SCTPWrite 寫入 AMF（10.0.0.1:38412）
6. AMF 回應後，middleware 以 TunnelReply 加密回傳給 gnb_proxy
7. gnb_proxy 解密後，以 SCTPWrite 回送 UERANSIM gNB

## 4. 現在使用的加密方法（詳細）

### 4.1 演算法組合

- 握手保護：AES-256-GCM（PSK 衍生 key）
- 金鑰交換：X25519（ECDH）
- 資料平面加密：AES-256-GCM（session key）
- 雜湊與 key 衍生：SHA-256

### 4.2 握手分兩層

第一層：PSK 保護握手訊息

- 程式先把 handshake_psk 轉成 bytes（若可 base64 decode 則使用 decode 後 bytes）
- 取 SHA-256(psk_raw) 作為 32-byte key
- 用此 key 建立 AES-256-GCM，保護 ClientHello/ServerHello

第二層：ECDH 協商 session key

- ClientHello 內帶 X25519 client public key
- ServerHello 回傳 X25519 server public key 與選定 cipher suite
- 雙方用 ECDH 產生 shared_secret
- 以 shared_secret + psk_raw + 字串 AES-256-GCM 做 SHA-256，取前 32 bytes 當 session key

### 4.3 資料封包加密格式

- 先把 TunnelRequest 或 TunnelReply 序列化為 JSON
- 用 session AEAD（AES-256-GCM）加密
- 每筆訊息都產生隨機 nonce
- 實際傳送的 envelope 為：nonce + ciphertext_and_tag
- 外層再加 4-byte big-endian 長度前綴（frame）

### 4.4 目前加密內容有哪些欄位

- TunnelRequest
  - dest_ip
  - payload（NGAP bytes）
  - stream（SCTP stream id）
  - ppid（SCTP payload protocol id）
- TunnelReply
  - from_ip
  - payload
  - stream
  - ppid

也就是說，目前不只 payload，連 stream/ppid metadata 也會一起帶在加密通道中。

### 4.5 為什麼這次要特別修 PPID

- NGAP 必須使用 SCTP PPID 60
- 先前錯誤是 AMF 收到非 60 的 PPID，直接丟包
- 現在 middleware 與 gnb_proxy 都使用 SCTPRead/SCTPWrite
- 並在轉送時正規化 PPID（支援 0、60、0x3c000000 三種輸入，統一轉為 host-order 60）

### 4.6 安全性特性與限制

目前特性：

- 機密性：由 AES-GCM 保證
- 完整性：由 GCM tag 驗證
- 金鑰新鮮性：每條隧道連線透過 X25519 產生新的 shared secret

目前限制：

- 沒有憑證鏈驗證與 PKI 身分綁定（主要依賴 PSK）
- 若 PSK 洩漏，攻擊者可偽裝端點參與握手
- 未設計額外的應用層 anti-replay 規則（目前仰賴連線與 AEAD 驗證）

## 5. 設定檔

config.yaml 主要參數：

- middleware_listen_ip
- middleware_listen_port
- middleware_vip_ip
- middleware_sctp_local_ip
- middleware_sctp_listen_port
- amf_target_ip
- amf_target_port
- gnb_local_ip
- gnb_proxy_listen_ip
- gnb_proxy_listen_port
- handshake_psk
- read_timeout_seconds

## 6. dummy0 配置

setup_dummy0.sh 會確保下列位址存在：

- 10.64.0.1/32（middleware）
- 10.64.0.100/32（gNB / gnb_proxy）
- 10.0.0.1/32（AMF N2）

執行：

```bash
cd /home/dbgr/N2-encryption
chmod +x setup_dummy0.sh
./setup_dummy0.sh
```

## 7. 編譯

```bash
cd /home/dbgr/N2-encryption
go mod tidy
go build -o middleware ./cmd/middleware
go build -o gnb_proxy ./cmd/gnb_proxy
go build -o mock_gnb ./cmd/mock_gnb
```

## 8. 執行順序（實際對接 UERANSIM）

1. 配置 dummy0
2. 啟動或重啟 free5gc AMF（確認 AMF N2 監聽 10.0.0.1:38412）
3. 啟動 middleware
4. 啟動 gnb_proxy
5. 啟動 UERANSIM gNB

參考指令：

```bash
cd /home/dbgr/N2-encryption
./setup_dummy0.sh
./middleware
```

新終端：

```bash
cd /home/dbgr/N2-encryption
./gnb_proxy
```

新終端：

```bash
cd /home/dbgr/UERANSIM
./build/nr-gnb -c config/free5gc-gnb.yaml
```

## 9. 成功判斷

UERANSIM gNB 成功訊號：

- NG Setup Response received
- NG Setup procedure is successful

middleware 成功訊號：

- gNB connected from 10.64.0.100:xxxxx
- forwarded ... (dest translated 10.64.0.1 -> 10.0.0.1)
- AMF->gNB encrypted ... bytes

AMF 成功訊號：

- Handle NGSetupRequest
- Send NG-Setup response

## 10. 疑難排解

- listen ... address already in use
  - 代表舊進程還在占埠，先停止舊 middleware/gnb_proxy 再重啟
- middleware 無法連 AMF
  - 檢查 AMF 是否真的在 10.0.0.1:38412 監聽（SCTP）
  - 檢查 dummy0 是否仍有 10.0.0.1
- AMF 出現 Received SCTP PPID != 60
  - 高機率是你正在跑舊版 binary，請重新 build 並重啟 middleware + gnb_proxy
