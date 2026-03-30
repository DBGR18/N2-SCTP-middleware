package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	cipherSuiteAES256GCM = "AES-256-GCM"
	frameMaxSize         = 1024 * 1024
)

type Config struct {
	MiddlewareListenIP   string `yaml:"middleware_listen_ip"`
	MiddlewareListenPort int    `yaml:"middleware_listen_port"`
	MiddlewareVIPIP      string `yaml:"middleware_vip_ip"`
	AMFTargetIP          string `yaml:"amf_target_ip"`
	AMFTargetPort        int    `yaml:"amf_target_port"`
	GNBLocalIP           string `yaml:"gnb_local_ip"`
	HandshakePSK         string `yaml:"handshake_psk"`
	ReadTimeoutSeconds   int    `yaml:"read_timeout_seconds"`
}

type ClientHello struct {
	Type         string   `json:"type"`
	CipherSuites []string `json:"cipher_suites"`
	ClientPubKey string   `json:"client_pub_key"`
}

type ServerHello struct {
	Type           string `json:"type"`
	SelectedCipher string `json:"selected_cipher"`
	ServerPubKey   string `json:"server_pub_key"`
}

type TunnelRequest struct {
	DestIP  string `json:"dest_ip"`
	Payload []byte `json:"payload"`
}

type TunnelReply struct {
	FromIP  string `json:"from_ip"`
	Payload []byte `json:"payload"`
}

func defaultConfig() Config {
	return Config{
		MiddlewareListenIP:   "10.64.0.1",
		MiddlewareListenPort: 29502,
		MiddlewareVIPIP:      "10.64.0.1",
		AMFTargetIP:          "10.0.0.1",
		AMFTargetPort:        38412,
		GNBLocalIP:           "10.64.0.100",
		HandshakePSK:         "n2-demo-psk-change-me",
		ReadTimeoutSeconds:   10,
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config yaml: %w", err)
		}
	}

	cfg.MiddlewareListenIP = envOrDefault("MIDDLEWARE_LISTEN_IP", cfg.MiddlewareListenIP)
	cfg.MiddlewareListenPort = envIntOrDefault("MIDDLEWARE_LISTEN_PORT", cfg.MiddlewareListenPort)
	cfg.MiddlewareVIPIP = envOrDefault("MIDDLEWARE_VIP_IP", cfg.MiddlewareVIPIP)
	cfg.GNBLocalIP = envOrDefault("GNB_LOCAL_IP", cfg.GNBLocalIP)
	cfg.AMFTargetIP = envOrDefault("AMF_TARGET_IP", cfg.AMFTargetIP)
	cfg.AMFTargetPort = envIntOrDefault("AMF_TARGET_PORT", cfg.AMFTargetPort)
	cfg.HandshakePSK = envOrDefault("HANDSHAKE_PSK", cfg.HandshakePSK)
	cfg.ReadTimeoutSeconds = envIntOrDefault("READ_TIMEOUT_SECONDS", cfg.ReadTimeoutSeconds)

	if cfg.HandshakePSK == "" {
		return cfg, errors.New("handshake_psk cannot be empty")
	}
	return cfg, nil
}

func decodePSK(psk string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(psk)
	if err == nil && len(decoded) > 0 {
		return decoded
	}
	return []byte(psk)
}

func newAEADFrom32BKey(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("expect 32-byte key, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newPSKAEAD(psk string) ([]byte, cipher.AEAD, error) {
	raw := decodePSK(psk)
	sum := sha256.Sum256(raw)
	aead, err := newAEADFrom32BKey(sum[:])
	if err != nil {
		return nil, nil, err
	}
	return raw, aead, nil
}

func deriveSessionKey(sharedSecret, pskRaw []byte) []byte {
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write(pskRaw)
	h.Write([]byte(cipherSuiteAES256GCM))
	key := h.Sum(nil)
	return key[:32]
}

func readFrame(conn net.Conn) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf)
	if n == 0 || n > frameMaxSize {
		return nil, fmt.Errorf("invalid frame length: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeFrame(conn net.Conn, payload []byte) error {
	if len(payload) == 0 || len(payload) > frameMaxSize {
		return fmt.Errorf("invalid payload length: %d", len(payload))
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func encryptEnvelope(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, sealed...), nil
}

func decryptEnvelope(aead cipher.AEAD, envelope []byte) ([]byte, error) {
	nonceSize := aead.NonceSize()
	if len(envelope) <= nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce := envelope[:nonceSize]
	ciphertext := envelope[nonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func writeEncryptedJSON(conn net.Conn, aead cipher.AEAD, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	envelope, err := encryptEnvelope(aead, raw)
	if err != nil {
		return err
	}
	return writeFrame(conn, envelope)
}

func readEncryptedJSON(conn net.Conn, aead cipher.AEAD, out any) error {
	envelope, err := readFrame(conn)
	if err != nil {
		return err
	}
	raw, err := decryptEnvelope(aead, envelope)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func clientHandshake(conn net.Conn, pskAEAD cipher.AEAD, pskRaw []byte) (cipher.AEAD, error) {
	curve := ecdh.X25519()
	clientPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	hello := ClientHello{
		Type:         "client_hello",
		CipherSuites: []string{cipherSuiteAES256GCM},
		ClientPubKey: base64.StdEncoding.EncodeToString(clientPriv.PublicKey().Bytes()),
	}
	if err := writeEncryptedJSON(conn, pskAEAD, hello); err != nil {
		return nil, fmt.Errorf("write client hello: %w", err)
	}

	var serverHello ServerHello
	if err := readEncryptedJSON(conn, pskAEAD, &serverHello); err != nil {
		return nil, fmt.Errorf("read server hello: %w", err)
	}
	if serverHello.Type != "server_hello" {
		return nil, fmt.Errorf("unexpected server hello type: %s", serverHello.Type)
	}
	if serverHello.SelectedCipher != cipherSuiteAES256GCM {
		return nil, fmt.Errorf("unsupported selected cipher: %s", serverHello.SelectedCipher)
	}

	serverPubRaw, err := base64.StdEncoding.DecodeString(serverHello.ServerPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode server pubkey: %w", err)
	}
	serverPub, err := curve.NewPublicKey(serverPubRaw)
	if err != nil {
		return nil, fmt.Errorf("parse server pubkey: %w", err)
	}

	sharedSecret, err := clientPriv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("derive ECDH secret: %w", err)
	}
	sessionKey := deriveSessionKey(sharedSecret, pskRaw)
	return newAEADFrom32BKey(sessionKey)
}

func run() error {
	configPath := envOrDefault("N2_PROXY_CONFIG", "./config.yaml")
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	pskRaw, pskAEAD, err := newPSKAEAD(cfg.HandshakePSK)
	if err != nil {
		return fmt.Errorf("init psk aead: %w", err)
	}

	remote := fmt.Sprintf("%s:%d", cfg.MiddlewareListenIP, cfg.MiddlewareListenPort)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if ip := net.ParseIP(cfg.GNBLocalIP); ip != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
	}

	conn, err := dialer.Dial("tcp", remote)
	if err != nil {
		return fmt.Errorf("dial middleware %s: %w", remote, err)
	}
	defer conn.Close()

	if cfg.ReadTimeoutSeconds > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(cfg.ReadTimeoutSeconds) * time.Second))
	}

	sessionAEAD, err := clientHandshake(conn, pskAEAD, pskRaw)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})

	req := TunnelRequest{
		DestIP:  cfg.MiddlewareVIPIP,
		Payload: []byte("dummy-ngap-initial-ue-message"),
	}
	if err := writeEncryptedJSON(conn, sessionAEAD, req); err != nil {
		return fmt.Errorf("send encrypted NGAP request: %w", err)
	}
	log.Printf("Sent encrypted request to middleware VIP %s", cfg.MiddlewareVIPIP)

	var reply TunnelReply
	if err := readEncryptedJSON(conn, sessionAEAD, &reply); err != nil {
		return fmt.Errorf("read encrypted NGAP reply: %w", err)
	}

	log.Printf("Received reply from %s, payload length=%d", reply.FromIP, len(reply.Payload))
	log.Printf("Reply payload (string): %q", string(reply.Payload))
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("mock_gnb failed: %v", err)
	}
}
