package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ishidawataru/sctp"
	"github.com/quic-go/quic-go"
	"gopkg.in/yaml.v3"
)

const (
	frameMaxSize = 1024 * 1024
	ngapPPID     = uint32(60)
	quicALPN     = "n2-quic-v1"
)

type Config struct {
	MiddlewareListenIP       string `yaml:"middleware_listen_ip"`
	MiddlewareListenPort     int    `yaml:"middleware_listen_port"`
	MiddlewareVIPIP          string `yaml:"middleware_vip_ip"`
	GNBLocalIP               string `yaml:"gnb_local_ip"`
	GNBProxyListenIP         string `yaml:"gnb_proxy_listen_ip"`
	GNBProxyListenPort       int    `yaml:"gnb_proxy_listen_port"`
	EnrollURL                string `yaml:"enroll_url"`
	EnrollmentJWT            string `yaml:"enrollment_jwt"`
	CACertPath               string `yaml:"ca_cert_path"`
	ClientCertPath           string `yaml:"client_cert_path"`
	ClientKeyPath            string `yaml:"client_key_path"`
	MiddlewareTLSServerName  string `yaml:"middleware_tls_server_name"`
	ReadTimeoutSeconds       int    `yaml:"read_timeout_seconds"`
	QUICIdleTimeoutSeconds   int    `yaml:"quic_idle_timeout_seconds"`
	QUICKeepAliveMS          int    `yaml:"quic_keepalive_ms"`
	EnrollmentTimeoutSeconds int    `yaml:"enrollment_timeout_seconds"`
}

type TunnelFrame struct {
	Stream  uint16
	PPID    uint32
	Payload []byte
}

func normalizeNGAPPPID(ppid uint32) uint32 {
	if ppid == 0 || ppid == 60 || ppid == 0x3c000000 {
		return ngapPPID
	}
	return ppid
}

func defaultConfig() Config {
	return Config{
		MiddlewareListenIP:       "10.64.0.1",
		MiddlewareListenPort:     29502,
		MiddlewareVIPIP:          "10.64.0.1",
		GNBLocalIP:               "10.64.0.100",
		GNBProxyListenIP:         "10.64.0.100",
		GNBProxyListenPort:       38412,
		EnrollURL:                "https://10.64.0.1:8443/enroll",
		EnrollmentJWT:            "",
		CACertPath:               "./pki/ca_cert.pem",
		ClientCertPath:           "./pki/gnb_client_cert.pem",
		ClientKeyPath:            "./pki/gnb_client_key.pem",
		MiddlewareTLSServerName:  "",
		ReadTimeoutSeconds:       10,
		QUICIdleTimeoutSeconds:   90,
		QUICKeepAliveMS:          20000,
		EnrollmentTimeoutSeconds: 10,
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
	cfg.GNBProxyListenIP = envOrDefault("GNB_PROXY_LISTEN_IP", cfg.GNBProxyListenIP)
	cfg.GNBProxyListenPort = envIntOrDefault("GNB_PROXY_LISTEN_PORT", cfg.GNBProxyListenPort)
	cfg.EnrollURL = envOrDefault("ENROLL_URL", cfg.EnrollURL)
	cfg.EnrollmentJWT = envOrDefault("ENROLLMENT_JWT", cfg.EnrollmentJWT)
	cfg.CACertPath = envOrDefault("CA_CERT_PATH", cfg.CACertPath)
	cfg.ClientCertPath = envOrDefault("CLIENT_CERT_PATH", cfg.ClientCertPath)
	cfg.ClientKeyPath = envOrDefault("CLIENT_KEY_PATH", cfg.ClientKeyPath)
	cfg.MiddlewareTLSServerName = envOrDefault("MIDDLEWARE_TLS_SERVER_NAME", cfg.MiddlewareTLSServerName)
	cfg.ReadTimeoutSeconds = envIntOrDefault("READ_TIMEOUT_SECONDS", cfg.ReadTimeoutSeconds)
	cfg.QUICIdleTimeoutSeconds = envIntOrDefault("QUIC_IDLE_TIMEOUT_SECONDS", cfg.QUICIdleTimeoutSeconds)
	cfg.QUICKeepAliveMS = envIntOrDefault("QUIC_KEEPALIVE_MS", cfg.QUICKeepAliveMS)
	cfg.EnrollmentTimeoutSeconds = envIntOrDefault("ENROLLMENT_TIMEOUT_SECONDS", cfg.EnrollmentTimeoutSeconds)

	if net.ParseIP(cfg.MiddlewareListenIP) == nil {
		return cfg, fmt.Errorf("invalid middleware_listen_ip: %s", cfg.MiddlewareListenIP)
	}
	if net.ParseIP(cfg.GNBLocalIP) == nil {
		return cfg, fmt.Errorf("invalid gnb_local_ip: %s", cfg.GNBLocalIP)
	}
	if net.ParseIP(cfg.GNBProxyListenIP) == nil {
		return cfg, fmt.Errorf("invalid gnb_proxy_listen_ip: %s", cfg.GNBProxyListenIP)
	}
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

func dialMiddleware(cfg Config) (net.Conn, error) {
	remote := net.JoinHostPort(cfg.MiddlewareListenIP, strconv.Itoa(cfg.MiddlewareListenPort))
	dialer := net.Dialer{Timeout: 5 * time.Second}
	if ip := net.ParseIP(cfg.GNBLocalIP); ip != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip, Port: 0}
	}
	return dialer.Dial("tcp", remote)
}

func handleUERANSIMGNB(cfg Config, pskRaw []byte, pskAEAD cipher.AEAD, gnbConn *sctp.SCTPConn) {
	defer gnbConn.Close()

	middlewareConn, err := dialMiddleware(cfg)
	if err != nil {
		log.Printf("dial middleware failed: %v", err)
		return
	}
	defer middlewareConn.Close()

	if cfg.ReadTimeoutSeconds > 0 {
		_ = middlewareConn.SetDeadline(time.Now().Add(time.Duration(cfg.ReadTimeoutSeconds) * time.Second))
	}

	sessionAEAD, err := clientHandshake(middlewareConn, pskAEAD, pskRaw)
	if err != nil {
		log.Printf("handshake with middleware failed: %v", err)
		return
	}
	_ = middlewareConn.SetDeadline(time.Time{})

	log.Printf("gNB proxy accepted SCTP from %s and established encrypted tunnel to middleware", gnbConn.RemoteAddr())

	go func() {
		buf := make([]byte, 65535)
		for {
			n, info, err := gnbConn.SCTPRead(buf)
			if err != nil {
				if errors.Is(err, io.EOF) {
					log.Printf("UERANSIM gNB closed SCTP connection")
					return
				}
				log.Printf("read from UERANSIM gNB failed: %v", err)
				_ = middlewareConn.Close()
				return
			}

			stream := uint16(0)
			ppid := ngapPPID
			if info != nil {
				stream = info.Stream
				ppid = normalizeNGAPPPID(info.PPID)
			}

			req := TunnelRequest{
				DestIP:  cfg.MiddlewareVIPIP,
				Payload: append([]byte(nil), buf[:n]...),
				Stream:  stream,
				PPID:    ppid,
			}
			if err := writeEncryptedJSON(middlewareConn, sessionAEAD, req); err != nil {
				log.Printf("forward encrypted request to middleware failed: %v", err)
				_ = middlewareConn.Close()
				return
			}
		}
	}()

	for {
		var reply TunnelReply
		if err := readEncryptedJSON(middlewareConn, sessionAEAD, &reply); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read encrypted reply from middleware failed: %v", err)
			}
			return
		}

		info := &sctp.SndRcvInfo{Stream: reply.Stream, PPID: normalizeNGAPPPID(reply.PPID)}
		if _, err := gnbConn.SCTPWrite(reply.Payload, info); err != nil {
			log.Printf("forward reply to UERANSIM gNB failed: %v", err)
			return
		}
	}
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

	laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(cfg.GNBProxyListenIP)}}, Port: cfg.GNBProxyListenPort}
	ln, err := sctp.ListenSCTP("sctp", laddr)
	if err != nil {
		return fmt.Errorf("listen gNB proxy SCTP on %s:%d failed: %w", cfg.GNBProxyListenIP, cfg.GNBProxyListenPort, err)
	}
	defer ln.Close()

	log.Printf("gNB proxy listening for UERANSIM on %s:%d", cfg.GNBProxyListenIP, cfg.GNBProxyListenPort)
	log.Printf("Forward target middleware %s:%d (VIP %s)", cfg.MiddlewareListenIP, cfg.MiddlewareListenPort, cfg.MiddlewareVIPIP)

	for {
		conn, err := ln.AcceptSCTP()
		if err != nil {
			log.Printf("accept UERANSIM gNB SCTP failed: %v", err)
			continue
		}
		go handleUERANSIMGNB(cfg, pskRaw, pskAEAD, conn)
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("gnb_proxy exited with error: %v", err)
	}
}
