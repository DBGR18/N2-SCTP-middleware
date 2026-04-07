package main

import (
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
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	EnrollListenIP           string `yaml:"enroll_listen_ip"`
	EnrollListenPort         int    `yaml:"enroll_listen_port"`
	MiddlewareSCTPLocalIP    string `yaml:"middleware_sctp_local_ip"`
	MiddlewareSCTPPort       int    `yaml:"middleware_sctp_listen_port"`
	AMFTargetIP              string `yaml:"amf_target_ip"`
	AMFTargetPort            int    `yaml:"amf_target_port"`
	JWTSecret                string `yaml:"jwt_secret"`
	CACertPath               string `yaml:"ca_cert_path"`
	CAKeyPath                string `yaml:"ca_key_path"`
	ServerCertPath           string `yaml:"server_cert_path"`
	ServerKeyPath            string `yaml:"server_key_path"`
	ClientCertValidityHours  int    `yaml:"client_cert_validity_hours"`
	ReadTimeoutSeconds       int    `yaml:"read_timeout_seconds"`
	QUICIdleTimeoutSeconds   int    `yaml:"quic_idle_timeout_seconds"`
	QUICKeepAliveMS          int    `yaml:"quic_keepalive_ms"`
	EnrollmentReadTimeoutSec int    `yaml:"enrollment_read_timeout_seconds"`
}

type EnrollmentClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type TunnelFrame struct {
	Stream  uint16
	PPID    uint32
	Payload []byte
}

type PKI struct {
	CACert      *x509.Certificate
	CAKey       *ecdsa.PrivateKey
	CACertPEM   []byte
	ServerTLS   tls.Certificate
	ServerLeaf  *x509.Certificate
	ServerRoots *x509.CertPool
}

type ProxyService struct {
	cfg     Config
	nextSID atomic.Uint64
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
		EnrollListenIP:           "10.64.0.1",
		EnrollListenPort:         8443,
		MiddlewareSCTPLocalIP:    "10.64.0.1",
		MiddlewareSCTPPort:       38413,
		AMFTargetIP:              "10.0.0.1",
		AMFTargetPort:            38412,
		JWTSecret:                "n2-demo-jwt-secret-change-me",
		CACertPath:               "./pki/ca_cert.pem",
		CAKeyPath:                "./pki/ca_key.pem",
		ServerCertPath:           "./pki/middleware_server_cert.pem",
		ServerKeyPath:            "./pki/middleware_server_key.pem",
		ClientCertValidityHours:  24,
		ReadTimeoutSeconds:       10,
		QUICIdleTimeoutSeconds:   90,
		QUICKeepAliveMS:          20000,
		EnrollmentReadTimeoutSec: 10,
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
	cfg.MiddlewareSCTPLocalIP = envOrDefault("MIDDLEWARE_SCTP_LOCAL_IP", cfg.MiddlewareSCTPLocalIP)
	cfg.MiddlewareSCTPPort = envIntOrDefault("MIDDLEWARE_SCTP_LISTEN_PORT", cfg.MiddlewareSCTPPort)
	cfg.AMFTargetIP = envOrDefault("AMF_TARGET_IP", cfg.AMFTargetIP)
	cfg.AMFTargetPort = envIntOrDefault("AMF_TARGET_PORT", cfg.AMFTargetPort)
	cfg.HandshakePSK = envOrDefault("HANDSHAKE_PSK", cfg.HandshakePSK)
	cfg.ReadTimeoutSeconds = envIntOrDefault("READ_TIMEOUT_SECONDS", cfg.ReadTimeoutSeconds)

	if net.ParseIP(cfg.MiddlewareListenIP) == nil {
		return cfg, fmt.Errorf("invalid middleware_listen_ip: %s", cfg.MiddlewareListenIP)
	}
	if net.ParseIP(cfg.MiddlewareSCTPLocalIP) == nil {
		return cfg, fmt.Errorf("invalid middleware_sctp_local_ip: %s", cfg.MiddlewareSCTPLocalIP)
	}
	if net.ParseIP(cfg.AMFTargetIP) == nil {
		return cfg, fmt.Errorf("invalid amf_target_ip: %s", cfg.AMFTargetIP)
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

func (p *ProxyService) registerSession(s *Session) {
	p.sessionsMu.Lock()
	defer p.sessionsMu.Unlock()
	p.sessions[s.id] = s
	p.amfToGnBMap[s.amfConn] = s.id
}

func (p *ProxyService) getSessionByAMFConn(conn *sctp.SCTPConn) (*Session, bool) {
	p.sessionsMu.RLock()
	defer p.sessionsMu.RUnlock()
	id, ok := p.amfToGnBMap[conn]
	if !ok {
		return nil, false
	}
	s, ok := p.sessions[id]
	if !ok {
		return nil, false
	}
	return s, true
}

func (p *ProxyService) unregisterSession(id uint64) {
	p.sessionsMu.Lock()
	s, ok := p.sessions[id]
	if ok {
		delete(p.sessions, id)
		if s.amfConn != nil {
			delete(p.amfToGnBMap, s.amfConn)
		}
	}
	p.sessionsMu.Unlock()

	if ok {
		if s.amfConn != nil {
			_ = s.amfConn.Close()
		}
		_ = s.gnbConn.Close()
	}
}

func (p *ProxyService) dialAMF() (*sctp.SCTPConn, error) {
	localIP := net.ParseIP(p.cfg.MiddlewareSCTPLocalIP)
	remoteIP := net.ParseIP(p.cfg.AMFTargetIP)
	if localIP == nil || remoteIP == nil {
		return nil, errors.New("invalid local/remote SCTP IP")
	}

	laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: localIP}}, Port: 0}
	raddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: remoteIP}}, Port: p.cfg.AMFTargetPort}

	conn, err := sctp.DialSCTP("sctp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial AMF SCTP %s:%d from %s: %w", p.cfg.AMFTargetIP, p.cfg.AMFTargetPort, p.cfg.MiddlewareSCTPLocalIP, err)
	}
	return conn, nil
}

func containsCipher(list []string, target string) bool {
	for _, c := range list {
		if c == target {
			return true
		}
	}
	return false
}

func (p *ProxyService) doHandshake(conn net.Conn) (cipher.AEAD, error) {
	var hello ClientHello
	if err := readEncryptedJSON(conn, p.pskAEAD, &hello); err != nil {
		return nil, fmt.Errorf("read client hello: %w", err)
	}
	if hello.Type != "client_hello" {
		return nil, fmt.Errorf("unexpected hello type: %s", hello.Type)
	}
	if !containsCipher(hello.CipherSuites, cipherSuiteAES256GCM) {
		return nil, errors.New("client does not support AES-256-GCM")
	}

	curve := ecdh.X25519()
	serverPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	clientPubRaw, err := base64.StdEncoding.DecodeString(hello.ClientPubKey)
	if err != nil {
		return nil, fmt.Errorf("decode client pubkey: %w", err)
	}
	clientPub, err := curve.NewPublicKey(clientPubRaw)
	if err != nil {
		return nil, fmt.Errorf("new client pubkey: %w", err)
	}

	resp := ServerHello{
		Type:           "server_hello",
		SelectedCipher: cipherSuiteAES256GCM,
		ServerPubKey:   base64.StdEncoding.EncodeToString(serverPriv.PublicKey().Bytes()),
	}
	if err := writeEncryptedJSON(conn, p.pskAEAD, resp); err != nil {
		return nil, fmt.Errorf("write server hello: %w", err)
	}

	sharedSecret, err := serverPriv.ECDH(clientPub)
	if err != nil {
		return nil, fmt.Errorf("derive ECDH shared secret: %w", err)
	}
	sessionKey := deriveSessionKey(sharedSecret, p.pskRaw)
	return newAEADFrom32BKey(sessionKey)
}

func (p *ProxyService) handleGNBConn(conn net.Conn) {
	id := p.nextID.Add(1)
	log.Printf("[session=%d] gNB connected from %s", id, conn.RemoteAddr())

	defer func() {
		_ = conn.Close()
	}()

	if p.cfg.ReadTimeoutSeconds > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(p.cfg.ReadTimeoutSeconds) * time.Second))
	}
	sessionAEAD, err := p.doHandshake(conn)
	if err != nil {
		log.Printf("[session=%d] handshake failed: %v", id, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	amfConn, err := p.dialAMF()
	if err != nil {
		log.Printf("[session=%d] AMF dial failed: %v", id, err)
		return
	}

	session := &Session{
		id:       id,
		gnbConn:  conn,
		amfConn:  amfConn,
		dataAEAD: sessionAEAD,
	}
	p.registerSession(session)
	defer p.unregisterSession(id)

	go p.forwardAMFToGNB(session)

	for {
		var req TunnelRequest
		if err := readEncryptedJSON(conn, sessionAEAD, &req); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("[session=%d] read encrypted request failed: %v", id, err)
			}
			return
		}

		if req.DestIP != p.cfg.MiddlewareVIPIP {
			log.Printf("[session=%d] warning: request target %s (expected VIP %s)", id, req.DestIP, p.cfg.MiddlewareVIPIP)
		}

		translatedIP := p.cfg.AMFTargetIP
		ppid := normalizeNGAPPPID(req.PPID)
		info := &sctp.SndRcvInfo{Stream: req.Stream, PPID: ppid}
		if _, err := amfConn.SCTPWrite(req.Payload, info); err != nil {
			log.Printf("[session=%d] write to AMF failed: %v", id, err)
			return
		}

		log.Printf("[session=%d] forwarded %d bytes (dest translated %s -> %s)", id, len(req.Payload), req.DestIP, translatedIP)
	}
}

func (p *ProxyService) forwardAMFToGNB(s *Session) {
	buf := make([]byte, 65535)
	for {
		n, info, err := s.amfConn.SCTPRead(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("[session=%d] read from AMF failed: %v", s.id, err)
			}
			return
		}

		stream := uint16(0)
		ppid := ngapPPID
		if info != nil {
			stream = info.Stream
			ppid = normalizeNGAPPPID(info.PPID)
		}

		reply := TunnelReply{
			FromIP:  p.cfg.AMFTargetIP,
			Payload: append([]byte(nil), buf[:n]...),
			Stream:  stream,
			PPID:    ppid,
		}
		targetSession, ok := p.getSessionByAMFConn(s.amfConn)
		if !ok {
			log.Printf("[session=%d] no gNB mapping found for AMF connection", s.id)
			return
		}

		if err := writeEncryptedJSON(targetSession.gnbConn, targetSession.dataAEAD, reply); err != nil {
			log.Printf("[session=%d] send encrypted reply to gNB failed: %v", s.id, err)
			return
		}

		log.Printf("[session=%d] AMF->gNB encrypted %d bytes", s.id, n)
	}
}

func (p *ProxyService) startSCTPServiceBind() error {
	ip := net.ParseIP(p.cfg.MiddlewareSCTPLocalIP)
	if ip == nil {
		return fmt.Errorf("invalid middleware_sctp_local_ip: %s", p.cfg.MiddlewareSCTPLocalIP)
	}

	addr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: ip}}, Port: p.cfg.MiddlewareSCTPPort}
	ln, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		return fmt.Errorf("listen SCTP on %s:%d failed: %w", p.cfg.MiddlewareSCTPLocalIP, p.cfg.MiddlewareSCTPPort, err)
	}

	log.Printf("SCTP service registered on %s:%d", p.cfg.MiddlewareSCTPLocalIP, p.cfg.MiddlewareSCTPPort)

	go func() {
		defer ln.Close()
		for {
			conn, err := ln.AcceptSCTP()
			if err != nil {
				log.Printf("SCTP accept error: %v", err)
				return
			}
			log.Printf("Accepted SCTP side connection from %s", conn.RemoteAddr())
			_ = conn.Close()
		}
	}()

	return nil
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

	proxy := &ProxyService{
		cfg:         cfg,
		pskRaw:      pskRaw,
		pskAEAD:     pskAEAD,
		sessions:    make(map[uint64]*Session),
		amfToGnBMap: make(map[*sctp.SCTPConn]uint64),
	}

	if err := proxy.startSCTPServiceBind(); err != nil {
		return err
	}

	listenAddr := fmt.Sprintf("%s:%d", cfg.MiddlewareListenIP, cfg.MiddlewareListenPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen encrypted tunnel on %s failed: %w", listenAddr, err)
	}
	defer ln.Close()

	log.Printf("Middleware encrypted tunnel listening on %s", listenAddr)
	log.Printf("AMF target %s:%d, VIP %s", cfg.AMFTargetIP, cfg.AMFTargetPort, cfg.MiddlewareVIPIP)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go proxy.handleGNBConn(conn)
	}
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("middleware exited with error: %v", err)
	}
}
