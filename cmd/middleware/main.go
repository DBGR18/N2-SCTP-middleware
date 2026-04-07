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
	cfg.EnrollListenIP = envOrDefault("ENROLL_LISTEN_IP", cfg.EnrollListenIP)
	cfg.EnrollListenPort = envIntOrDefault("ENROLL_LISTEN_PORT", cfg.EnrollListenPort)
	cfg.MiddlewareSCTPLocalIP = envOrDefault("MIDDLEWARE_SCTP_LOCAL_IP", cfg.MiddlewareSCTPLocalIP)
	cfg.MiddlewareSCTPPort = envIntOrDefault("MIDDLEWARE_SCTP_LISTEN_PORT", cfg.MiddlewareSCTPPort)
	cfg.AMFTargetIP = envOrDefault("AMF_TARGET_IP", cfg.AMFTargetIP)
	cfg.AMFTargetPort = envIntOrDefault("AMF_TARGET_PORT", cfg.AMFTargetPort)
	cfg.JWTSecret = envOrDefault("JWT_SECRET", cfg.JWTSecret)
	cfg.CACertPath = envOrDefault("CA_CERT_PATH", cfg.CACertPath)
	cfg.CAKeyPath = envOrDefault("CA_KEY_PATH", cfg.CAKeyPath)
	cfg.ServerCertPath = envOrDefault("SERVER_CERT_PATH", cfg.ServerCertPath)
	cfg.ServerKeyPath = envOrDefault("SERVER_KEY_PATH", cfg.ServerKeyPath)
	cfg.ClientCertValidityHours = envIntOrDefault("CLIENT_CERT_VALIDITY_HOURS", cfg.ClientCertValidityHours)
	cfg.ReadTimeoutSeconds = envIntOrDefault("READ_TIMEOUT_SECONDS", cfg.ReadTimeoutSeconds)
	cfg.QUICIdleTimeoutSeconds = envIntOrDefault("QUIC_IDLE_TIMEOUT_SECONDS", cfg.QUICIdleTimeoutSeconds)
	cfg.QUICKeepAliveMS = envIntOrDefault("QUIC_KEEPALIVE_MS", cfg.QUICKeepAliveMS)
	cfg.EnrollmentReadTimeoutSec = envIntOrDefault("ENROLLMENT_READ_TIMEOUT_SECONDS", cfg.EnrollmentReadTimeoutSec)

	if net.ParseIP(cfg.MiddlewareListenIP) == nil {
		return cfg, fmt.Errorf("invalid middleware_listen_ip: %s", cfg.MiddlewareListenIP)
	}
	if net.ParseIP(cfg.EnrollListenIP) == nil {
		return cfg, fmt.Errorf("invalid enroll_listen_ip: %s", cfg.EnrollListenIP)
	}
	if net.ParseIP(cfg.MiddlewareSCTPLocalIP) == nil {
		return cfg, fmt.Errorf("invalid middleware_sctp_local_ip: %s", cfg.MiddlewareSCTPLocalIP)
	}
	if net.ParseIP(cfg.AMFTargetIP) == nil {
		return cfg, fmt.Errorf("invalid amf_target_ip: %s", cfg.AMFTargetIP)
	}
	if cfg.JWTSecret == "" {
		return cfg, errors.New("jwt_secret cannot be empty")
	}
	if cfg.ClientCertValidityHours <= 0 {
		return cfg, errors.New("client_cert_validity_hours must be > 0")
	}
	if cfg.QUICIdleTimeoutSeconds <= 0 {
		cfg.QUICIdleTimeoutSeconds = 90
	}
	if cfg.QUICKeepAliveMS <= 0 {
		cfg.QUICKeepAliveMS = 20000
	}
	if cfg.EnrollmentReadTimeoutSec <= 0 {
		cfg.EnrollmentReadTimeoutSec = 10
	}

	return cfg, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func writeFile(path string, content []byte, perm os.FileMode) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}
	return os.WriteFile(path, content, perm)
}

func parsePEMCertificate(path string) (*x509.Certificate, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("no CERTIFICATE block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, raw, nil
}

func parsePEMECDSAKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("no PEM key block in %s", path)
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key in %s is not ECDSA", path)
	}
	return key, nil
}

func loadOrCreateCA(cfg Config) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	certExists := fileExists(cfg.CACertPath)
	keyExists := fileExists(cfg.CAKeyPath)

	if certExists != keyExists {
		return nil, nil, nil, errors.New("ca_cert_path and ca_key_path must both exist or both be absent")
	}

	if certExists {
		cert, certPEM, err := parsePEMCertificate(cfg.CACertPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load root CA cert: %w", err)
		}
		key, err := parsePEMECDSAKey(cfg.CAKeyPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load root CA key: %w", err)
		}
		if !cert.IsCA {
			return nil, nil, nil, errors.New("configured root certificate is not a CA certificate")
		}
		if time.Now().After(cert.NotAfter) {
			return nil, nil, nil, errors.New("configured root CA certificate is expired")
		}
		return cert, key, certPEM, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate root CA key: %w", err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate root CA serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "N2 Middleware Root CA", Organization: []string{"N2 Encryption"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create root CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal root CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFile(cfg.CACertPath, certPEM, 0o644); err != nil {
		return nil, nil, nil, fmt.Errorf("write root CA cert: %w", err)
	}
	if err := writeFile(cfg.CAKeyPath, keyPEM, 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("write root CA key: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse generated root CA cert: %w", err)
	}
	return cert, key, certPEM, nil
}

func uniqueIPs(ips ...net.IP) []net.IP {
	seen := make(map[string]struct{})
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		key := ip.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func loadOrCreateServerCert(cfg Config, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, caPEM []byte) (tls.Certificate, *x509.Certificate, error) {
	certExists := fileExists(cfg.ServerCertPath)
	keyExists := fileExists(cfg.ServerKeyPath)

	if certExists != keyExists {
		return tls.Certificate{}, nil, errors.New("server_cert_path and server_key_path must both exist or both be absent")
	}

	if certExists {
		cert, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
		if err == nil && len(cert.Certificate) > 0 {
			leaf, leafErr := x509.ParseCertificate(cert.Certificate[0])
			if leafErr == nil {
				roots := x509.NewCertPool()
				roots.AddCert(caCert)
				_, verifyErr := leaf.Verify(x509.VerifyOptions{
					Roots:       roots,
					CurrentTime: time.Now(),
					KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				})
				if verifyErr == nil {
					cert.Leaf = leaf
					return cert, leaf, nil
				}
			}
		}
		log.Printf("existing server certificate is invalid, regenerating")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate server key: %w", err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("generate server serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "n2-middleware",
			Organization: []string{"N2 Encryption"},
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "n2-middleware"},
		IPAddresses: uniqueIPs(
			net.ParseIP(cfg.MiddlewareListenIP),
			net.ParseIP(cfg.EnrollListenIP),
			net.ParseIP("127.0.0.1"),
		),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("create server certificate: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certPEM := append(leafPEM, caPEM...)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("marshal server key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := writeFile(cfg.ServerCertPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("write server certificate: %w", err)
	}
	if err := writeFile(cfg.ServerKeyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("write server key: %w", err)
	}

	serverTLS, err := tls.LoadX509KeyPair(cfg.ServerCertPath, cfg.ServerKeyPath)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("reload server key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(serverTLS.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse server leaf cert: %w", err)
	}
	serverTLS.Leaf = leaf
	return serverTLS, leaf, nil
}

func initPKI(cfg Config) (*PKI, error) {
	caCert, caKey, caPEM, err := loadOrCreateCA(cfg)
	if err != nil {
		return nil, err
	}
	serverTLS, serverLeaf, err := loadOrCreateServerCert(cfg, caCert, caKey, caPEM)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	return &PKI{
		CACert:      caCert,
		CAKey:       caKey,
		CACertPEM:   caPEM,
		ServerTLS:   serverTLS,
		ServerLeaf:  serverLeaf,
		ServerRoots: roots,
	}, nil
}

func generateEnrollmentJWT(secret string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := EnrollmentClaims{
		Role: "gnb",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func validateEnrollmentToken(tokenString, secret string) error {
	claims := &EnrollmentClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		return []byte(secret), nil
	})
	if err != nil {
		return fmt.Errorf("jwt validation failed: %w", err)
	}
	if claims.Role != "gnb" {
		return errors.New("jwt role must be gnb")
	}
	return nil
}

type enrollmentHandler struct {
	cfg Config
	pki *PKI
}

func (h *enrollmentHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authz, "Bearer ") {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if token == "" {
		http.Error(w, "empty bearer token", http.StatusUnauthorized)
		return
	}
	if err := validateEnrollmentToken(token, h.cfg.JWTSecret); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, frameMaxSize))
	if err != nil {
		http.Error(w, "failed to read csr body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	clientCertPEM, err := h.signCSR(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(clientCertPEM)
}

func (h *enrollmentHandler) signCSR(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("invalid CSR PEM")
	}
	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected CSR PEM type %s", block.Type)
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature check failed: %w", err)
	}

	serial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate client serial: %w", err)
	}
	now := time.Now()
	subject := csr.Subject
	if subject.CommonName == "" {
		subject.CommonName = "gnb-proxy"
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-2 * time.Minute),
		NotAfter:     now.Add(time.Duration(h.cfg.ClientCertValidityHours) * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, h.pki.CACert, csr.PublicKey, h.pki.CAKey)
	if err != nil {
		return nil, fmt.Errorf("sign client certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(certPEM, h.pki.CACertPEM...), nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func writeTunnelFrame(w io.Writer, stream uint16, ppid uint32, payload []byte) error {
	if len(payload) == 0 || len(payload) > frameMaxSize {
		return fmt.Errorf("invalid payload length %d", len(payload))
	}
	header := make([]byte, 10)
	binary.BigEndian.PutUint16(header[0:2], stream)
	binary.BigEndian.PutUint32(header[2:6], normalizeNGAPPPID(ppid))
	binary.BigEndian.PutUint32(header[6:10], uint32(len(payload)))

	if err := writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func readTunnelFrame(r io.Reader) (*TunnelFrame, error) {
	header := make([]byte, 10)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	stream := binary.BigEndian.Uint16(header[0:2])
	ppid := binary.BigEndian.Uint32(header[2:6])
	length := binary.BigEndian.Uint32(header[6:10])
	if length == 0 || length > frameMaxSize {
		return nil, fmt.Errorf("invalid frame payload length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &TunnelFrame{Stream: stream, PPID: ppid, Payload: payload}, nil
}

func (p *ProxyService) dialAMF() (*sctp.SCTPConn, error) {
	localIP := net.ParseIP(p.cfg.MiddlewareSCTPLocalIP)
	remoteIP := net.ParseIP(p.cfg.AMFTargetIP)
	if localIP == nil || remoteIP == nil {
		return nil, errors.New("invalid local/remote SCTP IP")
	}

	laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: localIP}}, Port: p.cfg.MiddlewareSCTPPort}
	raddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: remoteIP}}, Port: p.cfg.AMFTargetPort}

	conn, err := sctp.DialSCTP("sctp", laddr, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial AMF SCTP %s:%d from %s:%d: %w", p.cfg.AMFTargetIP, p.cfg.AMFTargetPort, p.cfg.MiddlewareSCTPLocalIP, p.cfg.MiddlewareSCTPPort, err)
	}
	return conn, nil
}

func (p *ProxyService) handleQUICConn(conn *quic.Conn) {
	sid := p.nextSID.Add(1)
	log.Printf("[session=%d] gNB QUIC connected from %s", sid, conn.RemoteAddr())

	defer func() {
		_ = conn.CloseWithError(0, "session closed")
	}()

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		log.Printf("[session=%d] accept stream failed: %v", sid, err)
		return
	}

	amfConn, err := p.dialAMF()
	if err != nil {
		log.Printf("[session=%d] AMF dial failed: %v", sid, err)
		return
	}
	defer amfConn.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- p.forwardStreamToAMF(sid, stream, amfConn)
	}()
	go func() {
		errCh <- p.forwardAMFToStream(sid, amfConn, stream)
	}()

	firstErr := <-errCh
	stream.CancelRead(0)
	stream.CancelWrite(0)
	_ = amfConn.Close()
	secondErr := <-errCh

	if firstErr != nil && !errors.Is(firstErr, io.EOF) {
		log.Printf("[session=%d] stream ended with error: %v", sid, firstErr)
	}
	if secondErr != nil && !errors.Is(secondErr, io.EOF) {
		log.Printf("[session=%d] reverse path ended with error: %v", sid, secondErr)
	}
}

func (p *ProxyService) forwardStreamToAMF(sid uint64, stream *quic.Stream, amfConn *sctp.SCTPConn) error {
	for {
		frame, err := readTunnelFrame(stream)
		if err != nil {
			return err
		}

		info := &sctp.SndRcvInfo{Stream: frame.Stream, PPID: normalizeNGAPPPID(frame.PPID)}
		if _, err := amfConn.SCTPWrite(frame.Payload, info); err != nil {
			return fmt.Errorf("write to AMF failed: %w", err)
		}

		log.Printf("[session=%d] forwarded %d bytes gNB->AMF", sid, len(frame.Payload))
	}
}

func (p *ProxyService) forwardAMFToStream(sid uint64, amfConn *sctp.SCTPConn, stream *quic.Stream) error {
	buf := make([]byte, 65535)
	for {
		n, info, err := amfConn.SCTPRead(buf)
		if err != nil {
			return err
		}

		streamID := uint16(0)
		ppid := ngapPPID
		if info != nil {
			streamID = info.Stream
			ppid = normalizeNGAPPPID(info.PPID)
		}

		payload := append([]byte(nil), buf[:n]...)
		if err := writeTunnelFrame(stream, streamID, ppid, payload); err != nil {
			return fmt.Errorf("write to QUIC stream failed: %w", err)
		}

		log.Printf("[session=%d] forwarded %d bytes AMF->gNB", sid, n)
	}
}

func startEnrollmentServer(cfg Config, pki *PKI) (*http.Server, error) {
	h := &enrollmentHandler{cfg: cfg, pki: pki}
	mux := http.NewServeMux()
	mux.Handle("/enroll", h)

	addr := net.JoinHostPort(cfg.EnrollListenIP, strconv.Itoa(cfg.EnrollListenPort))
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  time.Duration(cfg.EnrollmentReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(cfg.EnrollmentReadTimeoutSec) * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{pki.ServerTLS},
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("enrollment listener setup failed: %w", err)
	}

	go func() {
		if err := server.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("enrollment server stopped with error: %v", err)
		}
	}()

	log.Printf("Enrollment HTTPS listening on %s", addr)
	return server, nil
}

func (p *ProxyService) runQUICServer(serverTLS tls.Certificate, clientCAs *x509.CertPool) error {
	addr := net.JoinHostPort(p.cfg.MiddlewareListenIP, strconv.Itoa(p.cfg.MiddlewareListenPort))
	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
		Certificates: []tls.Certificate{serverTLS},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}

	listener, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		KeepAlivePeriod: time.Duration(p.cfg.QUICKeepAliveMS) * time.Millisecond,
		MaxIdleTimeout:  time.Duration(p.cfg.QUICIdleTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("listen QUIC on %s failed: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("Middleware QUIC mTLS listening on %s", addr)
	log.Printf("AMF target %s:%d (middleware VIP %s)", p.cfg.AMFTargetIP, p.cfg.AMFTargetPort, p.cfg.MiddlewareVIPIP)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("accept QUIC connection failed: %v", err)
			continue
		}
		go p.handleQUICConn(conn)
	}
}

func run(configPath string, generateJWTOnly bool) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	if generateJWTOnly {
		token, err := generateEnrollmentJWT(cfg.JWTSecret, 10*time.Minute)
		if err != nil {
			return fmt.Errorf("generate jwt: %w", err)
		}
		fmt.Println(token)
		return nil
	}

	pki, err := initPKI(cfg)
	if err != nil {
		return fmt.Errorf("initialize PKI: %w", err)
	}

	if _, err := startEnrollmentServer(cfg, pki); err != nil {
		return err
	}

	proxy := &ProxyService{cfg: cfg}
	return proxy.runQUICServer(pki.ServerTLS, pki.ServerRoots)
}

func main() {
	defaultConfigPath := envOrDefault("N2_PROXY_CONFIG", "./config.yaml")
	configPath := flag.String("config", defaultConfigPath, "Path to config file")
	generateJWTOnly := flag.Bool("generate-jwt", false, "Generate a short-lived gNB enrollment JWT and exit")
	flag.Parse()

	if err := run(*configPath, *generateJWTOnly); err != nil {
		log.Fatalf("middleware exited with error: %v", err)
	}
}
