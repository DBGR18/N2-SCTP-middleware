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
	if _, err := url.ParseRequestURI(cfg.EnrollURL); err != nil {
		return cfg, fmt.Errorf("invalid enroll_url: %w", err)
	}
	if cfg.QUICIdleTimeoutSeconds <= 0 {
		cfg.QUICIdleTimeoutSeconds = 90
	}
	if cfg.QUICKeepAliveMS <= 0 {
		cfg.QUICKeepAliveMS = 20000
	}
	if cfg.EnrollmentTimeoutSeconds <= 0 {
		cfg.EnrollmentTimeoutSeconds = 10
	}

	return cfg, nil
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
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

func loadCACertPool(path string) (*x509.CertPool, *x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read ca cert %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, nil, fmt.Errorf("append ca cert from %s failed", path)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("no certificate block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca cert %s: %w", path, err)
	}
	return pool, cert, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func loadClientKeyPair(certPath, keyPath string) (tls.Certificate, *x509.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, nil, errors.New("empty certificate chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("parse client cert leaf: %w", err)
	}
	cert.Leaf = leaf
	return cert, leaf, nil
}

func hasUsableClientCert(cfg Config, caPool *x509.CertPool) (bool, error) {
	if !fileExists(cfg.ClientCertPath) || !fileExists(cfg.ClientKeyPath) {
		return false, nil
	}

	cert, leaf, err := loadClientKeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return false, nil
	}
	_ = cert

	if time.Now().After(leaf.NotAfter.Add(-1 * time.Minute)) {
		return false, nil
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return false, nil
	}

	return true, nil
}

func enrollClientCertificate(cfg Config, caPool *x509.CertPool) error {
	if strings.TrimSpace(cfg.EnrollmentJWT) == "" {
		return errors.New("enrollment_jwt is empty; run middleware with -generate-jwt to create one")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate client private key: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "gnb-proxy",
			Organization: []string{"N2 Encryption"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	req, err := http.NewRequest(http.MethodPost, cfg.EnrollURL, bytes.NewReader(csrPEM))
	if err != nil {
		return fmt.Errorf("build enroll request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.EnrollmentJWT)
	req.Header.Set("Content-Type", "application/x-pem-file")

	httpClient := &http.Client{
		Timeout: time.Duration(cfg.EnrollmentTimeoutSeconds) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS13,
				ServerName: cfg.MiddlewareTLSServerName,
			},
		},
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("enroll request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, frameMaxSize))
	if err != nil {
		return fmt.Errorf("read enroll response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enroll failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("enroll response is not a certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrolled cert: %w", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: caPool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("verify enrolled cert failed: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal client private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := ensureParentDir(cfg.ClientKeyPath); err != nil {
		return err
	}
	if err := ensureParentDir(cfg.ClientCertPath); err != nil {
		return err
	}

	if err := os.WriteFile(cfg.ClientKeyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write client key: %w", err)
	}
	if err := os.WriteFile(cfg.ClientCertPath, body, 0o644); err != nil {
		return fmt.Errorf("write client cert: %w", err)
	}

	log.Printf("Client certificate enrolled successfully and saved to %s", cfg.ClientCertPath)
	return nil
}

func ensureClientCertificate(cfg Config, caPool *x509.CertPool) error {
	usable, err := hasUsableClientCert(cfg, caPool)
	if err != nil {
		return err
	}
	if usable {
		return nil
	}
	return enrollClientCertificate(cfg, caPool)
}

func dialQUIC(cfg Config, clientCert tls.Certificate, caPool *x509.CertPool) (*quic.Conn, *net.UDPConn, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(cfg.MiddlewareListenIP, strconv.Itoa(cfg.MiddlewareListenPort)))
	if err != nil {
		return nil, nil, fmt.Errorf("resolve middleware UDP address: %w", err)
	}
	localAddr := &net.UDPAddr{IP: net.ParseIP(cfg.GNBLocalIP), Port: 0}
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("bind local UDP %s failed: %w", cfg.GNBLocalIP, err)
	}

	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{quicALPN},
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   cfg.MiddlewareTLSServerName,
	}

	qConn, err := quic.Dial(context.Background(), udpConn, remoteAddr, tlsConf, &quic.Config{
		KeepAlivePeriod: time.Duration(cfg.QUICKeepAliveMS) * time.Millisecond,
		MaxIdleTimeout:  time.Duration(cfg.QUICIdleTimeoutSeconds) * time.Second,
	})
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, fmt.Errorf("dial QUIC middleware failed: %w", err)
	}

	return qConn, udpConn, nil
}

func forwardGNBToStream(gnbConn *sctp.SCTPConn, stream *quic.Stream) error {
	buf := make([]byte, 65535)
	for {
		n, info, err := gnbConn.SCTPRead(buf)
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
			return err
		}
	}
}

func forwardStreamToGNB(stream *quic.Stream, gnbConn *sctp.SCTPConn) error {
	for {
		frame, err := readTunnelFrame(stream)
		if err != nil {
			return err
		}
		info := &sctp.SndRcvInfo{Stream: frame.Stream, PPID: normalizeNGAPPPID(frame.PPID)}
		if _, err := gnbConn.SCTPWrite(frame.Payload, info); err != nil {
			return err
		}
	}
}

func handleUERANSIMGNB(cfg Config, caPool *x509.CertPool, gnbConn *sctp.SCTPConn) {
	defer gnbConn.Close()

	if err := ensureClientCertificate(cfg, caPool); err != nil {
		log.Printf("enroll/check client cert failed: %v", err)
		return
	}

	clientCert, _, err := loadClientKeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		log.Printf("load client certificate failed: %v", err)
		return
	}

	qConn, udpConn, err := dialQUIC(cfg, clientCert, caPool)
	if err != nil {
		log.Printf("connect QUIC middleware failed: %v", err)
		return
	}
	defer udpConn.Close()
	defer qConn.CloseWithError(0, "session closed")

	stream, err := qConn.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("open QUIC stream failed: %v", err)
		return
	}

	log.Printf("Accepted SCTP from %s; QUIC mTLS session established to %s:%d", gnbConn.RemoteAddr(), cfg.MiddlewareListenIP, cfg.MiddlewareListenPort)

	errCh := make(chan error, 2)
	go func() {
		errCh <- forwardGNBToStream(gnbConn, stream)
	}()
	go func() {
		errCh <- forwardStreamToGNB(stream, gnbConn)
	}()

	firstErr := <-errCh
	stream.CancelRead(0)
	stream.CancelWrite(0)
	_ = qConn.CloseWithError(0, "closing after one side ended")
	_ = gnbConn.Close()
	secondErr := <-errCh

	if firstErr != nil && !errors.Is(firstErr, io.EOF) {
		log.Printf("gNB forwarding path ended with error: %v", firstErr)
	}
	if secondErr != nil && !errors.Is(secondErr, io.EOF) {
		log.Printf("middleware forwarding path ended with error: %v", secondErr)
	}
}

func run(configPath string) error {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	caPool, _, err := loadCACertPool(cfg.CACertPath)
	if err != nil {
		return err
	}

	laddr := &sctp.SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP(cfg.GNBProxyListenIP)}}, Port: cfg.GNBProxyListenPort}
	ln, err := sctp.ListenSCTP("sctp", laddr)
	if err != nil {
		return fmt.Errorf("listen gNB proxy SCTP on %s:%d failed: %w", cfg.GNBProxyListenIP, cfg.GNBProxyListenPort, err)
	}
	defer ln.Close()

	log.Printf("gNB proxy listening SCTP on %s:%d", cfg.GNBProxyListenIP, cfg.GNBProxyListenPort)
	log.Printf("Middleware QUIC target %s:%d (VIP %s)", cfg.MiddlewareListenIP, cfg.MiddlewareListenPort, cfg.MiddlewareVIPIP)

	for {
		conn, err := ln.AcceptSCTP()
		if err != nil {
			log.Printf("accept UERANSIM gNB SCTP failed: %v", err)
			continue
		}
		go handleUERANSIMGNB(cfg, caPool, conn)
	}
}

func main() {
	defaultConfigPath := envOrDefault("N2_PROXY_CONFIG", "./config.yaml")
	configPath := flag.String("config", defaultConfigPath, "Path to config file")
	flag.Parse()

	if err := run(*configPath); err != nil {
		log.Fatalf("gnb_proxy exited with error: %v", err)
	}
}
