package e2e

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
)

// QUICSuite covers the QUIC listener/dialer pair (listener type: quic, dialer
// type: quic) with the cipherKey obfuscation enabled. It uses the canonical
// GOST chaining pattern: a client container exposes a plain HTTP proxy that
// tunnels through a quic chain to a quic server (HTTP over QUIC).
type QUICSuite struct {
	suite.Suite
	ctx    context.Context
	echoC  testcontainers.Container
	echoIP string
}

func (s *QUICSuite) SetupSuite() {
	s.ctx = context.Background()

	s.T().Logf("start tcp echo container...")
	echoC, err := RunEchoContainer(s.ctx, SharedNetworkName)
	s.Require().NoError(err)
	s.echoC = echoC

	echoIP, err := echoC.ContainerIP(s.ctx)
	s.Require().NoError(err)
	s.echoIP = echoIP
}

func (s *QUICSuite) TearDownSuite() {
	if s.echoC != nil {
		s.echoC.Terminate(s.ctx)
	}
}

// startChain brings up a quic server (alias "quic-server", cipherKey enabled,
// http handler) and a client container that chains to it through a quic
// dialer. The client exposes port 8080 for curl.
func (s *QUICSuite) startChain() (testcontainers.Container, testcontainers.Container) {
	s.T().Helper()

	serverC, err := RunGostContainerWithOptions(s.ctx, SharedNetworkName,
		"testdata/quic/server.yaml", []string{"quic-server"}, []string{"18843/udp"})
	s.Require().NoError(err)

	rendered, err := RenderConfig("testdata/quic/client.yaml", ConfigData{ServerAddr: "quic-server:18843"})
	s.Require().NoError(err)
	s.T().Cleanup(func() { os.Remove(rendered) })

	clientC, err := RunGostContainerWithPorts(s.ctx, SharedNetworkName, rendered, "8080/tcp")
	s.Require().NoError(err)

	return serverC, clientC
}

// curlEcho runs curl through the client's local http proxy and returns the
// exit code plus the captured body.
func (s *QUICSuite) curlEcho(clientC testcontainers.Container) (int, string) {
	s.T().Helper()
	cmd := []string{"curl", "-s", "--max-time", "20", "-x", "http://127.0.0.1:8080",
		fmt.Sprintf("http://%s:5678/", s.echoIP)}
	code, out, _ := clientC.Exec(s.ctx, cmd)
	body, _ := io.ReadAll(out)
	return code, string(body)
}

// sendInvalidDatagram sends a single malformed (non-encrypted) UDP datagram to
// the quic server's listener, reproducing the issue's repro packet.
func (s *QUICSuite) sendInvalidDatagram(clientC testcontainers.Container) {
	s.T().Helper()
	cmd := []string{"python3", "-c",
		"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b\"x\", (\"quic-server\", 18843))"}
	code, out, err := clientC.Exec(s.ctx, cmd)
	s.Require().NoError(err)
	if code != 0 {
		b, _ := io.ReadAll(out)
		s.T().Fatalf("send invalid datagram failed (%d): %s", code, string(b))
	}
}

// TestQUICForwardCipherKeySurvivesInvalidDatagram verifies that a malformed
// UDP datagram does not close the shared QUIC transport (go-gost/x#125).
//
// With the bug, cipherConn.ReadFrom returned the decrypt error straight to
// quic-go, which treats any packet-socket error as fatal and closes the shared
// transport: a single invalid datagram kills the listener and correct clients
// subsequently time out. With the fix the invalid datagram is discarded and
// the listener keeps serving.
//
// Sequence: baseline forward works -> malformed datagram -> forward still works.
func (s *QUICSuite) TestQUICForwardCipherKeySurvivesInvalidDatagram() {
	serverC, clientC := s.startChain()
	defer serverC.Terminate(s.ctx)
	defer clientC.Terminate(s.ctx)

	// Baseline: a valid QUIC forward must work before we poke the listener.
	code, body := s.curlEcho(clientC)
	if code != 0 || !strings.Contains(body, "hello-gost") {
		s.dump("quic-baseline logs", clientC, serverC)
	}
	s.Require().Equal(0, code, "baseline QUIC forward should work")
	s.Require().Contains(body, "hello-gost")

	// Send one malformed UDP datagram to the quic listener's cipher socket.
	s.sendInvalidDatagram(clientC)

	// The listener must still be alive: a fresh QUIC forward must succeed.
	code, body = s.curlEcho(clientC)
	if code != 0 || !strings.Contains(body, "hello-gost") {
		s.dump("quic-after-invalid logs", clientC, serverC)
	}
	s.Require().Equal(0, code,
		"QUIC forward should still work after an invalid datagram (issue #125)")
	s.Require().Contains(body, "hello-gost",
		"listener must not close on an invalid datagram (issue #125)")
}

func (s *QUICSuite) dump(label string, cs ...testcontainers.Container) {
	for _, c := range cs {
		DumpLogs(s.T(), s.ctx, fmt.Sprintf("%s: %s", label, c.GetContainerID()), c)
	}
}

func TestQUICSuite(t *testing.T) {
	suite.Run(t, new(QUICSuite))
}
