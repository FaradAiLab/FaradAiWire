package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/FaradAiLab/FaradAiWire/internal/agent"
	"github.com/FaradAiLab/FaradAiWire/internal/config"
	"github.com/FaradAiLab/FaradAiWire/internal/filter"
	"github.com/FaradAiLab/FaradAiWire/internal/guard"
	"github.com/FaradAiLab/FaradAiWire/internal/session"
	"github.com/FaradAiLab/FaradAiWire/pkg/mcp"
)

// StdioProxy wraps an MCP server command running as a subprocess via session.Dialer
// and redirects stdin/stdout through FaradAiWire security filters.
type StdioProxy struct {
	cmdPath     string
	cmdArgs     []string
	autoRestart bool
	pipeline    *filter.Pipeline
	userCtxCfg  config.UserContextConfig
	dialer      session.Dialer

	// Customizable I/O streams (defaults to os.Stdin, os.Stdout)
	in    io.Reader
	out   io.Writer
	outMu sync.Mutex

	mu          sync.Mutex
	isStopped   bool
	currSession *session.UpstreamSession
}

// NewStdioProxy initializes a new StdioProxy using default OS stdio streams and StdioDialer.
func NewStdioProxy(cmdPath string, cmdArgs []string, autoRestart bool, pipeline *filter.Pipeline, userCtxCfg config.UserContextConfig) *StdioProxy {
	return NewStdioProxyWithIO(cmdPath, cmdArgs, autoRestart, pipeline, userCtxCfg, os.Stdin, os.Stdout, session.NewStdioDialer())
}

// NewStdioProxyWithIO initializes a StdioProxy with customizable I/O streams and dialer for testing.
func NewStdioProxyWithIO(
	cmdPath string,
	cmdArgs []string,
	autoRestart bool,
	pipeline *filter.Pipeline,
	userCtxCfg config.UserContextConfig,
	in io.Reader,
	out io.Writer,
	dialer session.Dialer,
) *StdioProxy {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if dialer == nil {
		dialer = session.NewStdioDialer()
	}
	return &StdioProxy{
		cmdPath:     cmdPath,
		cmdArgs:     cmdArgs,
		autoRestart: autoRestart,
		pipeline:    pipeline,
		userCtxCfg:  userCtxCfg,
		in:          in,
		out:         out,
		dialer:      dialer,
	}
}

// Start launches the host stdin reader worker and the child subprocess monitor loop.
// It returns when context is canceled, host stdin reaches EOF, or subprocess exits without auto-restart.
func (s *StdioProxy) Start(ctx context.Context) error {
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	// Bind StdioProxy as the client notification sink for guard degradation notices
	if s.pipeline != nil {
		if gf, ok := s.pipeline.GetFilter("guard").(*guard.GuardFilter); ok && gf != nil {
			gf.SetNotificationSink(s)
		}
	}

	// Inbound host stdin scanner worker isolated from subprocess lifecycle
	linesCh := make(chan []byte, 128)
	go func() {
		defer close(linesCh)
		scanner := bufio.NewScanner(s.in)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 10*1024*1024) // 10MB limit

		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			lineCopy := make([]byte, len(line))
			copy(lineCopy, line)

			select {
			case <-runCtx.Done():
				return
			case linesCh <- lineCopy:
			}
		}
	}()

	for {
		s.mu.Lock()
		if s.isStopped {
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()

		err := s.runOnce(runCtx, linesCh)
		if err == nil {
			// Clean exit (e.g. host stdin closed / EOF)
			return nil
		}

		s.mu.Lock()
		if s.isStopped {
			s.mu.Unlock()
			return nil
		}
		if !s.autoRestart {
			s.mu.Unlock()
			return err
		}
		s.mu.Unlock()

		slog.Warn("MCP subprocess exited, auto-restarting in 1 second...", slog.String("error", err.Error()))
		select {
		case <-runCtx.Done():
			return runCtx.Err()
		case <-time.After(1 * time.Second):
		}
	}
}

// runOnce executes a single subprocess session lifecycle.
func (s *StdioProxy) runOnce(ctx context.Context, linesCh <-chan []byte) error {
	s.mu.Lock()
	if s.isStopped {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	fallbackUser := s.userCtxCfg.FallbackUser
	if fallbackUser == "" {
		fallbackUser = "local-developer"
	}
	fallbackRole := s.userCtxCfg.FallbackRole
	if fallbackRole == "" {
		fallbackRole = "Developer"
	}

	userCtx := context.WithValue(ctx, filter.UserContextKey, &filter.UserContext{
		UserID: fallbackUser,
		Role:   fallbackRole,
	})

	proto := agent.ProtocolConfig{
		ID:      "stdio-child",
		Name:    "stdio-child",
		Type:    "stdio",
		Command: s.cmdPath,
		Args:    s.cmdArgs,
	}

	eventCh := make(chan session.SSEEvent, 128)
	upSess := s.dialer.Dial(ctx, proto, eventCh, "stdio-proxy-client", nil)
	if upSess == nil || !upSess.IsHealthy() {
		return fmt.Errorf("failed to dial stdio subprocess: %s", s.cmdPath)
	}

	s.mu.Lock()
	s.currSession = upSess
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.currSession == upSess {
			s.currSession = nil
		}
		s.mu.Unlock()
		upSess.Close()
	}()

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()

	// Forward server notifications from eventCh to client stdout
	var eventWg sync.WaitGroup
	eventWg.Add(1)
	go func() {
		defer eventWg.Done()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case ev, ok := <-eventCh:
				if !ok {
					return
				}
				_ = s.writeOutput([]byte(ev.Data))
			}
		}
	}()

	// Inbound message dispatcher loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-upSess.ProcExitCh():
			s.mu.Lock()
			stopped := s.isStopped
			s.mu.Unlock()
			if stopped {
				return nil
			}
			return session.ErrSubprocessTerminated
		case line, ok := <-linesCh:
			if !ok {
				// Host stdin EOF: signal EOF to child subprocess stdin
				upSess.CloseStdin()
				// Await child process exit or server context termination
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-upSess.ProcExitCh():
					return nil
				}
			}
			go s.handleInboundLine(sessionCtx, userCtx, upSess, line)
		}
	}
}

// handleInboundLine routes a single JSON-RPC line through request/response filters and upSess.
func (s *StdioProxy) handleInboundLine(ctx context.Context, userCtx context.Context, upSess *session.UpstreamSession, line []byte) {
	req, _, isRequest, err := mcp.ParseMessage(line)
	if err != nil {
		resp := mcp.NewErrorResponse(nil, mcp.ErrParseError, "Parse error: "+err.Error(), nil)
		_ = s.writeJSON(resp)
		return
	}

	if isRequest && req != nil && !req.IsNotification() {
		var toolName string
		if req.Method == "tools/call" {
			var callParams struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(req.Params, &callParams); err == nil {
				toolName = callParams.Name
			}
		}

		// Process request filters
		filteredReq := req
		if s.pipeline != nil {
			var mcpErr *mcp.Error
			filteredReq, mcpErr = s.pipeline.ProcessRequest(userCtx, req)
			if mcpErr != nil {
				resp := mcp.NewErrorResponse(req.ID, mcpErr.Code, mcpErr.Message, mcpErr.Data)
				_ = s.writeJSON(resp)
				return
			}
		}

		// Execute against stdio subprocess
		resp, callErr := upSess.CallTool(ctx, filteredReq)
		if callErr != nil {
			errResp := mcp.NewErrorResponse(req.ID, mcp.ErrInternalError, callErr.Error(), nil)
			_ = s.writeJSON(errResp)
			return
		}

		// Process response filters
		filteredResp := resp
		if s.pipeline != nil {
			respCtx := userCtx
			if toolName != "" {
				respCtx = context.WithValue(respCtx, filter.ToolNameContextKey, toolName)
			}
			var mcpRespErr *mcp.Error
			filteredResp, mcpRespErr = s.pipeline.ProcessResponse(respCtx, resp)
			if mcpRespErr != nil {
				errResp := mcp.NewErrorResponse(resp.ID, mcpRespErr.Code, mcpRespErr.Message, mcpRespErr.Data)
				_ = s.writeJSON(errResp)
				return
			}
		}

		_ = s.writeJSON(filteredResp)
	} else {
		// Notifications or raw messages
		if isRequest && req != nil && s.pipeline != nil {
			filteredReq, mcpErr := s.pipeline.ProcessRequest(userCtx, req)
			if mcpErr != nil {
				return // Drop blocked notification
			}
			reqBytes, _ := json.Marshal(filteredReq)
			_ = upSess.SendNotification(reqBytes)
		} else {
			_ = upSess.SendNotification(line)
		}
	}
}

// Stop terminates the active stdio subprocess and cancels monitoring immediately.
func (s *StdioProxy) Stop() {
	s.mu.Lock()
	s.isStopped = true
	sess := s.currSession
	s.mu.Unlock()

	if sess != nil {
		sess.Close()
	}
}

func (s *StdioProxy) writeJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.writeOutput(data)
}

func (s *StdioProxy) writeOutput(data []byte) error {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	_, err := s.out.Write(append(data, '\n'))
	return err
}

// SendNotification writes an MCP JSON-RPC 2.0 notification directly to client stdout.
func (s *StdioProxy) SendNotification(ctx context.Context, method string, params interface{}) error {
	rawParams, err := json.Marshal(params)
	if err != nil {
		return err
	}
	notif := mcp.Request{
		JSONRPC: "2.0",
		Method:  method,
		Params:  rawParams,
	}
	return s.writeJSON(notif)
}
