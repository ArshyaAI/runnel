package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/ArshyaAI/runnel/internal/buildinfo"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
	"github.com/ArshyaAI/runnel/internal/receipt"
	"github.com/ArshyaAI/runnel/internal/ui"
	"github.com/ArshyaAI/runnel/schema"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
)

const (
	ExitOK                = 0
	ExitUsage             = 2
	ExitPartial           = 3
	ExitUnavailable       = 4
	ExitRecoveryLocked    = 4
	ExitRecoveryPartial   = 5
	ExitRecoveryFailed    = 6
	ExitReceiptIntegrity  = 7
	ExitRecoveryCancelled = 130
)

// ExitError lets the small cmd wrapper preserve useful shell exit codes while
// tests can inspect the underlying error without calling os.Exit.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}
func (e *ExitError) Unwrap() error { return e.Err }

type ExplainService interface {
	Explain(context.Context, string) (string, error)
}
type RecoveryService interface {
	Recover(context.Context, io.Reader, io.Writer) error
}
type HistoryService interface {
	History(context.Context) ([]receipt.Entry, error)
}
type ReceiptService interface {
	Receipt(context.Context, string, bool) ([]byte, error)
}
type DoctorService interface {
	Doctor(context.Context, bool) ([]byte, error)
}

type Options struct {
	In       io.Reader
	Out      io.Writer
	ErrOut   io.Writer
	Scan     SnapshotService
	Explain  ExplainService
	Recovery RecoveryService
	History  HistoryService
	Receipt  ReceiptService
	Doctor   DoctorService
}

// NewRoot composes the complete public command surface. All capabilities are
// injected so the command package never invents detector candidates or signals.
func NewRoot(options Options) *cobra.Command {
	if options.In == nil {
		options.In = os.Stdin
	}
	if options.Out == nil {
		options.Out = os.Stdout
	}
	if options.ErrOut == nil {
		options.ErrOut = os.Stderr
	}
	if options.Scan == nil {
		options.Scan = NewLocalScanner()
	}
	root := &cobra.Command{Use: "runnel", Short: "Trace the work. Stop only what the evidence proves safe.", SilenceUsage: true, SilenceErrors: true}
	root.SetIn(options.In)
	root.SetOut(options.Out)
	root.SetErr(options.ErrOut)
	root.RunE = func(cmd *cobra.Command, _ []string) error { return runScan(cmd, options.Scan, false) }
	root.AddCommand(scanCommand(options), explainCommand(options), recoverCommand(options), historyCommand(options), receiptCommand(options), doctorCommand(options), completionCommand(), versionCommand())
	return root
}

func scanCommand(options Options) *cobra.Command {
	var asJSON bool
	c := &cobra.Command{Use: "scan", Short: "Read-only workflow snapshot", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return runScan(cmd, options.Scan, asJSON) }}
	c.Flags().BoolVar(&asJSON, "json", false, "emit strict JSON")
	return c
}
func runScan(cmd *cobra.Command, service SnapshotService, asJSON bool) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	tty := !asJSON && terminalWriter(cmd.OutOrStdout())
	if tty {
		// Paint the stable shell before the first potentially slow platform
		// probe. This is intentionally plain text so a failed probe still leaves
		// a useful terminal state.
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "READY  Runnel workflow radar")
	}
	snapshot, err := service.Snapshot(ctx)
	if asJSON {
		data, renderErr := ui.JSON(snapshot)
		if renderErr != nil {
			return &ExitError{ExitUnavailable, renderErr}
		}
		_, _ = cmd.OutOrStdout().Write(data)
	} else if tty {
		program := tea.NewProgram(ui.NewTUIModel(snapshot), tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.OutOrStdout()))
		if _, tuiErr := program.Run(); tuiErr != nil {
			return &ExitError{ExitUnavailable, tuiErr}
		}
	} else if renderErr := ui.Plain(cmd.OutOrStdout(), snapshot); renderErr != nil {
		return &ExitError{ExitUnavailable, renderErr}
	}
	if err != nil {
		return &ExitError{ExitPartial, err}
	}
	return nil
}

type unavailableExplain struct{}

func (unavailableExplain) Explain(context.Context, string) (string, error) {
	return "", errors.New("evidence explanation is unavailable: no deep evidence service configured")
}

type unavailableRecovery struct{}

type unavailableRecoveryError struct{}

func (unavailableRecoveryError) Error() string {
	return "recovery unavailable: no live recovery capability enabled"
}
func (unavailableRecoveryError) ExitCode() int { return ExitRecoveryLocked }

func (unavailableRecovery) Recover(context.Context, io.Reader, io.Writer) error {
	return unavailableRecoveryError{}
}

type unavailableHistory struct{}

func (unavailableHistory) History(context.Context) ([]receipt.Entry, error) {
	return nil, errors.New("receipt history is unavailable: no receipt service configured")
}

type unavailableReceipt struct{}

func (unavailableReceipt) Receipt(context.Context, string, bool) ([]byte, error) {
	return nil, errors.New("receipt is unavailable: no receipt service configured")
}

func explainCommand(o Options) *cobra.Command {
	if o.Explain == nil {
		o.Explain = unavailableExplain{}
	}
	return &cobra.Command{Use: "explain <finding>", Short: "Show bounded evidence for a finding", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		v, e := o.Explain.Explain(c.Context(), args[0])
		if e != nil {
			return &ExitError{ExitUnavailable, e}
		}
		_, _ = fmt.Fprintln(c.OutOrStdout(), v)
		return nil
	}}
}
func recoverCommand(o Options) *cobra.Command {
	if o.Recovery == nil {
		o.Recovery = unavailableRecovery{}
	}
	return &cobra.Command{Use: "recover", Short: "Attempt gated recovery (never available without an injected capability)", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		if !terminalReader(c.InOrStdin()) || !terminalWriter(c.OutOrStdout()) {
			return &ExitError{ExitRecoveryLocked, errors.New("recover requires interactive input and output terminals")}
		}
		e := o.Recovery.Recover(c.Context(), c.InOrStdin(), c.OutOrStdout())
		if e != nil {
			code := ExitRecoveryFailed
			var coded interface{ ExitCode() int }
			if errors.As(e, &coded) {
				code = coded.ExitCode()
			}
			if code != ExitRecoveryLocked && code != ExitRecoveryPartial && code != ExitRecoveryFailed && code != ExitReceiptIntegrity && code != ExitRecoveryCancelled {
				code = ExitRecoveryFailed
			}
			return &ExitError{code, e}
		}
		return nil
	}}
}
func historyCommand(o Options) *cobra.Command {
	if o.History == nil {
		o.History = unavailableHistory{}
	}
	return &cobra.Command{Use: "history", Short: "List local receipts", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		entries, e := o.History.History(c.Context())
		if e != nil {
			return &ExitError{ExitUnavailable, e}
		}
		for _, entry := range entries {
			fmt.Fprintf(c.OutOrStdout(), "%s\t%s\n", entry.ID, entry.State)
		}
		return nil
	}}
}
func receiptCommand(o Options) *cobra.Command {
	if o.Receipt == nil {
		o.Receipt = unavailableReceipt{}
	}
	var share bool
	c := &cobra.Command{Use: "receipt <id>", Short: "Read a local receipt", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, args []string) error {
		data, e := o.Receipt.Receipt(c.Context(), args[0], share)
		if e != nil {
			return &ExitError{ExitUnavailable, e}
		}
		_, _ = c.OutOrStdout().Write(data)
		if len(data) == 0 || data[len(data)-1] != '\n' {
			_, _ = fmt.Fprintln(c.OutOrStdout())
		}
		return nil
	}}
	c.Flags().BoolVar(&share, "share", false, "emit the separately allowlisted share receipt")
	return c
}

type localDoctor struct{ RecoveryConfigured bool }

func (d localDoctor) Doctor(ctx context.Context, selfTest bool) ([]byte, error) {
	type report struct {
		Platform         model.Platform `json:"platform"`
		ProcessProbe     string         `json:"process_probe"`
		SignalCapability string         `json:"signal_capability"`
		RecoveryService  string         `json:"recovery_service"`
		SelfTest         string         `json:"self_test"`
		Status           string         `json:"status"`
	}
	capability := darwin.NewAuditTokenSignaler().Capability()
	probe := "available"
	if runtime.GOOS != "darwin" {
		probe = "unsupported_platform"
	}
	selfTestStatus := "not_run"
	if selfTest {
		if err := runDoctorSelfTest(ctx); err != nil {
			return nil, fmt.Errorf("doctor self-test: %w", err)
		}
		selfTestStatus = "passed"
	}
	recoveryService := "disabled"
	status := "read_only_ready"
	if d.RecoveryConfigured {
		recoveryService = "configured"
	}
	if d.RecoveryConfigured && capability.Supported() && probe == "available" {
		status = "ready"
	}
	return json.Marshal(report{Platform: model.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}, ProcessProbe: probe, SignalCapability: string(capability.Availability), RecoveryService: recoveryService, SelfTest: selfTestStatus, Status: status})
}

func runDoctorSelfTest(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	value := model.Snapshot{
		SchemaVersion: model.SnapshotSchemaVersion,
		ToolVersion:   "self-test",
		ObservedAt:    time.Unix(1, 0).UTC(),
		Platform:      model.Platform{OS: "synthetic", Arch: "synthetic"},
		Availability:  []model.ProbeAvailability{},
		Groups:        []model.WorkflowGroup{},
	}
	data, err := model.MarshalDeterministic(value)
	if err != nil {
		return err
	}
	if err := schema.Validate(schema.Snapshot, data); err != nil {
		return err
	}
	var decoded model.Snapshot
	return model.DecodeStrict(data, &decoded)
}

func doctorCommand(o Options) *cobra.Command {
	if o.Doctor == nil {
		o.Doctor = localDoctor{RecoveryConfigured: o.Recovery != nil}
	}
	var jsonOut, selfTest bool
	c := &cobra.Command{Use: "doctor", Short: "Report local probe and capability status", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		data, e := o.Doctor.Doctor(c.Context(), selfTest)
		if e != nil {
			return &ExitError{ExitUnavailable, e}
		}
		if jsonOut {
			_, _ = c.OutOrStdout().Write(append(data, '\n'))
			return nil
		}
		var v map[string]any
		_ = json.Unmarshal(data, &v)
		fmt.Fprintf(c.OutOrStdout(), "Doctor: %s (%s/%s)\n", v["status"], runtime.GOOS, runtime.GOARCH)
		fmt.Fprintf(c.OutOrStdout(), "Process probe: %s\nSignal capability: %s\nRecovery service: %s\nSelf-test: %s\n", v["process_probe"], v["signal_capability"], v["recovery_service"], v["self_test"])
		return nil
	}}
	c.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	c.Flags().BoolVar(&selfTest, "self-test", false, "run in-memory read-only self-test")
	return c
}
func completionCommand() *cobra.Command {
	return &cobra.Command{Use: "completion <shell>", Short: "Generate shell completion", Args: cobra.ExactArgs(1), ValidArgs: []string{"bash", "zsh", "fish", "powershell"}, RunE: func(c *cobra.Command, args []string) error {
		switch strings.ToLower(args[0]) {
		case "bash":
			return c.Root().GenBashCompletion(c.OutOrStdout())
		case "zsh":
			return c.Root().GenZshCompletion(c.OutOrStdout())
		case "fish":
			return c.Root().GenFishCompletion(c.OutOrStdout(), true)
		case "powershell":
			return c.Root().GenPowerShellCompletion(c.OutOrStdout())
		default:
			return &ExitError{ExitUsage, fmt.Errorf("unsupported shell %q", args[0])}
		}
	}}
}
func versionCommand() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{Use: "version", Short: "Print build information", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		info := buildinfo.Current()
		if asJSON {
			data, e := info.JSON()
			if e != nil {
				return e
			}
			_, _ = c.OutOrStdout().Write(append(data, '\n'))
			return nil
		}
		fmt.Fprintf(c.OutOrStdout(), "%s (%s, %s)\n", info.Version, info.Commit, info.BuildDate)
		return nil
	}}
	c.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return c
}

func terminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}

func terminalReader(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(f.Fd())
}
