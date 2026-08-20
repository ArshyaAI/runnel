package darwin

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ArshyaAI/runnel/internal/model"
)

type GlobalSocket struct {
	PID      int32
	FD       string
	Protocol string
	State    string
	Name     string
}

type SocketCounts struct {
	Listening   uint32
	Established uint32
}

type GlobalSocketSnapshot struct {
	Sockets      []GlobalSocket
	ByPID        map[int32]SocketCounts
	Truncated    bool
	Availability model.Availability
}

// GlobalSockets invokes lsof once for the complete TCP map. There is no
// per-process child command and the launcher enforces all child/output bounds.
func GlobalSockets(ctx context.Context, launcher ProbeLauncher, maxRecords int) (GlobalSocketSnapshot, error) {
	if maxRecords <= 0 {
		maxRecords = 65_536
	}
	maxRecords = min(maxRecords, 65_536)
	result, err := launcher.Run(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN,ESTABLISHED", "-FpcfPTn")
	if err != nil {
		var exitErr *ProbeExitError
		if errors.As(err, &exitErr) && exitErr.Code == 1 && len(bytes.TrimSpace(result.Output)) == 0 {
			return GlobalSocketSnapshot{Sockets: []GlobalSocket{}, ByPID: map[int32]SocketCounts{}, Availability: model.AvailabilityAvailable}, nil
		}
		availability := availabilityForError(err)
		if errors.Is(err, ErrOutputLimit) {
			availability = model.AvailabilityContradictory
		}
		return GlobalSocketSnapshot{Availability: availability}, &OperationError{Op: "socket_map", Availability: availability, Err: err}
	}
	sockets, truncated, parseErr := ParseLSOF(result.Output, maxRecords)
	if parseErr != nil {
		return GlobalSocketSnapshot{Availability: model.AvailabilityMalformedOutput}, &OperationError{Op: "socket_parse", Availability: model.AvailabilityMalformedOutput, Err: parseErr}
	}
	snapshot := GlobalSocketSnapshot{Sockets: sockets, ByPID: make(map[int32]SocketCounts), Truncated: truncated, Availability: model.AvailabilityAvailable}
	if truncated {
		snapshot.Availability = model.AvailabilityContradictory
	}
	for _, socket := range sockets {
		counts := snapshot.ByPID[socket.PID]
		switch socket.State {
		case "LISTEN":
			counts.Listening++
		case "ESTABLISHED":
			counts.Established++
		}
		snapshot.ByPID[socket.PID] = counts
	}
	return snapshot, nil
}

// ParseLSOF accepts lsof field mode (-FpcfPTn). It keeps only bounded socket
// metadata and never accepts human-oriented column output.
func ParseLSOF(data []byte, maxRecords int) ([]GlobalSocket, bool, error) {
	if maxRecords <= 0 {
		return nil, false, errors.New("maxRecords must be positive")
	}
	maxRecords = min(maxRecords, 65_536)
	if len(data) > 8<<20 {
		return nil, false, ErrOutputLimit
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	var currentPID int32
	var current *GlobalSocket
	out := make([]GlobalSocket, 0)
	truncated := false
	flush := func() error {
		if current == nil {
			return nil
		}
		if current.PID <= 0 || current.FD == "" || current.Protocol == "" || current.State == "" {
			return errors.New("incomplete lsof socket record")
		}
		if current.State != "LISTEN" && current.State != "ESTABLISHED" {
			return fmt.Errorf("unsupported TCP state %q", current.State)
		}
		if len(out) >= maxRecords {
			truncated = true
			current = nil
			return nil
		}
		out = append(out, *current)
		current = nil
		return nil
	}
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 100_000 {
			return nil, false, ErrOutputLimit
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		kind, value := line[0], line[1:]
		switch kind {
		case 'p':
			if err := flush(); err != nil {
				return nil, false, err
			}
			parsed, err := strconv.ParseInt(value, 10, 32)
			if err != nil || parsed <= 0 {
				return nil, false, errors.New("invalid lsof pid")
			}
			currentPID = int32(parsed)
		case 'f':
			if err := flush(); err != nil {
				return nil, false, err
			}
			if currentPID <= 0 || value == "" {
				return nil, false, errors.New("lsof fd without process")
			}
			current = &GlobalSocket{PID: currentPID, FD: value}
		case 'P':
			if current != nil {
				current.Protocol = strings.ToUpper(value)
			}
		case 'T':
			if current != nil && strings.HasPrefix(value, "ST=") {
				current.State = strings.ToUpper(strings.TrimPrefix(value, "ST="))
			}
		case 'n':
			if current != nil {
				current.Name = value
			}
		case 'c', 't':
			// Command and type fields are not required for correlation.
		default:
			// lsof may add field-mode values across releases. Ignoring an
			// unknown non-critical field is safer than parsing column output;
			// the required record fields above remain strict.
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, false, err
	}
	if err := flush(); err != nil {
		return nil, false, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PID != out[j].PID {
			return out[i].PID < out[j].PID
		}
		return out[i].FD < out[j].FD
	})
	return out, truncated, nil
}
