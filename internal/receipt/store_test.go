package receipt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testValidator(data []byte) error {
	fields, err := decodeJSONObject(data)
	if err != nil {
		return err
	}
	if string(fields["ok"]) != "true" && string(fields["done"]) != "true" {
		return errors.New("invalid test receipt")
	}
	return nil
}

func testPrepared(id string) []byte {
	return []byte(fmt.Sprintf(`{"receipt_id":%q,"ok":true}`, id))
}

func testResult(id, preparedDigest string) []byte {
	return []byte(fmt.Sprintf(`{"receipt_id":%q,"prepared_digest":%q,"done":true}`, id, preparedDigest))
}

func claimTestTransaction(t *testing.T, store *Store, id string, prepared []byte) string {
	t.Helper()
	digest := digestBytes(prepared)
	if err := store.ClaimExecution(context.Background(), id, digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	base, err := os.MkdirTemp("/private/tmp", "runnel-receipt-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(filepath.Join(base, "receipts"), testValidator, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestPrepareFinalizeReadList(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	id := "r-0123456789abcdef0123456789abcdef"
	prepared := testPrepared(id)
	if err := store.Prepare(ctx, id, prepared); err != nil {
		t.Fatal(err)
	}
	state, data, err := store.Read(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != StatePrepared || string(data) != string(prepared) {
		t.Fatalf("unexpected prepared read: %s %s", state, data)
	}
	digest := claimTestTransaction(t, store, id, prepared)
	state, data, err = store.Read(ctx, id)
	if err != nil || state != StateExecuting || string(data) != string(prepared) {
		t.Fatalf("unexpected executing read: %s %s %v", state, data, err)
	}
	result := testResult(id, digest)
	if err := store.Finalize(ctx, id, result); err != nil {
		t.Fatal(err)
	}
	state, data, err = store.Read(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if state != StateResult || string(data) != string(result) {
		t.Fatalf("unexpected result read: %s %s", state, data)
	}
	entries, err := store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != id || entries[0].State != StateResult {
		t.Fatalf("unexpected list: %#v", entries)
	}
	entries, err = store.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != id {
		t.Fatalf("second list lost directory entries: %#v", entries)
	}
}

func TestPrepareAndFinalizeAreExclusive(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	id := "r-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	prepared := testPrepared(id)
	if err := store.Prepare(ctx, id, prepared); err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(ctx, id, prepared); !errors.Is(err, ErrCollision) {
		t.Fatalf("expected collision, got %v", err)
	}
	digest := claimTestTransaction(t, store, id, prepared)
	if err := store.ClaimExecution(ctx, id, digest); !errors.Is(err, ErrCollision) {
		t.Fatalf("expected claim collision, got %v", err)
	}
	result := testResult(id, digest)
	if err := store.Finalize(ctx, id, result); err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(ctx, id, result); !errors.Is(err, ErrCollision) {
		t.Fatalf("expected result collision, got %v", err)
	}
}

func TestInvalidDataMutatesNothing(t *testing.T) {
	store := newTestStore(t)
	id := "r-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := store.Prepare(context.Background(), id, []byte(fmt.Sprintf(`{"receipt_id":%q,"private":"path"}`, id))); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected invalid state, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Root(), id)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid payload created transaction: %v", err)
	}
}

func TestSymlinkRootIsRefused(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "runnel-receipt-link-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "receipts")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(link, testValidator, testValidator); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected unsafe path, got %v", err)
	}
}

func TestUnsafePreparedSymlinkBlocksFinalize(t *testing.T) {
	store := newTestStore(t)
	id := "r-cccccccccccccccccccccccccccccccc"
	tx := filepath.Join(store.Root(), id)
	if err := os.Mkdir(tx, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(tx, preparedName)); err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(context.Background(), id, testResult(id, fmt.Sprintf("%064x", 0))); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected unsafe prepared path, got %v", err)
	}
}

func TestWrongModeTransactionIsRefused(t *testing.T) {
	store := newTestStore(t)
	id := "r-dddddddddddddddddddddddddddddddd"
	tx := filepath.Join(store.Root(), id)
	if err := os.Mkdir(tx, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(context.Background(), id, testResult(id, fmt.Sprintf("%064x", 0))); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("expected unsafe transaction mode, got %v", err)
	}
}

func TestCancellationAndClose(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	id := "r-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if err := store.Prepare(ctx, id, testPrepared(id)); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	id = "r-ffffffffffffffffffffffffffffffff"
	if err := store.Prepare(context.Background(), id, testPrepared(id)); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected closed store, got %v", err)
	}
}

func TestPrepareBindsPayloadReceiptIDBeforeMutation(t *testing.T) {
	store := newTestStore(t)
	directoryID := "r-11111111111111111111111111111111"
	payloadID := "r-22222222222222222222222222222222"
	if err := store.Prepare(context.Background(), directoryID, testPrepared(payloadID)); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected mismatched receipt id rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(store.Root(), directoryID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched payload mutated store: %v", err)
	}
	duplicate := []byte(fmt.Sprintf(`{"receipt_id":%q,"receipt_id":%q,"ok":true}`, directoryID, directoryID))
	if err := store.Prepare(context.Background(), directoryID, duplicate); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected duplicate receipt_id rejection, got %v", err)
	}
}

func TestMalformedDirectoryIDsAreRejectedWithoutMutation(t *testing.T) {
	store := newTestStore(t)
	badID := "../r-77777777777777777777777777777777"
	for name, operation := range map[string]func() error{
		"prepare": func() error { return store.Prepare(context.Background(), badID, testPrepared(badID)) },
		"claim":   func() error { return store.ClaimExecution(context.Background(), badID, fmt.Sprintf("%064x", 0)) },
		"finalize": func() error {
			return store.Finalize(context.Background(), badID, testResult(badID, fmt.Sprintf("%064x", 0)))
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := operation(); !errors.Is(err, ErrInvalidID) {
				t.Fatalf("malformed id error = %v", err)
			}
		})
	}
	entries, err := store.List(context.Background())
	if err != nil || len(entries) != 0 {
		t.Fatalf("malformed ids mutated store: %#v %v", entries, err)
	}
}

func TestExecutionClaimIsDurableExclusiveAndCrashInspectable(t *testing.T) {
	store := newTestStore(t)
	id := "r-33333333333333333333333333333333"
	prepared := testPrepared(id)
	if err := store.Prepare(context.Background(), id, prepared); err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(prepared)
	const contenders = 16
	start := make(chan struct{})
	errorsOut := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsOut <- store.ClaimExecution(context.Background(), id, digest)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsOut)
	successes := 0
	for err := range errorsOut {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrCollision) {
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("durable claim successes = %d, want 1", successes)
	}
	state, got, err := store.Read(context.Background(), id)
	if err != nil || state != StateExecuting || string(got) != string(prepared) {
		t.Fatalf("crash claim not inspectable: %s %s %v", state, got, err)
	}
	entries, err := store.List(context.Background())
	if err != nil || len(entries) != 1 || entries[0].State != StateExecuting {
		t.Fatalf("executing state not listed: %#v %v", entries, err)
	}
}

func TestExecutionClaimIsExclusiveAcrossStoreInstancesAndCancellationLeavesPrepared(t *testing.T) {
	first := newTestStore(t)
	second, err := NewStore(first.Root(), testValidator, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	id := "r-66666666666666666666666666666666"
	prepared := testPrepared(id)
	if err := first.Prepare(context.Background(), id, prepared); err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(prepared)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.ClaimExecution(cancelled, id, digest); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled claim error = %v", err)
	}
	state, _, err := second.Read(context.Background(), id)
	if err != nil || state != StatePrepared {
		t.Fatalf("cancelled claim did not preserve prepared state: %s %v", state, err)
	}
	start := make(chan struct{})
	completed := make(chan error, 2)
	for _, store := range []*Store{first, second} {
		go func(store *Store) {
			<-start
			completed <- store.ClaimExecution(context.Background(), id, digest)
		}(store)
	}
	close(start)
	firstErr, secondErr := <-completed, <-completed
	successes := 0
	for _, err := range []error{firstErr, secondErr} {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrCollision) {
			t.Fatalf("cross-store claim error = %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("cross-store claim successes = %d", successes)
	}
}

func TestFinalizeBindsIDAndPreparedDigestWithoutCollisionMutation(t *testing.T) {
	store := newTestStore(t)
	id := "r-44444444444444444444444444444444"
	otherID := "r-55555555555555555555555555555555"
	prepared := testPrepared(id)
	if err := store.Prepare(context.Background(), id, prepared); err != nil {
		t.Fatal(err)
	}
	digest := claimTestTransaction(t, store, id, prepared)
	for _, result := range [][]byte{
		testResult(otherID, digest),
		testResult(id, fmt.Sprintf("%064x", 7)),
	} {
		if err := store.Finalize(context.Background(), id, result); !errors.Is(err, ErrInvalidState) {
			t.Fatalf("expected linkage rejection, got %v", err)
		}
		if _, err := os.Stat(filepath.Join(store.Root(), id, resultName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("invalid result created final receipt: %v", err)
		}
	}
	result := testResult(id, digest)
	const contenders = 8
	start := make(chan struct{})
	errorsOut := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsOut <- store.Finalize(context.Background(), id, result)
		}()
	}
	close(start)
	wait.Wait()
	close(errorsOut)
	successes := 0
	for err := range errorsOut {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrCollision) {
			t.Fatalf("unexpected finalize collision error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("finalize successes = %d, want 1", successes)
	}
}

func TestNewID(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !receiptIDPattern.MatchString(a) || !receiptIDPattern.MatchString(b) {
		t.Fatalf("invalid ids: %q %q", a, b)
	}
}
