package sqlite

import (
	"testing"
	"uuid"
)

func TestScanIDRequiresSixteenBytes(t *testing.T) {
	id := uuid.NewV7()

	var got uuid.UUID
	if err := scanID(&got).Scan(id[:]); err != nil || got != id {
		t.Fatalf("Scan(16 bytes) = %v, %v; want %v", got, err, id)
	}
	got = id
	if err := scanID(&got).Scan(nil); err != nil || got != uuid.Nil() {
		t.Fatalf("Scan(nil) = %v, %v; want the nil UUID", got, err)
	}
	if err := scanID(&got).Scan(make([]byte, 15)); err == nil {
		t.Fatal("Scan(15 bytes) succeeded, want an error")
	}
	if err := scanID(&got).Scan(id.String()); err == nil {
		t.Fatal("Scan(text) succeeded, want an error")
	}
}
