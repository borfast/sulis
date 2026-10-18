package postgres

import (
	"testing"
	"uuid"
)

func TestScanIDParsesTextAndNull(t *testing.T) {
	id := uuid.NewV7()

	var got uuid.UUID
	if err := scanID(&got).Scan(id.String()); err != nil || got != id {
		t.Fatalf("Scan(string) = %v, %v; want %v", got, err, id)
	}
	got = uuid.Nil()
	if err := scanID(&got).Scan([]byte(id.String())); err != nil || got != id {
		t.Fatalf("Scan([]byte) = %v, %v; want %v", got, err, id)
	}
	if err := scanID(&got).Scan(nil); err != nil || got != uuid.Nil() {
		t.Fatalf("Scan(nil) = %v, %v; want the nil UUID", got, err)
	}
	if err := scanID(&got).Scan("not-a-uuid"); err == nil {
		t.Fatal("Scan(not-a-uuid) succeeded, want an error")
	}
	if err := scanID(&got).Scan(int64(7)); err == nil {
		t.Fatal("Scan(int64) succeeded, want an error")
	}
}
