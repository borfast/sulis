package sqlite

import (
	"database/sql"
	"fmt"
	"uuid"
)

// idArg turns an ID into a query argument: its 16 bytes.
func idArg(id uuid.UUID) any { return id[:] }

// nullableIDArg is idArg, except that uuid.Nil becomes NULL.
func nullableIDArg(id uuid.UUID) any {
	if id == uuid.Nil() {
		return nil
	}
	return id[:]
}

// idScanner scans a BLOB column holding exactly 16 bytes.
type idScanner struct{ dst *uuid.UUID }

// scanID scans an ID column into dst: NULL gives uuid.Nil, anything malformed is an error.
func scanID(dst *uuid.UUID) sql.Scanner { return idScanner{dst} }

func (s idScanner) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		*s.dst = uuid.Nil()
		return nil
	case []byte:
		if len(v) != len(uuid.UUID{}) {
			return fmt.Errorf("sulis/sqlite: reading an ID: got %d bytes, want 16", len(v))
		}
		copy(s.dst[:], v)
		return nil
	default:
		return fmt.Errorf("sulis/sqlite: reading an ID: unexpected type %T", src)
	}
}
