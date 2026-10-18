package postgres

import (
	"database/sql"
	"fmt"
	"uuid"
)

// idArg turns an ID into a query argument: its text form, which a uuid column accepts.
func idArg(id uuid.UUID) any { return id.String() }

// nullableIDArg is idArg, except that uuid.Nil becomes NULL.
func nullableIDArg(id uuid.UUID) any {
	if id == uuid.Nil() {
		return nil
	}
	return id.String()
}

// idScanner scans a uuid column, which pgx hands over in its text form.
type idScanner struct{ dst *uuid.UUID }

// scanID scans an ID column into dst: NULL gives uuid.Nil, anything malformed is an error.
func scanID(dst *uuid.UUID) sql.Scanner { return idScanner{dst} }

func (s idScanner) Scan(src any) error {
	var text string
	switch v := src.(type) {
	case nil:
		*s.dst = uuid.Nil()
		return nil
	case string:
		text = v
	case []byte:
		text = string(v)
	default:
		return fmt.Errorf("sulis/postgres: reading an ID: unexpected type %T", src)
	}
	id, err := uuid.Parse(text)
	if err != nil {
		return fmt.Errorf("sulis/postgres: reading an ID: %w", err)
	}
	*s.dst = id
	return nil
}
