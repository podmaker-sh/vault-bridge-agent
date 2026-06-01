// Package upstream contains the drivers that translate a bridge
// envelope into a real call against whichever secret backend the
// workspace registered.
//
// Each driver implements three operations (read / write / delete)
// plus a ping. The dispatcher picks the right driver based on the
// `Type` field configured at agent startup.
package upstream

import (
	"context"
	"fmt"
)

// Result is the agent's reply for a single envelope.
type Result struct {
	OK     bool                   `json:"ok"`
	Data   map[string]any         `json:"data,omitempty"`
	Status int                    `json:"status,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

// Driver is the contract every upstream backend satisfies.
type Driver interface {
	Slug() string
	Read(ctx context.Context, path string) (map[string]any, bool, error) // (data, found, err)
	Write(ctx context.Context, path string, data map[string]any) error
	Delete(ctx context.Context, path string) error
	Ping(ctx context.Context) error
}

// Dispatcher executes a single envelope op against the configured driver.
type Dispatcher struct {
	Driver Driver
}

func (d *Dispatcher) Handle(ctx context.Context, op, path string, data map[string]any) Result {
	switch op {
	case "ping":
		if err := d.Driver.Ping(ctx); err != nil {
			return Result{OK: false, Error: err.Error()}
		}
		return Result{OK: true, Data: map[string]any{"slug": d.Driver.Slug()}}

	case "read":
		out, found, err := d.Driver.Read(ctx, path)
		if err != nil {
			return Result{OK: false, Error: err.Error()}
		}
		if !found {
			return Result{OK: false, Status: 404}
		}
		return Result{OK: true, Data: out}

	case "write":
		if err := d.Driver.Write(ctx, path, data); err != nil {
			return Result{OK: false, Error: err.Error()}
		}
		return Result{OK: true}

	case "delete":
		if err := d.Driver.Delete(ctx, path); err != nil {
			return Result{OK: false, Error: err.Error()}
		}
		return Result{OK: true}

	default:
		return Result{OK: false, Error: fmt.Sprintf("unknown op %q", op)}
	}
}
