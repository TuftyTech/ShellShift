// Package obs provides structured logging and metrics.
//
// Importing this package performs no I/O: no directory is created, no file is
// opened, no global logger is replaced, and nothing calls os.Exit. The predecessor
// created directories and opened two log sinks at import time, which made every test
// that imported it write to disk.
package obs
