package runzero

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
)

// MaxReadLineSize sets an upper limit on parsed line length
const MaxReadLineSize = 1024 * 1024 * 256

// MaxReadLineErrors provides an upper bounds to prevent cpu loops on repeated errors
const MaxReadLineErrors = 10000

// ReadLines reads lines from file handle and writes to a string channel
func ReadLines(input io.Reader, out chan<- string) error {
	return ReadLinesFromReader(context.Background(), bufio.NewReaderSize(input, MaxReadLineSize), out)
}

// ReadLinesBackground is functionally equivalent to ReadLines but is meant to be run inside of a
// goroutine so it can be canceled. It returns any errors on the supplied error channel
func ReadLinesBackground(ctx context.Context, input io.Reader, out chan<- string, errChan chan<- error, panicHandler func()) {
	defer panicHandler()
	errChan <- ReadLinesFromReader(ctx, bufio.NewReaderSize(input, MaxReadLineSize), out)
}

// ReadLinesFromReader reads lines from Reader and writes to a string channel
func ReadLinesFromReader(ctx context.Context, input io.Reader, out chan<- string) error {
	var err error
	var line string
	var ecnt int
	lineRdr := &io.LimitedReader{R: input, N: MaxReadLineSize}
	r := bufio.NewReaderSize(lineRdr, MaxReadLineSize)
ReadLineLoop:
	for {
		select {
		case <-ctx.Done():
			break ReadLineLoop
		default:
		}

		// Reset the LimitedReader limit for each line
		lineRdr.N = MaxReadLineSize

		line, err = r.ReadString('\n')
		if (err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF)) && len(line) == 0 {
			break
		}

		if err != nil && (strings.Contains(err.Error(), "flate:") ||
			strings.Contains(err.Error(), "gzip:")) {
			break
		}

		if len(line) == 0 {
			continue
		}

		select {
		case <-ctx.Done():
			break ReadLineLoop
		case out <- line:
		}

		if err != nil {
			ecnt++
			if ecnt > MaxReadLineErrors {
				break
			}
		}
	}

	close(out)

	if err != nil && !(err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF)) {
		return err
	}

	return nil
}
