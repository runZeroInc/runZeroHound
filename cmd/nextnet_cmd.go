package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/runZeroInc/runZeroHound/cmd/nextnet"
	"github.com/spf13/cobra"
)

type NextnetSettings struct {
	Rate       int
	OutputFile string
}

var nextnetSettings = NextnetSettings{}

func init() {
	nextnetCmd.Flags().IntVarP(&nextnetSettings.Rate, "rate", "r", 1000, "Maximum packets per second")
	nextnetCmd.Flags().StringVarP(&nextnetSettings.OutputFile, "output", "o", "", "Output file path (default: nextnet-<timestamp>.nxt)")
	rootCmd.AddCommand(nextnetCmd)
}

var nextnetCmd = &cobra.Command{
	Use:   "nextnet <cidr> [cidr ...]",
	Short: "Scan networks for pivot points and multi-homed hosts",
	Long: `nextnet probes networks using lightweight UDP techniques (NetBIOS, etc.)
to discover hosts with multiple network interfaces, gateways, and other
potential pivot points.

Results are written in JSONL format with the .nxt extension so they can be
directly imported by the 'convert' command.

Example:
  runZeroHound nextnet 192.168.1.0/24 10.0.0.0/8
`,
	Run: runNextnet,
}

func runNextnet(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fmt.Printf("Usage: %s nextnet [options] <cidr> [cidr ...]\n", ToolName)
		return
	}

	outPath := nextnetSettings.OutputFile
	if outPath == "" {
		ts := time.Now().Format("20060102-150405")
		outPath = filepath.Join(".", fmt.Sprintf("nextnet-%s.nxt", ts))
	}

	// Ensure the file has the .nxt extension
	if filepath.Ext(outPath) != ".nxt" {
		outPath = outPath + ".nxt"
	}

	outFd, err := os.Create(outPath) // #nosec G304
	if err != nil {
		fmt.Printf("error creating output file %s: %v\n", outPath, err)
		return
	}
	defer outFd.Close()

	rlog("info", "scanning %d CIDR(s) at %d pps, output → %s", len(args), nextnetSettings.Rate, outPath)

	if err := nextnet.Scanner(args, nextnetSettings.Rate, outFd); err != nil {
		fmt.Printf("nextnet scan error: %v\n", err)
		return
	}

	rlog("info", "nextnet scan complete, results written to %s", outPath)
}
