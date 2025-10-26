package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

const ToolName = "runZeroHound"
const Version = "0.0.0"

var rootCmd = &cobra.Command{
	Use:               ToolName,
	Short:             fmt.Sprintf(`%s v%s`, ToolName, Version),
	Long:              fmt.Sprintf(`%s v%s`, ToolName, Version),
	Args:              cobra.ArbitraryArgs,
	CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
}

func Execute(defCmd string) {
	var cmdFound bool
	if len(os.Args) > 1 {
		userCmd := os.Args[1]
		cmdFound = (userCmd == "help" || userCmd == "-h" || userCmd == "--help")
		if !cmdFound {
			for _, a := range rootCmd.Commands() {
				if a.Name() == userCmd {
					cmdFound = true
					break
				}
			}
		}
	}
	if !cmdFound && len(os.Args) > 2 {
		args := append([]string{defCmd}, os.Args[1:]...)
		rootCmd.SetArgs(args)
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type RootSettings struct {
	Verbose bool
	Logger  *slog.Logger
}

var rootSettings = &RootSettings{}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&rootSettings.Verbose, "verbose", "v", false, "Display verbose output")
	rootSettings.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: rlogFormat}))
}

func rlog(level string, format string, a ...interface{}) {
	switch level {
	case "debug", "trace":
		if rootSettings.Verbose {
			rootSettings.Logger.Debug(fmt.Sprintf(format, a...))
		}
	case "info":
		rootSettings.Logger.Info(fmt.Sprintf(format, a...))
	case "warn":
		rootSettings.Logger.Warn(fmt.Sprintf(format, a...))
	case "error":
		rootSettings.Logger.Error(fmt.Sprintf(format, a...))
	default:
		rootSettings.Logger.Info(fmt.Sprintf(format, a...))
	}
}

func rlogFormat(groups []string, a slog.Attr) slog.Attr {
	if a.Key == "time" {
		return slog.Attr{Key: "t", Value: a.Value}
	}
	return a
}
