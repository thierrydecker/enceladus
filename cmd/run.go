package cmd

import (
	"enceladus/run"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run enceladus agent",
	Long: `
Run Enceladus agent
`,
	Run: func(cmd *cobra.Command, args []string) {
		run.Run()
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
