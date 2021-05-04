package cmd

import (
	"github.com/spf13/cobra"

	"enceladus/devices"
)

var devicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "Devices found",
	Long: `
List devices found on the host
`,
	Run: func(cmd *cobra.Command, args []string) {
		devices.Devices()
	},
}

func init() {
	rootCmd.AddCommand(devicesCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// devicesCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// devicesCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
