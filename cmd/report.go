package cmd

import "github.com/spf13/cobra"

func init() {
	rootCmd.AddCommand(reportCmd)
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "operate on existing report files",
}
