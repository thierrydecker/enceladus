package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

var rootCmd = &cobra.Command{
	/*
		rootCmd represents the base command when called without any subcommands
	*/
	Use:   "enceladus",
	Short: "Enceladus network analyzer",
	Long: `
Enceladus is a network analyzer using InfluxDB as storage backend 
	`,
	Run: func(cmd *cobra.Command, args []string) {},
}

func Execute() {
	/*
		Execute adds all child commands to the root command and sets flags appropriately.
		This is called by main.main(). It only needs to happen once to the rootCmd.
	*/
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)
	/*
		Here you will define your flags and configuration settings.
		Cobra supports persistent flags, which, if defined here,
		will be global for your application.
	*/
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.enceladus.yaml)")
	/*
		Cobra also supports local flags, which will only run
		when this action is called directly.
	*/
	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func initConfig() {
	/*
		initConfig reads in config file and ENV variables if set.
	*/
	if cfgFile != "" {
		/*
			Use config file from the flag.
		*/
		viper.SetConfigFile(cfgFile)
	} else {
		/*
			Find home directory.
		*/
		home, err := homedir.Dir()
		cobra.CheckErr(err)
		/*
		   Search config in home directory with name ".enceladus" (without extension).
		*/
		viper.AddConfigPath(home)
		viper.SetConfigName(".enceladus")
	}
	viper.AutomaticEnv() // read in environment variables that match
	/*
		If a config file is found, read it in.
	*/
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
