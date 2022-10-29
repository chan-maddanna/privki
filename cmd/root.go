package cmd

import (
	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"sfcert/openssl"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "privki",
	Short: "sample_org PKI Initialization & Certs creation toolset",
	Long: `privki is a PKI Initialization & Certs creation toolset
you can use it for initializing a new CA Authority, by running init.

example> privki init

Once you have initialized a new Private Key Infrastructure,
you can establish a Certifying Authority, by creating the
required self-signed Root CA Certificates using createCert command

example>  privki create_cert rootCert

If you would like your organizations PKI to have DR Capability, 
you can enable DR at this stage like shown in example below:

example> privki create_cert root_cert --with-dr=true

once you have established your own certifying authority, then you
can proceed to issue Intermediate Certifying authorities to your 
development and other business teams. For example, lets create 
an intermediary CA for an imaginary "chat team"

example: privki create_cert intermediary_cert --org="sample_org chat team" --name-restrict="alpha.chat.com"
`,
}

// backupConfigCmd represent sub command to encrypt and backup up config and PKI base
var backupConfigCmd = &cobra.Command{
	Use:   "backup",
	Short: "backup subcommand is used to backup and encrypt PKI config",
	Long: `You can use backup subcommand to backup and encrypt root PKI config
to location of choice like for example a USB stick. This enables users 
to load their PKI root from an USB stick and perform PKI operations
from any supported machine

the following example shows how to backup an active PKI root config to a directory of choice
example> privki backup --destination="/media/usbdrive1/"

you can find more help, by using the --help flag after there subcommands.
example> privki backup --help
`,
	Run: func(cmd *cobra.Command, args []string) {
		destination, _ := cmd.Flags().GetString("destination")
		if destination == "NA" || destination == "" || destination == " " {
			log.Printf("\nmissing destination directory from the arguments")
			log.Fatal("argument --destination is required")
		}
		encryptedArchiver(destination)
	},
}

// backupConfigCmd represent sub command to encrypt and backup up config and PKI base
var restoreConfigCmd = &cobra.Command{
	Use:   "restore",
	Short: "restore subcommand is used to restore a previously encrypted backup created using privki's backup functionality",
	Long: `You can use restore subcommand to restore encrypted root PKI config
to location of choice like for a linux thin terminal or a server host. 
This enables users to load their PKI root from an USB stick and perform 
PKI operations from any supported machine

you can find more help, by using the --help flag after there subcommands.

example> privki restore --help
`,
	Run: func(cmd *cobra.Command, args []string) {
		source, _ := cmd.Flags().GetString("source")
		if source == "NA" || source == "" || source == " " {
			log.Printf("\nmissing source directory from the arguments")
			log.Fatal("argument --source is required")
		}
		decryptAndRestore(source)
	},
}

// createCertCmd represent sub command for PKI cert object creation
var createCertCmd = &cobra.Command{
	Use:   "create",
	Short: "create subcommand is used to create A0 and A1 CA Objects",
	Long: `You can use create subcommand to create A0 or A1 CA Object
by using respective subcommands A0 and A1.

the following example shows how to restore an active PKI root config to a directory of choice
example> privki restore --source="/media/usbdrive1/"

you can find more help, by using the --help flag after there subcommands.
example> privki restore --help
`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(checkJson)
	formatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(formatter)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.privki.yaml)")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.PersistentFlags().BoolP("json", "j", false, "logging in json format")

	var initPkiCmd = &cobra.Command{
		Use:   "init",
		Short: "Initializes a PKI repo",
		Long: `
use init subcommand to initialize a new PKI Repository
Please note that at any point in time, there can only be one
active repository on a host that acts as a Certifying Authority. 

example> privki init

this will initialize PKI repository in the default location under 
default location. If you want the repository under a specific location,
then you can use --pki-path option as shown below

example> privki init_pki --pki-path=<full path where you want the PKI respository to be located>
`,
		Run: func(cmd *cobra.Command, args []string) {

			log.Printf("initPki\n")
			// check if OpenSSL is installed on the system
			openssl.CheckOpenSSL()
			// check if the installed openssl supports aes-256-cbc chiper
			openssl.CheckAES256Cipher()
			// Initialize PKI repository
			openssl.InitPki()
		},
	}

	rootCmd.AddCommand(initPkiCmd)
	rootCmd.AddCommand(createCertCmd)
	rootCmd.AddCommand(backupConfigCmd)
	rootCmd.AddCommand(restoreConfigCmd)

}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".privki" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".privki")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Printf("Using config file:", viper.ConfigFileUsed())
	}
}

// Check if Json flag is set, and switch log output to json format if requested.
// This does not change the default behaviour, only if a global json flag is used.
func checkJson() {
	// Enable JSON Log format if selected
	jsonLogging, _ := rootCmd.Flags().GetBool("json")
	if jsonLogging {
		log.SetFormatter(&log.JSONFormatter{})
	}
}
