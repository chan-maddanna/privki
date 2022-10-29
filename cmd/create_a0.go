package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sfcert/openssl"
)

// rootCertCmd represents the rootCert command
var rootCertCmd = &cobra.Command{
	Use:   "A0",
	Short: "Creates Root CA Certs with or without DR",
	Long: `
Use root_cert subcommand to establish Root CA Authority with 
or without DR and Create the required self signed Root CA and
Root DR Certificates. 

example> privki create A0

Please note, by default DR is disabled.
To enable DR, please use set the flag --with-dr=true 

example> privki create A0 --with-dr=true

To Specify a new Custom OID for your organization, you could use
the --custom-oid flag, as shown here:

example> privki create A0 --with-dr=true --custom-oid="1.9.9.1.4.4.7.8.5"

to set you Organization Name and Common Names for the Root CA (A0) entity,
please use --org and --common-name flags respectively. Additionally, you can 
specify the new A0 passphrase on command line for a complete non-interactive 
execution, like below:

example> privki create A0 --with-dr=true --custom-oid="1.9.9.1.4.4.7.8.5" \
			--org="alpha beta corporation" --common-name="alpha beta certifying authority" \
			--passphrase="mySecretA0Passphrase"

Please note that, there should be an existing PKI repository 
and related configuration before you can establish Certificate 
Authority. Hence, If you have not done so, please run init_pki
before running any of the create_cert subcommands.
`,
	Run: func(cmd *cobra.Command, args []string) {

		customOID, _ := cmd.Flags().GetString("custom-oid")
		openssl.SetCustomOid(customOID)
		organizationName, _ := cmd.Flags().GetString("org")
		if organizationName == "NA" {
			log.Printf("\nmissing organization name from the arguments")
			log.Fatal("argument --org is required")
		}
		openssl.SetOrganizationName(organizationName)
		organizationCommonName, _ := cmd.Flags().GetString("common-name")
		if organizationCommonName == "NA" {
			log.Printf("\nmissing common name from the arguments")
			log.Fatal("argument --common-name is required")
		}
		openssl.SetOrganizationCommonName(organizationCommonName)
		passphrase, _ := cmd.Flags().GetString("passphrase")

		rootDrStatus, _ := cmd.Flags().GetString("with-dr")
		if rootDrStatus == "true" {
			openssl.CreateRootCA(passphrase)
			openssl.CreateDRRootCA()

		} else if rootDrStatus == "false" {
			openssl.CreateRootCA(passphrase)
		} else {
			log.Printf("\nUnrecognized value %v for flag --with-dr. can only be <true/false>", rootDrStatus)
			log.Fatal("Unrecognized value for --with-dr")
		}
	},
}

func init() {

	var withDR string
	var customOID string
	var organizationName string
	var organizationCommonName string
	var passphrase string

	createCertCmd.AddCommand(rootCertCmd)
	// Add and Process flags to check if DR certs are needed
	rootCertCmd.Flags().StringVar(&withDR, "with-dr", "false", "setting this option to true enables Root DR")
	rootCertCmd.Flags().StringVar(&customOID, "custom-oid", "1.3.6.1.5.5.7.8.5", "flag --custom-oid=<your_chosen_oid> sets your custom oid for Class Definition")
	rootCertCmd.Flags().StringVar(&organizationName, "org", "NA", "flag --org=<organization legal name> sets your organization")
	rootCertCmd.Flags().StringVar(&organizationCommonName, "common-name", "NA", "flag --common-name=<organization common name> sets your organization's common/functional name")
	rootCertCmd.Flags().StringVar(&passphrase, "passphrase", "NA", "flag --passphrase=<my_secret_passphrase> sets passphrase for your Root CA and Root CA DR Certificates")

}
