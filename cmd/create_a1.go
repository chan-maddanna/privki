package cmd

import (
	"github.com/spf13/cobra"
	"sfcert/openssl"
)

// intermediaryCertCmd represents the intermediaryCert command
var intermediaryCertCmd = &cobra.Command{
	Use:   "A1",
	Short: "Creates Intermediary CA Certs with or without DR Cross Signing and Name Restrictions",
	Long: `
Use A1 subcommand to create Intermediate Certifying
Authorities. If DR is enabled on Root CA, then automatically all 
intermedaries are cross-signed and packaged for ease.

example> privki create A1 --org="XYZ Department"

If you want to limit Intermediate CA to be able to issue certificates
only to a certain domain, then please use the flag --name-restrict
to apply these name restrictions.

example> privki create A1 --org="XYZ Department" --name-restrict="chat.alpha.com"

To specify your A0 Root passphrase on command line, for non interactive execution
you could use the --root-passphrase flag. Additionally you could also specify
new passphrase for the A1 being created, using --passphrase flag for a complete
non interactive execution.

example> privki create A1 --org="XYZ Department" --name-restrict="chat.alpha.com" --root-passphrase="mySecretRootPassword" --passphrase="myNewSecretPassword"

Please note that, there should be an existing PKI repository 
and related configuration along with an established Root CA
before you can establish an Intermediate Certificate Authority. 
Hence, If you have not done so, please run init
and create A0 subcommands to establish these pre-requisite

run --help for those respective subcommands for more information on
how to use them
`,
	Run: func(cmd *cobra.Command, args []string) {

		nameRestriction, _ := cmd.Flags().GetString("name-restrict")
		orgName, _ := cmd.Flags().GetString("org")
		rootPassphrase, _ := cmd.Flags().GetString("root-passphrase")
		passphrase, _ := cmd.Flags().GetString("passphrase")
		openssl.CreateIntermediateCA(nameRestriction, orgName, passphrase, rootPassphrase)
	},
}

func init() {

	var name_restrict string
	var org string
	var a1Passphrase string
	var rootPassphrase string

	createCertCmd.AddCommand(intermediaryCertCmd)
	intermediaryCertCmd.Flags().StringVar(&name_restrict, "name-restrict", "NA", "set --name-restrict=<DomainName> to restrict issuance to DomainName")
	intermediaryCertCmd.Flags().StringVar(&org, "org", "NA", "set --org=<organization/project name>")
	intermediaryCertCmd.Flags().StringVar(&a1Passphrase, "passphrase", "NA", "flag --passphrase=<my_secret_passphrase> sets passphrase for your Intermediary CA Certificates")
	intermediaryCertCmd.Flags().StringVar(&rootPassphrase, "root-passphrase", "NA", "use --root-passphrase=<A0_secret_passphrase> to provide your A0 passphrase")
}
