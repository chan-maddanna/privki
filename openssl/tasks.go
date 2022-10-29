package openssl

import (
	"fmt"
	"github.com/chuckpreslar/gofer"
	pkger "github.com/markbates/pkger"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"sfcert/shell"
	"strings"
	"time"
)

// PKI Initialization related task definitions
var taskCreateRootUID = gofer.Register(gofer.Task{
	Namespace:   "PKI",
	Label:       "createRootUID",
	Description: "Task to Initialise PKI Repository",
	Action: func(arguments ...string) error {

		rootCertUID := arguments[0]

		createDirCmd := "mkdir -p " + GetPkiConfigDir()
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(createDirCmd, false, false)

		//Handle folder permission errors in user home
		if shellOutput.Stderr != "" {
			log.Printf("Found previous config : %v\nIf you are sure you do not need this, please delete this folder and retry\n", GetPkiConfigDir())
			return shellOutput.CmdError
		}

		saveRootUIDCmd := "echo " + rootCertUID + " > " + GetPkiConfigDir() + "/root_cert_uid"
		shellOutput = shell.Execute(saveRootUIDCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to file : %v/root_cert_uid\n", GetPkiConfigDir())
			return shellOutput.CmdError
		}
		return nil
	},
})
var taskInitPki = gofer.Register(gofer.Task{
	Namespace:   "PKI",
	Label:       "init",
	Description: "Task to Initialise PKI Repository",

	Action: func(arguments ...string) error {
		// Register and store PKI Repository config under a standard location
		// in Users home directory
		currentPkiPath := arguments[0]
		savePkiPathCmd := "echo " + currentPkiPath + " > " + GetPkiPathConfigFile()

		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(savePkiPathCmd, false, false)

		//Handle other write permission or change of permission errors.
		if shellOutput.Stderr != "" {
			log.Printf("Unable to write to : %vnPlease check permissions\n", GetPkiPathConfigFile())
			return shellOutput.CmdError
		}

		//Creating PKI Base Directory
		createPkiBaseDirectory := "mkdir -p " + currentPkiPath
		shellOutput = shell.Execute(createPkiBaseDirectory, false, false)

		//Handle errors if unable to create PKI Base
		if shellOutput.Stderr != "" {
			log.Printf("Unable to create : %v/sfcert_pki\nPlease check permissions\n", currentPkiPath)
			return shellOutput.CmdError
		}

		//Creating Other config files.
		createPrimaryRootConfigCmd := "touch " + GetPrimaryRootConfigFile()
		//Handle other write permission or change of permission errors.
		shellOutput = shell.Execute(createPrimaryRootConfigCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to: %v\nPlease check permissions\n", GetPkiConfigDir())
			return shellOutput.CmdError
		}

		log.Printf("Successfully initialized new PKI Repository at %v/sfcert_pki\nYou can now proceed to create/add certs to this repo\n", currentPkiPath)
		return nil
	},
})

// Root CA (A0) related task definitions
var taskRootCAPrepWork = gofer.Register(gofer.Task{
	Namespace:   "A0",
	Label:       "Prepare",
	Description: "Task to Prepare structure and permissions for Root CA (A0)",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := GetPkiPath()
		rootCertUID := GetRootUID()
		//use pkiPathFromConfig location and root uid as seed information to create the required root certs.
		createRootCertDirCmd := "mkdir -p " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/{certreqs,certs,crl,newcerts,private}"
		setRootCertPermsCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && chmod 700 private && touch ./root-ca.index && echo 00 > ./root-ca.crlnum"
		createRandSerialCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && openssl rand -hex 16 > ./root-ca.serial"

		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(createRootCertDirCmd, false, false)

		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		shellOutput = shell.Execute(setRootCertPermsCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		shellOutput = shell.Execute(createRandSerialCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		return nil
	},
})

var taskRootSetCustomOID = gofer.Register(gofer.Task{
	Namespace:   "A0",
	Label:       "SetCustomOID",
	Description: "Task to setup Custom OID for the Root CA",
	Action: func(arguments ...string) error {
		customOID := arguments[0]
		setCustomOIDCmd := "echo " + customOID + " > " + GetOidConfigFile()
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setCustomOIDCmd, false, false)
		return shellOutput.CmdError
	},
})

var taskRootSetOrganizationName = gofer.Register(gofer.Task{
	Namespace:   "A0",
	Label:       "SetOrganizationName",
	Description: "Task to setup Custom OID for the Root CA",
	Action: func(arguments ...string) error {
		organizationName := arguments[0]
		setOrganizationNameCmd := "echo " + organizationName + " > " + GetOrgNameConfigFile()
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOrganizationNameCmd, false, false)
		return shellOutput.CmdError
	},
})

var taskRootSetOrganizationCommonName = gofer.Register(gofer.Task{
	Namespace:   "A0",
	Label:       "SetOrganizationCommonName",
	Description: "Task to setup Custom OID for the Root CA",
	Action: func(arguments ...string) error {
		organizationCommonName := arguments[0]
		setOrganizationCommonNameCmd := "echo " + organizationCommonName + " > " + GetOrgCommonNameConfigFile()
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOrganizationCommonNameCmd, false, false)
		return shellOutput.CmdError
	},
})

var taskRootCAConfig = gofer.Register(gofer.Task{
	Namespace:   "A0",
	Label:       "Config",
	Description: "Task to write Root CA (A0) Configuration",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]

		rootConfigFile := pkiPathFromConfig + "/" + rootCertUID + "-root-ca/root-ca.cnf"
		rootConfigResource, err := pkger.Open("/resources/root_ca.cnf")
		if err != nil {
			return err
		}
		defer rootConfigResource.Close()
		rootConfigResourceStats, err := rootConfigResource.Stat()
		if err != nil {
			return err
		}
		readBuffer := make([]byte, rootConfigResourceStats.Size())

		rootConfigResource.Read(readBuffer)
		err = ioutil.WriteFile(rootConfigFile, readBuffer, 0644)
		if err != nil {
			return err
		}

		setOidCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/#customOID/" + GetOid() + "/g\" root-ca.cnf"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOidCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save active OID in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/sample_org Cloud Corporation/" + GetOrganizationName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Name in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		removeSubAltNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/subjectAltName/#subjectAltName/g\" root-ca.cnf"
		shellOutput = shell.Execute(removeSubAltNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to remove Subject Alt Name requirements from config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		orgFirstName := strings.Fields(GetOrganizationName())
		ordDomainEncodeCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/sfcc.tech/" + orgFirstName[0] + ".tech/g\" root-ca.cnf"
		shellOutput = shell.Execute(ordDomainEncodeCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to remove CA Issuers requirements from config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationCommonNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/sample_org Root Certification Authority/" + GetOrganizationCommonName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationCommonNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Common Name in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		removeExtentionsInRootCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/crl_extensions/#crl_extensions/g\" root-ca.cnf"
		shellOutput = shell.Execute(removeExtentionsInRootCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to remove crl extentions in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		removeIssuerAltInRootCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/issuerAltName/#issuerAltName/g\" root-ca.cnf"
		shellOutput = shell.Execute(removeIssuerAltInRootCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to remove issuer alternative names in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		crlDistIssuerAltInRootCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/crlDistributionPoints/#crlDistributionPoints/g\" root-ca.cnf"
		shellOutput = shell.Execute(crlDistIssuerAltInRootCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to crl distribution points in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		authInfoAltInRootCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/authorityInfoAccess/#authorityInfoAccess/g\" root-ca.cnf"
		shellOutput = shell.Execute(authInfoAltInRootCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to Authority Info access in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskRootCACreate = gofer.Register(gofer.Task{
	Namespace:    "A0",
	Label:        "Create",
	Description:  "Create Root CA (A0)",
	Dependencies: []string{"A0:Prepare", "A0:Config"},
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]

		t := time.Now().UTC()
		startDate := fmt.Sprintf(t.AddDate(0, 0, -1).Format("20060102150405Z"))
		expiryDate := fmt.Sprintf(t.AddDate(30, 0, 0).Format("20060102150405Z"))
		opensslPassoutString := arguments[2]
		opensslPassinString := arguments[3]

		opensslCSRCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl req " + opensslPassoutString + opensslPassinString + "-new -out root-ca.req.pem"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(opensslCSRCmd, true, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nCSR Generation error for root at location : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		opensslSelfSignA0Cmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl rand -hex 16 > root-ca.serial && openssl ca " + opensslPassinString + "-selfsign -in root-ca.req.pem -out root-ca.cert.pem -extensions root-ca_ext -batch -startdate " + startDate + " -enddate " + expiryDate
		shellOutput = shell.Execute(opensslSelfSignA0Cmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nCSR Generation error for root at location : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		caCertName := strings.ReplaceAll(GetOrganizationName()+"_"+GetOrganizationCommonName()+"_"+"RA0_"+rootCertUID+".pem", " ", "-")
		selfSignA0CertCopyCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/root-ca.cert.pem  " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/" + caCertName
		shellOutput = shell.Execute(selfSignA0CertCopyCmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nCSR Generation error for root at location : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		log.Printf("\n\n\t*************************************\n\tRoot Cert: %v/%v-root-ca/%v created!\n\tStart Date : %v, Expiry Date : %v\n\t*************************************\n", pkiPathFromConfig, rootCertUID, caCertName, startDate, expiryDate)

		opensslRevocationCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl ca " + opensslPassinString + "-gencrl -out crl/root-ca.crl -batch"
		fmt.Printf("\n\tRevocation List at %v/%v-root-ca/crl/root-ca.crl\n\n", pkiPathFromConfig, rootCertUID)
		shellOutput = shell.Execute(opensslRevocationCmd, true, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nRevocation Generation error for root at location : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

// DR Root CA (DR A0) related task definitions
var taskDRRootCAPrepWork = gofer.Register(gofer.Task{
	Namespace:   "A0DR",
	Label:       "Prepare",
	Description: "Task to Prepare structure and permissions for DR Root CA (A0)",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := GetPkiPath()
		rootCertUID := GetRootUID()
		//use pkiPathFromConfig location and root uid as seed information to create the required root certs.
		createRootCertDirCmd := "mkdir -p " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/{certreqs,certs,crl,newcerts,private}"
		setRootCertPermsCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && chmod 700 private && touch ./root-ca.index && echo 00 > ./root-ca.crlnum"
		createRandSerialCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && openssl rand -hex 16 > ./root-ca.serial"

		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(createRootCertDirCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		shellOutput = shell.Execute(setRootCertPermsCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		shellOutput = shell.Execute(createRandSerialCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		return nil
	},
})

var taskDRRootCAConfig = gofer.Register(gofer.Task{
	Namespace:   "A0DR",
	Label:       "Config",
	Description: "Task to write DR Root CA (A0) Configuration",
	Action: func(arguments ...string) error {
		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]

		rootConfigFile := pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/root-ca.cnf"
		rootConfigResource, err := pkger.Open("/resources/root_ca.cnf")
		if err != nil {
			return err
		}
		defer rootConfigResource.Close()
		rootConfigResourceStats, err := rootConfigResource.Stat()
		if err != nil {
			return err
		}
		readBuffer := make([]byte, rootConfigResourceStats.Size())

		rootConfigResource.Read(readBuffer)
		err = ioutil.WriteFile(rootConfigFile, readBuffer, 0644)
		if err != nil {
			return err
		}

		setOidCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/#customOID/" + GetOid() + "/g\" root-ca.cnf"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOidCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save active OID in config at %v/%v-dr-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/sample_org Cloud Corporation/" + GetOrganizationName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Name in config at %v/%v-dr-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationCommonNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/sample_org Root Certification Authority/" + GetOrganizationCommonName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationCommonNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Common Name in config at %v/%v-dr-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskDRRootCACreate = gofer.Register(gofer.Task{
	Namespace:    "A0DR",
	Label:        "Create",
	Description:  "Create DR Root CA (A0)",
	Dependencies: []string{"A0DR:Prepare", "A0DR:Config"},
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]

		t := time.Now().UTC()
		startDate := fmt.Sprintf(t.AddDate(0, 0, -1).Format("20060102150405Z"))
		expiryDate := fmt.Sprintf(t.AddDate(30, 0, 0).Format("20060102150405Z"))

		/*
			fmt.Printf("\n\tEnter passphrase for DR A0 : ")
			a0Paaaphrase,_ := gopass.GetPasswdMasked()
			opensslPassoutString := "-passout pass:" + string(a0Paaaphrase) + " "
			opensslPassinString := "-passin pass:" + string(a0Paaaphrase) + " "

		*/

		opensslPassoutString := arguments[2]
		opensslPassinString := arguments[3]

		opensslCSRCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl req " + opensslPassoutString + opensslPassinString + "-new -out root-ca.req.pem"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(opensslCSRCmd, true, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nCSR Generation error for Root DR at location : %v/%v-dr-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		opensslSelfSignA0Cmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl rand -hex 16 > root-ca.serial && openssl ca " + opensslPassinString + "-selfsign -in root-ca.req.pem -out root-ca.cert.pem -extensions root-ca_ext -batch -startdate " + startDate + " -enddate " + expiryDate
		log.Printf("\nCreating Self Signed DR Root Certificate (A0)\n")
		shellOutput = shell.Execute(opensslSelfSignA0Cmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nCSR Generation error for root at location : %v/%v-dr-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		caCertName := strings.ReplaceAll(GetOrganizationName()+"_"+GetOrganizationCommonName()+"_"+"RA0_D_"+rootCertUID+".pem", " ", "-")
		selfSignA0DRCertCopyCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/root-ca.cert.pem  " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/" + caCertName
		shellOutput = shell.Execute(selfSignA0DRCertCopyCmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nCSR Generation error for root at location : %v/%v-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		log.Printf("\n\n\t*************************************\n\tDR Root Cert (A0): %v/%v-dr-root-ca/%v created!\n\tStart Date : %v, Expiry Date : %v\n\t*************************************\n", pkiPathFromConfig, rootCertUID, caCertName, startDate, expiryDate)

		opensslRevocationCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl ca " + opensslPassinString + "-gencrl -out crl/root-ca.crl -batch"
		fmt.Printf("\n\tRevocation List at %v/%v-dr-root-ca/crl/root-ca.crl\n\n", pkiPathFromConfig, rootCertUID)
		shellOutput = shell.Execute(opensslRevocationCmd, true, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nRevocation Generation error for root at location : %v/%v-dr-root-ca\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskDRRootCARecord = gofer.Register(gofer.Task{
	Namespace:   "A0DR",
	Label:       "SaveConfig",
	Description: "Task to Save DR Status in PKI central configuration",
	Action: func(arguments ...string) error {
		saveDRStatusCmd := "touch " + GetDRStatusConfigFile() + " && echo true > " + GetDRStatusConfigFile()
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(saveDRStatusCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to file : %v\n", GetDRStatusConfigFile())
			return shellOutput.CmdError
		}
		return nil
	},
})

// Intermediary CA related task definitions
var taskIntermediaryCAPrepWork = gofer.Register(gofer.Task{
	Namespace:   "A1",
	Label:       "Prepare",
	Description: "Task to Prepare structure and permissions for Intermediary CA (A1)",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		intermediaryDirCreateCmd := "mkdir -p " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/{certreqs,certs,crl,newcerts,private}"
		intermediaryPermSetCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && chmod 700 private && touch intermed-ca.index && echo 00 > intermed-ca.crlnum && openssl rand -hex 16 > intermed-ca.serial"

		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(intermediaryDirCreateCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		shellOutput = shell.Execute(intermediaryPermSetCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}
		return nil
	},
})

var taskIntermediaryCAConfig = gofer.Register(gofer.Task{
	Namespace:    "A1",
	Label:        "Config",
	Description:  "Task to write Intermediary CA (A1) Configuration",
	Dependencies: []string{"A1:Prepare"},
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		orgName := arguments[2]

		intermediateConfigFile := pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.cnf"
		intermediaryConfigResource, err := pkger.Open("/resources/intermediary_ca.cnf")
		if err != nil {
			return err
		}
		defer intermediaryConfigResource.Close()
		intermediaryConfigResourceStats, err := intermediaryConfigResource.Stat()
		if err != nil {
			return err
		}
		readBuffer := make([]byte, intermediaryConfigResourceStats.Size())

		intermediaryConfigResource.Read(readBuffer)
		err = ioutil.WriteFile(intermediateConfigFile, readBuffer, 0644)
		if err != nil {
			return err
		}

		setOrgNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && sed -i \"s/organizationName        =.*/organizationName        =" + orgName + "/g\" intermed-ca.cnf"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOrgNameCmd, false, false)

		setCommonNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && sed -i \"s/commonName              =.*/commonName              =A1/g\" intermed-ca.cnf"
		shellOutput = shell.Execute(setCommonNameCmd, false, false)

		replaceDomainNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && sed -i \"s/sampledom/" + orgName + "/g\" intermed-ca.cnf"
		shellOutput = shell.Execute(replaceDomainNameCmd, false, false)

		replaceDNSInternalNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && sed -i \"s/sfcc.tech/cluster.internal/g\" intermed-ca.cnf"
		shellOutput = shell.Execute(replaceDNSInternalNameCmd, false, false)

		removeSubAltNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/subjectAltName/#subjectAltName/g\" intermed-ca.cnf"
		shellOutput = shell.Execute(removeSubAltNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to remove Subject Alt Name requirements from config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to edit config file : %v/%v-intermed-ca/intermed-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOidCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && sed -i \"s/#customOID/" + GetOid() + "/g\" intermed-ca.cnf"
		shellOutput = shell.Execute(setOidCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to save active OID in config at %v/%v-intermed-ca/intermed-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskIntermediaryCABlankConfig = gofer.Register(gofer.Task{
	Namespace:   "A1",
	Label:       "BlankConfig",
	Description: "Task to write Intermediary CA (A1) Configuration",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]

		intermediateConfigFile := pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.cnf"
		intermediaryConfigResource, err := pkger.Open("/resources/intermediary_ca.cnf")
		if err != nil {
			return err
		}
		defer intermediaryConfigResource.Close()
		intermediaryConfigResourceStats, err := intermediaryConfigResource.Stat()
		if err != nil {
			return err
		}
		readBuffer := make([]byte, intermediaryConfigResourceStats.Size())

		intermediaryConfigResource.Read(readBuffer)
		err = ioutil.WriteFile(intermediateConfigFile, readBuffer, 0644)
		if err != nil {
			return err
		}

		setOidCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && sed -i \"s/#customOID/" + GetOid() + "/g\" intermed-ca.cnf"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOidCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to save active OID in config at %v/%v-intermed-ca/intermed-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskResetRootCAConfig = gofer.Register(gofer.Task{
	Namespace:   "A1",
	Label:       "A0ConfigReset",
	Description: "Task to write Intermediary CA (A1) Configuration",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		rootConfigFile01 := pkiPathFromConfig + "/" + rootCertUID + "-root-ca/root-ca.cnf"
		rootConfigResource, err := pkger.Open("/resources/root_ca.cnf")
		if err != nil {
			return err
		}
		defer rootConfigResource.Close()
		rootConfigResourceStats, err := rootConfigResource.Stat()
		if err != nil {
			return err
		}
		readBuffer := make([]byte, rootConfigResourceStats.Size())

		rootConfigResource.Read(readBuffer)
		err = ioutil.WriteFile(rootConfigFile01, readBuffer, 0644)
		if err != nil {
			return err
		}

		setOidCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/#customOID/" + GetOid() + "/g\" root-ca.cnf"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOidCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save active OID in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/#OrganizationName/" + GetOrganizationName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Name in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationCommonNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/#OrganizationCommonName/" + GetOrganizationCommonName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationCommonNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Common Name in config at %v/%v-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskResetDRRootCAConfig = gofer.Register(gofer.Task{
	Namespace:   "A1",
	Label:       "A0DRConfigReset",
	Description: "Task to write Intermediary CA (A1) Configuration",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		rootDRConfigFile01 := pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/root-ca.cnf"
		rootConfigResource, err := pkger.Open("/resources/root_ca.cnf")
		if err != nil {
			return err
		}
		defer rootConfigResource.Close()
		rootConfigResourceStats, err := rootConfigResource.Stat()
		if err != nil {
			return err
		}
		readBuffer := make([]byte, rootConfigResourceStats.Size())

		rootConfigResource.Read(readBuffer)
		rootDRCAConfigFileWritingError := ioutil.WriteFile(rootDRConfigFile01, readBuffer, 0644)
		if rootDRCAConfigFileWritingError != nil {
			return rootDRCAConfigFileWritingError
		}

		setOidCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/#customOID/" + GetOid() + "/g\" root-ca.cnf"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(setOidCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save active OID in config at %v/%v-dr-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/#OrganizationName/" + GetOrganizationName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Name in config at %v/%v-dr-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		setOrganizationCommonNameCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/#OrganizationCommonName/" + GetOrganizationCommonName() + "/g\" root-ca.cnf"
		shellOutput = shell.Execute(setOrganizationCommonNameCmd, false, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to save Organization Common Name in config at %v/%v-dr-root-ca/root-ca.cnf\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		return nil
	},
})

var taskIntermediaryCACreateA1 = gofer.Register(gofer.Task{
	Namespace:    "A1",
	Label:        "Create",
	Description:  "Create Intermediary CA (A1)",
	Dependencies: []string{"A1:Prepare", "A1:Config"},
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		nameRestriction := arguments[2]
		startDate := arguments[3]
		expiryDate := arguments[4]

		opensslPassoutString := arguments[5]
		opensslPassinString := arguments[6]
		opensslA0PassinString := arguments[7]

		opensslReqCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && export OPENSSL_CONF=./intermed-ca.cnf && openssl req " + opensslPassoutString + opensslPassinString + "-new -out intermed-ca.req.pem"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(opensslReqCmd, true, false)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			return shellOutput.CmdError
		}

		fixNamingCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && cp private/intermed-ca.key private/intermed-ca.key.pem"
		fixPemPermsCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && chmod 400 private/intermed-ca.key.pem"
		fixKeyPermsCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/ && chmod 400 private/intermed-ca.key"
		shellOutput = shell.Execute(fixNamingCmd, false, false)
		if shellOutput.CmdError != nil {
			return shellOutput.CmdError
		}
		shellOutput = shell.Execute(fixPemPermsCmd, false, false)
		if shellOutput.CmdError != nil {
			return shellOutput.CmdError
		}
		shellOutput = shell.Execute(fixKeyPermsCmd, false, false)
		if shellOutput.CmdError != nil {
			return shellOutput.CmdError
		}

		//copy CSR for Root CA signing
		queueToRootCACmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.req.pem " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/certreqs/"
		shellOutput = shell.Execute(queueToRootCACmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		if nameRestriction != "NA" {
			applyNameRestrictionCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/#permitted.DNS.1/permitted.DNS.1 = " + nameRestriction + "/g\" ./root-ca.cnf"
			shellOutput = shell.Execute(applyNameRestrictionCmd, false, false)
			if shellOutput.Stderr != "" {
				log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
				log.Fatal(shellOutput.CmdError)
			}
		} else {
			applyNameRestrictionCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && sed -i \"s/nameConstraints/#nameConstraints/g\" ./root-ca.cnf"
			shellOutput = shell.Execute(applyNameRestrictionCmd, false, false)
			if shellOutput.Stderr != "" {
				log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
				log.Fatal(shellOutput.CmdError)
			}
		}

		genRandomSerialCmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl rand -hex 16 > root-ca.serial"
		shellOutput = shell.Execute(genRandomSerialCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		signIntermediaryWithA0Cmd := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl ca " + opensslA0PassinString + "-in certreqs/intermed-ca.req.pem -out certs/intermed-ca.cert.pem -extensions intermed-ca_ext -batch -startdate " + startDate + " -enddate " + expiryDate
		shellOutput = shell.Execute(signIntermediaryWithA0Cmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to load your private key from, is this the right passphrase for Root CA (A0)?: %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		saveA0SignedIntermediaryCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/certs/intermed-ca.cert.pem " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.cert.pem"
		shellOutput = shell.Execute(saveA0SignedIntermediaryCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		caCertName := strings.ReplaceAll(GetOrganizationName()+"_"+GetOrganizationCommonName()+"_"+"IA1_"+rootCertUID+".pem", " ", "-")
		selfSignA1CertCopyCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.cert.pem " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/" + caCertName
		shellOutput = shell.Execute(selfSignA1CertCopyCmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		convertPrivateKeyCmd := "openssl rsa " + opensslPassinString + " -in " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/private/intermed-ca.key.pem " + " -out " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/private/intermed-ca-pkcs1.key.pem" + " -outform pem "
		shellOutput = shell.Execute(convertPrivateKeyCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		createCAChainBundleCmd := "cat " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/private/intermed-ca-pkcs1.key.pem " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/certs/intermed-ca.cert.pem  " + pkiPathFromConfig + "/" + rootCertUID + "-root-ca/root-ca.cert.pem > " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca-chain-bundle.cert.pem"
		shellOutput = shell.Execute(createCAChainBundleCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		caChainName := strings.ReplaceAll(GetOrganizationName()+"_"+GetOrganizationCommonName()+"_"+"IA1_"+rootCertUID+"chain-bundle.pem", " ", "-")
		selfSignA1ChainCopyCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca-chain-bundle.cert.pem " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/" + caChainName
		shellOutput = shell.Execute(selfSignA1ChainCopyCmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		return nil
	},
})

var taskIntermediaryCACrossSignA1 = gofer.Register(gofer.Task{
	Namespace:   "A1",
	Label:       "CrossSign",
	Description: "CrossSign Intermediary CA (A1)",
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		nameRestriction := arguments[2]
		startDate := arguments[3]
		expiryDate := arguments[4]

		opensslA0PassinString := arguments[5]

		//Handle DR Certificates here, if DR is enabled
		//copy CSR for Root CA signing
		coCmd09 := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.req.pem " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/certreqs/"
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(coCmd09, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		if nameRestriction != "NA" {
			coCmd10 := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && sed -i \"s/#permitted.DNS.1/permitted.DNS.1 = " + nameRestriction + "/g\" ./root-ca.cnf"
			shellOutput = shell.Execute(coCmd10, false, false)
			if shellOutput.Stderr != "" {
				log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca/\n", pkiPathFromConfig, rootCertUID)
				log.Fatal(shellOutput.CmdError)
			}
		}
		coCmd11 := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl rand -hex 16 > root-ca.serial"
		shellOutput = shell.Execute(coCmd11, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		coCmd12 := "cd " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/ && export OPENSSL_CONF=./root-ca.cnf && openssl ca " + opensslA0PassinString + "-in certreqs/intermed-ca.req.pem -out certs/intermed-ca.cert.pem -extensions intermed-ca_ext -batch -startdate " + startDate + " -enddate " + expiryDate
		shellOutput = shell.Execute(coCmd12, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to write to folder : %v/%v-dr-root-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		coCmd13 := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/certs/intermed-ca.cert.pem " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.dr.cert.pem"
		shellOutput = shell.Execute(coCmd13, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		caCertName := strings.ReplaceAll(GetOrganizationName()+"_"+GetOrganizationCommonName()+"_"+"IA1_C_"+rootCertUID+".pem", " ", "-")
		selfSignA1CertCopyCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca.dr.cert.pem " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/" + caCertName
		shellOutput = shell.Execute(selfSignA1CertCopyCmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		drChainCmd := "cat " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/private/intermed-ca-pkcs1.key.pem " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/certs/intermed-ca.cert.pem  " + pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/root-ca.cert.pem  > " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca-chain-bundle.dr.cert.pem"
		shellOutput = shell.Execute(drChainCmd, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		caChainName := strings.ReplaceAll(GetOrganizationName()+"_"+GetOrganizationCommonName()+"_"+"IA1_C_"+rootCertUID+"chain-bundle.pem", " ", "-")
		selfSignA1ChainCopyCmd := "cp " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/intermed-ca-chain-bundle.dr.cert.pem " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca/" + caChainName
		shellOutput = shell.Execute(selfSignA1ChainCopyCmd, true, true)
		if shellOutput.CmdError != nil {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		rootConfigFile02 := pkiPathFromConfig + "/" + rootCertUID + "-dr-root-ca/root-ca.cnf"
		rootConfigResource, rootConfigResourceErrors := pkger.Open("/resources/root_ca.cnf")
		if rootConfigResourceErrors != nil {
			return rootConfigResourceErrors
		}
		defer rootConfigResource.Close()
		rootConfigResourceStats, rootConfigResourceStatsErrors := rootConfigResource.Stat()
		if rootConfigResourceStatsErrors != nil {
			return rootConfigResourceStatsErrors
		}
		readBuffer := make([]byte, rootConfigResourceStats.Size())

		rootConfigResource.Read(readBuffer)
		drRootCaConfigFileWritingError := ioutil.WriteFile(rootConfigFile02, readBuffer, 0644)
		return drRootCaConfigFileWritingError
	},
})

var taskIntermediaryCAZipout = gofer.Register(gofer.Task{
	Namespace:    "A1",
	Label:        "Zipout",
	Description:  "Task to produce unique Intermediary CA (A1) PKI Zip output file",
	Dependencies: []string{"A1:A0ConfigReset", "A1:BlankConfig"},
	Action: func(arguments ...string) error {

		pkiPathFromConfig := arguments[0]
		rootCertUID := arguments[1]
		startDate := arguments[2]
		zipCmd01 := "mkdir " + pkiPathFromConfig + "/output "
		shellOutput := new(shell.ShellOutput)
		shellOutput = shell.Execute(zipCmd01, false, false)
		if shellOutput.Stderr != "" {
			log.Printf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			log.Fatal(shellOutput.CmdError)
		}

		zipCmd02 := "zip -r " + pkiPathFromConfig + "/output/" + rootCertUID + "-intermed-ca-" + startDate + ".zip " + pkiPathFromConfig + "/" + rootCertUID + "-intermed-ca"
		shellOutput = shell.Execute(zipCmd02, false, false)
		if shellOutput.CmdError != nil {
			log.Warnf("\nUnable to write to folder : %v/%v-intermed-ca/\n", pkiPathFromConfig, rootCertUID)
			//log.Fatal(zip_cmd02_exec_errors)
		}

		shell.ShellExecWithChannels("unzip -l "+pkiPathFromConfig+"/output/"+rootCertUID+"-intermed-ca-"+startDate+".zip ", true, false)
		log.Printf("\n\n\t*************************************\n\tYour Intermediary CA repo with Certificates have been saved as\n\t%v/output/%v-intermed-ca-%v.zip\n\t*************************************\n\n", pkiPathFromConfig, rootCertUID, startDate)
		shell.ShellExecWithChannels("mv "+pkiPathFromConfig+"/"+rootCertUID+"-intermed-ca "+pkiPathFromConfig+"/"+rootCertUID+"-intermed-ca-"+startDate, false, false)

		return nil
	},
})
