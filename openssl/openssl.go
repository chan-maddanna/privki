package openssl

import (
	"errors"
	"fmt"
	"github.com/chuckpreslar/gofer"
	"github.com/howeyc/gopass"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os/exec"
	"sfcert/shell"
	"strings"
	"time"
)

var drStatus string
var opensslPassoutString string
var opensslPassinString string

// Public Utility Functions follow
// Checks if openssl is available on the host machine
func CheckOpenSSL() {
	_, opensslError := exec.LookPath("openssl")
	_, opensslStdout, _ := shell.ShellExecWithChannels("openssl version", false, false)
	if opensslError != nil {
		log.Printf("OpenSSL not found on your system. Please make sure OpenSSL 1.1 or later is installed and in the search path. \n")
		log.Error(opensslError)
	}
	log.Printf(opensslStdout)
	if fileExists(GetRootCertUIDConfigFile()) {
		log.Printf("An existing PKI root was already found at %v. \n I you are sure you do not need this, please delete and try again", GetUserHomeDir()+pkiBaseDefault)
		log.Panic(errors.New("PKI root already exists"))
	}
}

// Checks if the openssl in use supports AES 256 CBC Cipher
func CheckAES256Cipher() {
	aes256Errors, _, _ := shell.ShellExecWithChannels("openssl enc -ciphers | grep aes-256-cbc", false, false)
	if aes256Errors != nil {
		log.Printf("Your OpenSSL installation does not support aes-256-cbc cipher.\n\t Please upgrade your OpenSSL Installation and try again.\n\n")
		log.Error(aes256Errors)
	}
}

// Get active OID in use for Custom Class Definitions
func GetOid() string {
	oidBytes, oidReadError := ioutil.ReadFile(GetOidConfigFile())
	if oidReadError != nil {
		log.Printf("unable to read your oid settings at %v, make sure to run privki init before creating certs", GetOidConfigFile())
		log.Fatal(oidReadError)
	}

	return strings.TrimSuffix(string(oidBytes), "\n")
}

// Get the Root Certifying authority's UID
// for the current PKI
func GetRootUID() string {
	rootCertUID, rootCertUIDError := ioutil.ReadFile(GetRootCertUIDConfigFile())

	if rootCertUIDError != nil {
		log.Printf("unable to find a registered root cert UID at %v", GetRootCertUIDConfigFile())
		log.Fatal(rootCertUIDError)
	}
	return strings.TrimSuffix(string(rootCertUID), "\n")
}

// Get path of active PKI Repository
func GetPkiPath() string {
	pkipathbytes, pkiconfigerror := ioutil.ReadFile(GetUserHomeDir() + pkiPathConfigFile)

	if pkiconfigerror != nil {
		log.Printf("unable to read your pki settings at %v, make sure to run privki initPki before creating certs", GetUserHomeDir()+pkiPathConfigFile)
		log.Fatal(pkiconfigerror)
	}

	return strings.TrimSuffix(string(pkipathbytes), "\n")
}

// Get active OID in use for Custom Class Definitions
func GetOrganizationName() string {
	organizationBytes, organizationReadError := ioutil.ReadFile(GetOrgNameConfigFile())
	if organizationReadError != nil {
		log.Printf("unable to read your organization settings at %v, make sure to run privki init before creating certs", GetOrgNameConfigFile())
		log.Fatal(organizationReadError)
	}

	return strings.TrimSuffix(string(organizationBytes), "\n")
}

// Get active OID in use for Custom Class Definitions
func GetOrganizationCommonName() string {
	commonBytes, commonReadError := ioutil.ReadFile(GetOrgCommonNameConfigFile())
	if commonReadError != nil {
		log.Printf("unable to read your organization's common name settings at %v, make sure to run privki init before creating certs", GetOrgCommonNameConfigFile())
		log.Fatal(commonReadError)
	}

	return strings.TrimSuffix(string(commonBytes), "\n")
}

// Initializes a PKI Repository
// Please note that at any point in time, there can only be one
// active repository on a host that acts as a Certifying Authority.
func InitPki() {

	rootUID := xid.New().String()
	current_pki_path := GetUserHomeDir() + pkiBaseDefault + rootUID

	// Run gofer Task PKI:createRootUID to generate unique root UID
	createRootUIDErrors := gofer.Perform("PKI:createRootUID", rootUID)
	if createRootUIDErrors != nil {
		log.Errorf("Errors occurred in execution of task \"PKI:createRootUID\" :", createRootUIDErrors)
	}

	// Run gofer Task PKI:init to init PKI repo/vault
	initPkiErrors := gofer.Perform("PKI:init", current_pki_path)
	if initPkiErrors != nil {
		log.Errorf("Errors occurred in execution of task \"PKI:init\" :", initPkiErrors)
	}

}

// Generate Self Signed Certificate for Root Certifying Authority
// and Create the Root Certifying Authority (A0)
// Using self generated PKI Configuration & random seed UID
func CreateRootCA(passphrase string) {
	log.Printf("Creating Root CA (A0)")
	pkiPathFromConfig := GetPkiPath()
	rootCertUID := GetRootUID()

	if passphrase != "NA" && len(passphrase) > 5 {
		opensslPassoutString = "-passout pass:" + passphrase + " "
		opensslPassinString = "-passin pass:" + passphrase + " "
	} else {
		fmt.Printf("\n\tEnter passphrase for A0 : ")
		a0Paaaphrase, _ := gopass.GetPasswdMasked()
		opensslPassoutString = "-passout pass:" + string(a0Paaaphrase) + " "
		opensslPassinString = "-passin pass:" + string(a0Paaaphrase) + " "
	}
	fmt.Printf("\n\n\t*************************************\n\tIMPORTANT: Please remember and note this Passphrase somewhere safe. \n\tYou will loose access to  your vault without this passphrase.\n\t*************************************\n")

	taskRootCACreateErrors := gofer.Perform("A0:Create", pkiPathFromConfig, rootCertUID, opensslPassoutString, opensslPassinString)
	if taskRootCACreateErrors != nil {
		log.Errorf("Errors occurred in execution of task \"A0:Create\" :", taskRootCACreateErrors)
	}
}

// Generate Self Signed Certificate for DR Root Certifying Authority
// and Create the Root DR Certifying Authority (DR A0)
// Using self generated PKI Configuration & random seed UUID
func CreateDRRootCA() {
	log.Printf("\n\nCreating DR Root CA (A0)")
	pkiPathFromConfig := GetPkiPath()
	rootCertUID := GetRootUID()

	//Create DR Root CA(A0) Certificate
	taskDRRootCACreateErrors := gofer.Perform("A0DR:Create", pkiPathFromConfig, rootCertUID, opensslPassoutString, opensslPassinString)
	if taskDRRootCACreateErrors != nil {
		log.Errorf("Errors occurred in execution of task \"A0DR:Create\" :", taskDRRootCACreateErrors)
	}

	taskDRRootCARecordErrors := gofer.Perform("A0DR:SaveConfig", pkiPathFromConfig, rootCertUID)
	if taskDRRootCARecordErrors != nil {
		log.Errorf("Errors occurred in execution of task \"A0DR:SaveConfig\" :", taskDRRootCARecordErrors)
	}
}

// Create Root CA (A0) and/or Root DR CA (DR A0) Cross signed Intermediate Certifying authority (A1)
// Using self generated PKI Configuration & random seed UUID
func CreateIntermediateCA(nameRestriction string, orgName string, passphrase string, rootPassphrase string) {

	log.Printf("\nCreating Intermediate CA (A1)\n")
	pkiPathFromConfig := GetPkiPath()
	rootCertUID := GetRootUID()
	if orgName == "NA" || orgName == "" {
		log.Warnf("\nPlease specify an organization or a project name for this Intermediate Certifying Authority")
		log.Fatalf("\nProgram Exit, try again with suggested corrections\n")
	}

	// Check if DR is Enabled
	drStatusBytes, drConfigError := ioutil.ReadFile(GetDRStatusConfigFile())
	if drConfigError != nil {
		log.Printf("unable to read your DR settings at %v. Proceeding without DR", GetDRStatusConfigFile())
		drStatus = "false"
	} else {
		drStatus = strings.TrimSuffix(string(drStatusBytes), "\n")
	}

	// Generate Start and Expiry dates for the intermediary (A1)
	t := time.Now().UTC()
	startDate := fmt.Sprintf(t.AddDate(0, 0, -1).Format("20060102150405Z"))
	expiryDate := fmt.Sprintf(t.AddDate(18, 0, 0).Format("20060102150405Z"))

	var opensslPassoutString, opensslPassinString, opensslA0PassinString string

	if rootPassphrase != "NA" && len(rootPassphrase) > 5 {
		opensslA0PassinString = "-passin pass:" + string(rootPassphrase) + " "
	} else {
		fmt.Printf("\n\tRoot CA (A0) Passphrase: ")
		a0Paaaphrase, _ := gopass.GetPasswdMasked()
		opensslA0PassinString = "-passin pass:" + string(a0Paaaphrase) + " "
	}

	if passphrase != "NA" && len(passphrase) > 5 {
		opensslPassoutString = "-passout pass:" + string(passphrase) + " "
		opensslPassinString = "-passin pass:" + string(passphrase) + " "
	} else {
		fmt.Printf("\n\tEnter a new passphrase for this Intermediary CA (A1) \n\tPlease make sure this is different from Root CA (A0):  ")
		a1Paaaphrase, _ := gopass.GetPasswdMasked()
		opensslPassoutString = "-passout pass:" + string(a1Paaaphrase) + " "
		opensslPassinString = "-passin pass:" + string(a1Paaaphrase) + " "
	}

	taskIntermediaryCACreateA1Errors := gofer.Perform("A1:Create", pkiPathFromConfig, rootCertUID, nameRestriction, startDate, expiryDate, opensslPassoutString, opensslPassinString, opensslA0PassinString)
	if taskIntermediaryCACreateA1Errors != nil {
		log.Errorf("Errors occurred in execution of task \"A1:Create\" :", taskIntermediaryCACreateA1Errors)
	}

	// DR CROSS SIGNING Only if DR is Enabled.
	// copy CSR for Root DR CA signing, IF DR is enabled by user
	if drStatus == "true" {
		taskIntermediaryCACrossSignA1Errors := gofer.Perform("A1:CrossSign", pkiPathFromConfig, rootCertUID, nameRestriction, startDate, expiryDate, opensslA0PassinString)
		if taskIntermediaryCACrossSignA1Errors != nil {
			log.Errorf("Errors occurred in execution of task \"A1:CrossSign\" :", taskIntermediaryCACrossSignA1Errors)
		}
	}

	// If DR is enabled check here and run ,"A1:A0DRConfigReset"
	if drStatus == "true" {
		taskDRConfigResetErrors := gofer.Perform("A1:A0DRConfigReset", pkiPathFromConfig, rootCertUID)
		if taskDRConfigResetErrors != nil {
			log.Warnf("Errors occurred in execution of task \"A1:A0DRConfigReset\" :", taskDRConfigResetErrors)
		}
	}

	//   Here, We package the new created Intermediary Certifying Authority,
	//   their PKI Repository & the certifications into a single zip file,
	//   save them in outputs folder and then print it out so that the user
	//   knows where to look for.
	taskIntermediaryCAZipoutErrors := gofer.Perform("A1:Zipout", pkiPathFromConfig, rootCertUID, startDate)
	if taskIntermediaryCAZipoutErrors != nil {
		log.Warnf("Errors occurred in execution of task \"A1:Zipout\" :", taskIntermediaryCAZipoutErrors)
	}

}
