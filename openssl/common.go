package openssl

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/chuckpreslar/gofer"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"os/user"
)

const pkiConfigDir string = "/.privki/config"
const orgCommonNameConfigFile string = "/.privki/config/common"
const orgNameConfigFile string = "/.privki/config/org"
const drStatusConfigFile string = "/.privki/config/drstatus"
const oidConfigFile string = "/.privki/config/oid"
const primaryRootConfigFile string = "/.privki/config/primary_root"
const pkiPathConfigFile string = "/.privki/config/pki_path"
const rootCertUIDConfigFile = "/.privki/config/root_cert_uid"
const pkiBaseDefault = "/.privki/"
const DefaultDirPerms = 0755

var backupPassword string

// Get the Host PKI Configuration Directory
func GetPkiConfigDir() string {
	return GetUserHomeDir() + pkiConfigDir
}

// Get the Host PKI Base Directory
func GetPkiBaseDir() string {
	return GetUserHomeDir() + pkiBaseDefault
}

// Gets config file that contains Organization's Common Name
func GetOrgCommonNameConfigFile() string {
	return GetUserHomeDir() + orgCommonNameConfigFile
}

// Gets config file that contains Root UID
func GetRootCertUIDConfigFile() string {
	return GetUserHomeDir() + rootCertUIDConfigFile
}

// Gets Config File that contains Organization Name
func GetOrgNameConfigFile() string {
	return GetUserHomeDir() + orgNameConfigFile
}

// Gets Config File that contains PKI Config Path
func GetPkiPathConfigFile() string {
	return GetUserHomeDir() + pkiPathConfigFile
}

// Gets Config File that contains active OID
func GetOidConfigFile() string {
	return GetUserHomeDir() + oidConfigFile
}

// Gets the config file that contains primary root
func GetPrimaryRootConfigFile() string {
	return GetUserHomeDir() + primaryRootConfigFile
}

// Gets config file that contains Dr status
func GetDRStatusConfigFile() string {
	return GetUserHomeDir() + drStatusConfigFile
}

// Gets use home directory where that is also users SSL & Certificate home
// Note in Windows these both can be different, and SSL home will often be the roaming directory
func GetUserHomeDir() string {
	currentUser, userError := user.Current()
	if userError != nil {
		log.Fatal(userError)
	}
	return currentUser.HomeDir
}

// Set Custom OID if provided by the user
// If not use default OID implemented by sample_org Cloud Corporation
func SetCustomOid(customOID string) {
	err := gofer.Perform("A0:SetCustomOID", customOID)
	if err != nil {
		log.Errorf("Error setting up custom OID.\n")
	}
}

// Sets vault wide Owner, and registers it as the Organization Name for A0
func SetOrganizationName(organizationName string) {
	setOrganizationNameErrors := gofer.Perform("A0:SetOrganizationName", organizationName)
	if setOrganizationNameErrors != nil {
		log.Errorf("Error setting Organization name. Task A0:SetOrganizationName\n")
	}
}

// Sets A0 Organization Common Name field.
func SetOrganizationCommonName(organizationCommonName string) {
	SetOrganizationCommonNameErrors := gofer.Perform("A0:SetOrganizationCommonName", organizationCommonName)
	if SetOrganizationCommonNameErrors != nil {
		log.Errorf("Error setting Organization Common name. Task A0:SetOrganizationCommonName\n")
	}
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func GetBackupRestorePassword() string {
	return backupPassword
}

func SetBackupRestorePassword() {
	selfBytes, err := os.Open(os.Args[0])
	if err != nil {
		log.Fatal(err)
	}
	defer selfBytes.Close()
	hasher := sha256.New()

	hasher.Write([]byte("SHA256_DIGMAC_CPSR"))
	hasher.Write([]byte("HMAC_ID_CODEPSR"))
	if _, err := io.Copy(hasher, selfBytes); err != nil {
		log.Fatal(err)
	}
	hasher.Write([]byte("AES256_CBC_CTR1"))

	backupPassword = hex.EncodeToString(hasher.Sum(nil))
}
