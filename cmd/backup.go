package cmd

import (
	log "github.com/sirupsen/logrus"
	"github.com/yeka/zip"
	"io"
	"os"
	"path/filepath"
	"sfcert/openssl"
	"strings"
)

//local utility function to get short/relative naming for internal paths
// that will be used in config archive encryption
func getShortFileName(filename string) (shortname string) {
	split := strings.Split(filename, "/")
	return strings.Join(split[3:], "/")
}

//local utility function to get short/relative naming for internal paths
// that will be used in PKI archive encryption
func getShortPkiName(filename string) (shortname string) {
	split := strings.Split(filename, "/")
	return strings.Join(split[4:], "/")
}

//local implementation of walker function for standard filepath crawlers
//that format structure for the standard config layout, iteratively
func configWalkers(writer *zip.Writer, configDir string) {
	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}

		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		// Ensure that `path` is not absolute; it should not start with "/".
		// transforms path into a archive root relative path.
		encryptedWriter, err := writer.Encrypt(getShortFileName(file.Name()), openssl.GetBackupRestorePassword(), zip.AES256Encryption)
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.Copy(encryptedWriter, file)
		if err != nil {
			log.Fatal(err)
		}
		return nil
	}

	err := filepath.Walk(configDir, walker)
	if err != nil {
		log.Fatal(err)
	}

}

//local implementation of walker function for standard filepath crawlers
//that format structure for the standard PKI layout, iteratively
func pkiWalkers(writer *zip.Writer, configDir string) {
	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}

		if info.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		// Ensure that `path` is not absolute; it should not start with "/".
		// This snippet happens to work because I don't use
		// absolute paths, but ensure your real-world code
		// transforms path into a zip-root relative path.
		//_, err = writer.Create(filepath.Base(file.Name()))
		encryptedWriter, err := writer.Encrypt(getShortPkiName(file.Name()), openssl.GetBackupRestorePassword(), zip.AES256Encryption)
		if err != nil {
			log.Fatal(err)
		}

		_, err = io.Copy(encryptedWriter, file)
		if err != nil {
			log.Fatal(err)
		}
		return nil
	}

	err := filepath.Walk(configDir, walker)
	if err != nil {
		log.Fatal(err)
	}

}

//Main internal function to perform encryption, compression and archive
//takes in a destination location as an argument.
func encryptedArchiver(destination string) {
	openssl.SetBackupRestorePassword()
	baseConfigDir := openssl.GetPkiConfigDir() + "/"

	// Create a new encrypted config archive
	configOutputFile, err := os.Create(destination + "sfcert_config.dat")
	if err != nil {
		log.Fatal(err)
	}
	defer configOutputFile.Close()
	configArchive := zip.NewWriter(configOutputFile)
	defer configArchive.Close()
	configWalkers(configArchive, baseConfigDir)

	// Create a new encrypted pki archive
	basePkiDir := openssl.GetPkiPath() + "/"
	pkiOutputFile, err := os.Create(destination + "sfcert_pki.dat")
	if err != nil {
		log.Fatal(err)
	}
	defer pkiOutputFile.Close()
	pkiArchive := zip.NewWriter(pkiOutputFile)
	defer pkiArchive.Close()
	pkiWalkers(pkiArchive, basePkiDir)

	log.Printf("\nThe following backup files have been created: \n CONFIG :%s%s\n PKIPACK:%s%s", destination, "/sfcert_config.dat", destination, "/sfcert_pki.dat")
}

//Init function for backupConfigCmd
func init() {
	var destination string
	// Add and Process flags to check if DR certs are needed
	backupConfigCmd.Flags().StringVar(&destination, "destination", "NA", "flag --destination=<full path to destination directory where backup should be stored> sets destination directory to save encrypted backups")
}
