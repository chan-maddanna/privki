package cmd

import (
	"github.com/yeka/zip"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"
	"sfcert/openssl"
	"strings"
)

//internal utility function to remove PKI structure
//within restore code, to reset any existing config
func removeContents(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	names, err := d.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, name := range names {
		err = os.RemoveAll(filepath.Join(dir, name))
		if err != nil {
			return err
		}
	}
	return nil
}

//internal function to traverse the encrypted archive, decrypt and extract the config archive
func traverseAndExtractConfig(configArchiveReader *zip.ReadCloser) {
	// Iterate through each file/dir found in
	for _, file := range configArchiveReader.File {
		// Open the file inside the zip archive
		// as an excrypted file
		file.SetPassword(openssl.GetBackupRestorePassword())

		archiveFile, err := file.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer archiveFile.Close()

		// Specify what the extracted file name should be.
		// You can specify a full path or a prefix
		// to move it to a different directory.
		// In this case, we will extract the file from
		// the archive to a file of the same name.
		targetDir := openssl.GetUserHomeDir()
		extractedFilePath := filepath.Join(
			targetDir,
			file.Name,
		)

		os.Mkdir(openssl.GetPkiBaseDir(),openssl.DefaultDirPerms)
		os.Mkdir(openssl.GetPkiConfigDir(),openssl.DefaultDirPerms)
		// Extract the item (or create directory)
		if file.FileInfo().IsDir() {
			// Create directories to recreate directory
			// structure inside the zip archive. Also
			// preserves permissions
			os.MkdirAll(extractedFilePath, file.Mode())
		} else {
			// Extract regular file since not a directory
			// Open an output file for writing
			outputFile, err := os.OpenFile(
				extractedFilePath,
				os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
				file.Mode(),
			)
			if err != nil {
				log.Fatal(err)
			}
			defer outputFile.Close()

			// "Extract" the file by copying archived file
			// contents to the output file
			_, err = io.Copy(outputFile, archiveFile)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

//internal function to traverse the encrypted archive, decrypt and extract the PKI archive
func traverseAndExtractPki(pkiArchiveReader *zip.ReadCloser) {
	pkiPath := openssl.GetPkiPath()
	os.Mkdir(openssl.GetPkiBaseDir(),openssl.DefaultDirPerms)

	// Iterate through each file/dir found in
	for _, file := range pkiArchiveReader.File {
		// Open the file inside the zip archive
		// as an excrypted file
		file.SetPassword(openssl.GetBackupRestorePassword())

		archiveFile, err := file.Open()
		if err != nil {
			log.Fatal(err)
		}
		defer archiveFile.Close()

		// Specify what the extracted file name should be.
		// You can specify a full path or a prefix
		// to move it to a different directory.
		// In this case, we will extract the file from
		// the archive to a file of the same name.
		//targetDir := openssl.GetUserHomeDir()
		//targetDir := pkiPath
		tokenSlice := strings.Split(pkiPath, "/")
		targetDir := strings.Join(tokenSlice[:len(tokenSlice)-1],"/")
		os.Mkdir(pkiPath,openssl.DefaultDirPerms)


		extractedFilePath := filepath.Join(
			targetDir,
			file.Name,
		)

		// Extract the item (or create directory)
		if file.FileInfo().IsDir() {
			// Create directories to recreate directory
			// structure inside the zip archive. Also
			// preserves permissions
			extSlice := strings.Split(extractedFilePath,"/")
			os.Mkdir(strings.Join(extSlice[:len(extSlice)-2],"/"), openssl.DefaultDirPerms)
			os.Mkdir(strings.Join(extSlice[:len(extSlice)-1],"/"), openssl.DefaultDirPerms)
		} else {
			// Extract regular file since not a directory
			extSlice := strings.Split(extractedFilePath,"/")
			os.Mkdir(strings.Join(extSlice[:len(extSlice)-2],"/"), openssl.DefaultDirPerms)
			os.Mkdir(strings.Join(extSlice[:len(extSlice)-1],"/"), openssl.DefaultDirPerms)
			// Open an output file for writing
			outputFile, err := os.OpenFile(
				extractedFilePath,
				os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
				file.Mode(),
			)
			if err != nil {
				log.Fatal(err)
			}
			defer outputFile.Close()

			// "Extract" the file by copying archived file
			// contents to the output file
			_, err = io.Copy(outputFile, archiveFile)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

}

//main internal function to handle PKI config and data decryption
//and restore on a new system to bootstrap a primary PKI root
func decryptAndRestore(sourcePath string) {
	err := removeContents(openssl.GetPkiBaseDir())
	if err != nil {
		log.Fatal(err)
	}
	openssl.SetBackupRestorePassword()
	os.Mkdir(openssl.GetPkiBaseDir(),openssl.DefaultDirPerms)

	// Create a reader out of the encrypted config archive
	// decrypt and extract config archive
	configArchiveReader, err := zip.OpenReader(sourcePath + "sfcert_config.dat")
	if err != nil {
		log.Printf("\n File %s : failed to open archive",sourcePath + "sfcert_config.dat")
		log.Fatal(err)
	}
	defer configArchiveReader.Close()
	traverseAndExtractConfig(configArchiveReader)

	// Create a reader out of the encrypted pki archive
	// decrypt and extract pki archive
	pkiArchiveReader, err := zip.OpenReader(sourcePath + "sfcert_pki.dat")
	if err != nil {
		log.Printf("\n File %s : failed to open archive",sourcePath + "sfcert_pki.dat")
		log.Fatal(err)
	}
	defer pkiArchiveReader.Close()
	traverseAndExtractPki(pkiArchiveReader)
}

func init() {
	var source string
	// Add and Process flags to check if DR certs are needed
	restoreConfigCmd.Flags().StringVar(&source, "source","NA","flag --destination=<full path to source directory where encrypted backup files are present>")
}