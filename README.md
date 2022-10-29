# SFCERT

privki is a PKI Initialization & Certs creation toolset.
you can use it for the following:

* initializing a PKI Repository
* Establish a new CA Authority with or without DR
* Issue Intermediary CA's for other Organizations and teams

### Prerequisites
- Your system should be one of the supported platforms: 
  ```darwin/amd64, darwin/ia32, windows/amd64, windows/x86, linux/amd64, linux/i386, linux/arm```
- You should have ```Golang 1.12``` or above installed on your system.
- You should have ```OpenSSL 1.1.1d FIPS``` or above installed on your system.
- You should have ```Zip 3.0``` or above installed on your system.

### Installing

- Pull the source code
- Run ``` make build```
- Run ``` make install``` 
 
 this installs ```privki``` in location pointed by ```$GOBIN```
 
## Getting Started

once you have followed the procedure under "Installing" section below you can use it for initializing a new CA Authority, by running: privki init

Once you have initialized a new Private Key Infrastructure,
you can establish a Certifying Authority, by creating the
required self-signed Root CA Certificates using createCert command

example:  privki create A0

If you would like your organizations PKI to have DR Capability, 
you can enable DR at this stage like shown in example below:

example: privki create A0 --with-dr=true

For more options, please use --help flag after any specific subcommand.

```
example: privki create A0 --help 
example: privki create A1 --help
```

It is also possible to execute the complete process non-interactively. 
To do so, please provide all passphrases for A0 or A1 through command 
line flags --passphrase. 

Here is an example of a complete workflow, with custom OID and DR
performed non-interactively:

```
pki-host# privki init
pki-host# privki  create A0 --with-dr=true --custom-oid="1.9.6.1.4.4.7.8.5" --org="alpha corp" --common-name="alpha certifying authority" --passphrase="A0_Password"
pki-host# privki create A1 --org="Alpha Chat Engineering Team" --name-restrict="dbsvc.chat.alpha.com" --root-passphrase="A0_Password" --passphrase="new_dbsvc_passphrase"
pki-host# privki create A1 --org="Alpha Chat Engineering Team" --name-restrict="mqsvc.chat.alpha.com" --root-passphrase="A0_Password" --passphrase="new_mqsvc_passphrase"
pki-host# privki create A1 --org="Alpha Chat Engineering Team" --name-restrict="websvc.chat.alpha.com" --root-passphrase="A0_Password" --passphrase="new_websvc_passphrase"
```
the above example, will accomplish the following:

* Initialize a brand new PKI Vault
* Create Root CA (A0) along with DR Root CA (A0 DR)
* Set custom OID "1.9.6.1.4.4.7.8.5" throughtout the Vault Root
* Generate three A1 Certifying authorities all for "Alpha Chat Engineering Team"
* All three A1 Certificates are name restricted to the subdomains they are responsible for.
* The execution is fully non-interactive, as needed passphrases are provided upfront through command line flags.

The structure created by the above example will look as follows:

```
pki-host# tree /home/cmaddanna/.privki/bscsp1bdnvecdg8dvpv0 
/home/cmaddanna/.privki/bscsp1bdnvecdg8dvpv0
├── bscsp1bdnvecdg8dvpv0-dr-root-ca
│   ├── certreqs
│   │   └── intermed-ca.req.pem
│   ├── certs
│   │   └── intermed-ca.cert.pem
│   ├── crl
│   │   └── root-ca.crl
│   ├── newcerts
│   │   ├── 19B34F898B68D03F6FA77BEE43B2E4C6.pem
│   │   ├── 2D73E60CC882E5460F38B1A29F6B367D.pem
│   │   ├── 65D154C54C94EEEE16CB7E2422DFC76C.pem
│   │   └── 7E508DE26FAFF941DBAD044EB1E9FDA7.pem
│   ├── private
│   │   └── root-ca.key.pem
│   ├── root-ca.cert.pem
│   ├── root-ca.cnf
│   ├── root-ca.crlnum
│   ├── root-ca.crlnum.old
│   ├── root-ca.index
│   ├── root-ca.index.attr
│   ├── root-ca.index.attr.old
│   ├── root-ca.index.old
│   ├── root-ca.req.pem
│   ├── root-ca.serial
│   └── root-ca.serial.old
├── bscsp1bdnvecdg8dvpv0-intermed-ca-20200722174505Z
│   ├── certreqs
│   ├── certs
│   ├── crl
│   ├── intermed-ca.cert.pem
│   ├── intermed-ca-chain-bundle.cert.pem
│   ├── intermed-ca-chain-bundle.dr.cert.pem
│   ├── intermed-ca.cnf
│   ├── intermed-ca.crlnum
│   ├── intermed-ca.dr.cert.pem
│   ├── intermed-ca.index
│   ├── intermed-ca.req.pem
│   ├── intermed-ca.serial
│   ├── newcerts
│   └── private
│       ├── intermed-ca.key
│       └── intermed-ca.key.pem
├── bscsp1bdnvecdg8dvpv0-intermed-ca-20200722174513Z
│   ├── certreqs
│   ├── certs
│   ├── crl
│   ├── intermed-ca.cert.pem
│   ├── intermed-ca-chain-bundle.cert.pem
│   ├── intermed-ca-chain-bundle.dr.cert.pem
│   ├── intermed-ca.cnf
│   ├── intermed-ca.crlnum
│   ├── intermed-ca.dr.cert.pem
│   ├── intermed-ca.index
│   ├── intermed-ca.req.pem
│   ├── intermed-ca.serial
│   ├── newcerts
│   └── private
│       ├── intermed-ca.key
│       └── intermed-ca.key.pem
├── bscsp1bdnvecdg8dvpv0-intermed-ca-20200722174520Z
│   ├── certreqs
│   ├── certs
│   ├── crl
│   ├── intermed-ca.cert.pem
│   ├── intermed-ca-chain-bundle.cert.pem
│   ├── intermed-ca-chain-bundle.dr.cert.pem
│   ├── intermed-ca.cnf
│   ├── intermed-ca.crlnum
│   ├── intermed-ca.dr.cert.pem
│   ├── intermed-ca.index
│   ├── intermed-ca.req.pem
│   ├── intermed-ca.serial
│   ├── newcerts
│   └── private
│       ├── intermed-ca.key
│       └── intermed-ca.key.pem
├── bscsp1bdnvecdg8dvpv0-root-ca
│   ├── certreqs
│   │   └── intermed-ca.req.pem
│   ├── certs
│   │   └── intermed-ca.cert.pem
│   ├── crl
│   │   └── root-ca.crl
│   ├── newcerts
│   │   ├── 5966D15E28B52D94B13D478A9831EDD9.pem
│   │   ├── 5C9C7538070C8C0C35B4B85D2823B8AC.pem
│   │   ├── F167079787E9BF265195C529F718ABB1.pem
│   │   └── FC0D56B9018018960A8A50C23BF0BC9F.pem
│   ├── private
│   │   └── root-ca.key.pem
│   ├── root-ca.cert.pem
│   ├── root-ca.cnf
│   ├── root-ca.crlnum
│   ├── root-ca.crlnum.old
│   ├── root-ca.index
│   ├── root-ca.index.attr
│   ├── root-ca.index.attr.old
│   ├── root-ca.index.old
│   ├── root-ca.req.pem
│   ├── root-ca.serial
│   └── root-ca.serial.old
└── output
    ├── bscsp1bdnvecdg8dvpv0-intermed-ca-20200722174505Z.zip
    ├── bscsp1bdnvecdg8dvpv0-intermed-ca-20200722174513Z.zip
    └── bscsp1bdnvecdg8dvpv0-intermed-ca-20200722174520Z.zip

31 directories, 74 files
pki-host# 
```
## Backup and Restore

You can also use privki to backup the entire setup from a system, to a destination of choice. 
This functionality is very useful as then it can be restored on a different machine, which can act as a PKI root

It is important to note that backup is encrypted and utilizes a transformation on privki binary internally. 
Which means the same version and plaf of privki binary has to be used to restore a backup on a different machine, 
which was used to create it on a different machine. 

This also means, any attempts to tamper with privki binary will make it incapable of restoring a previous backup.
the symmetric encryption combination we use is AES 256 / CBC / SHA 256 / HMAC

the below example shows how to create a USB backup on Linux, from an active PKI root host 

```
system01$ mount /dev/sdb1 /media/usbdrive
system01$ privki backup --destination=/media/usbdrive
```

then the usbdrive can be used to restore this backup on another host, and bootstrap it into the active PKI root

```
system01$ mount /dev/sdb1 /media/usbdrive
system01$ privki restore --source=/media/usbdrive
```

For more options, please use --help flag after any specific subcommand.


## Versioning
0.1.1 First referential implementation

0.1.2 Roaming profiles release


## License

The contents of this repository is licensed under the MS-RSL license.
Copyright © 2020, sample_org Cloud Corporation.

For more detail please refer to accompanying LICENSE.md file

## TODO
* Implement utility wide, global --silent mode 


 
