# FSMsgGen - V2X message generator

CAM/DENM/PKI message generator using [FitSec](https://github.com/fillabs/fitsec2-rel) library.

## Build and install
The tool can be built for Linux and Windows (MSVC or cygwin).

If you want to build it for another architecture, please run `make ARCH=<arch>` where \<arch\> is one of supported architectures existing in FitSec _lib_ folder. 

## General usage
This is a demonstration tool to generate secured V2X messages:
  - CAM (as defined in ETSI EN 302 637-2)
  - DENM (as defined in ETSI EN 302 637-3)
  - PKI (as defined in ETSI TS 102 941)
  - .. to be continued.

Please run the `fsmsggen -h` to get full list of command line switches.

The tool is able to inject and read V2X messages directly on the Ethernet interface using PCAP library.
You can set the interface using the -i command line switch.
Use -D switch to get the list of available interfaces. (like in tcpdump, lol).

In Linux you need to have SELinux permissions to access the network interface.
Please run `sudo setcap cap_net_raw,cap_net_admin=eip ./fsmsggen` to allow this access.

The tool has a ETSI UpperTester implementation. External tests system can interact with the tool using this interface.

The tool needs for a set of certificates to send and verify messages. Certificates can be generated using the certificate generation tool - 
the part of the ETSI ITS Security test suite: [ItsCertGen](https://forge.etsi.org/rep/ITS/itscertgen/-/tree/release2). **Please use release2 branch**.

Please use certificate profiles from the [ETSI ITS Security Test Suite](https://forge.etsi.org/rep/ITS/TS.ITS/-/tree/master/data/certificates) or create your own set.
Anyway to start sending messages you need the Root CA, AA and at least one AT certificate.

Certificates can be specified using -1 command line switch. You can provide the directory, single certificate file or (E)CTL file as an argument. Multiple -1 swithes are allowed.

The minimal requirements to start sending CAM are:
- put certificates in some path/to/certs (./POOL_CAM by default):
  - 1 RootCA certificate
  - 1 AA certificate, signed with RootCA cert
  - 1 AT certificate, signed with AA cert and providing CAM permissions
- run the tool as `./fsmsggen -i eth0 -1 path/to/certs` 

If certificates permitting it, tool will inject CAM messages in the `eth0` interface.

## CA messages

It is possible to change position, speed, BTP port and station type in CAM messages. Please refer to the `./fitsec -h` information.

CAM generation can be started or stopped using upper-tester commands.

## DEN messages

The dedicated upper-tester command shall be used to trigger DENM. 

User can set station ID, sequence number, station type and BTP port for the message using command line switches.
It is also possible to generate negation or cancelation events

## PKI messages

Tool can be used to generate and send Enrolment and authorization PKI requests using HTTP.

EA and AA URLs can be set by the CTL or using the `-d <url>` switch __BEFORE__ the `-1 <cert path>`.

Enrollment and authorization procedure can be triggered by uppertester command or using command line scripting.

### Enrollment
The tool will select the Enrollment Authority certificate, suitable for the current location.
Enrollment procedure requires canonical station id and key pair. Theis ID and public key shall be registered in the Enrollment Authority.
You can let the tool to use hardcoded ones or change it to the custom ones using these command line options:
- -I &lt;path to station&gt; - The path to the canonical station identifier. <br>Default value is `b1b8c6e0b75dd6f676d577436bb541e`.
- -K &lt;path to private key&gt; - Path to the private key file. The file extension defines the curve to be used:
  - ".nist384"
  - ".bpool384"
  - ".bpool256"
  - ".sm2"
  - ".nist256" - used by default if unknown extension
  
  Default canonocal key pair is based on NIST P256 curve:
  - private `32B0BAC19C38E93A821413281C4755E6DC25B6CE5A12DA8AAB49FC9BBC86EDE2`
  - public  `024B1A9F155CFD5B99BB25D9A1207CB48A17287E3790E319D23873AE54B9931922` (y0 point type).

- --reenrol-delay <n sec> Run re-enrolment after the delay. Set to 0 to disable re-enrolment.

### Authorization
Authorization procedure will use the Authorization Authority certificate and Enrollment Credentials certificate, suitables for the current location.
Only CAM AID will be requested for the moment.

## Command line scripts
Tool can execute simple command line scripts. There are some generic and application specific commands:

### Generic commands
 - `load <path>`  - load data from path. Path can be a directory, certificate file, CTL or CRL file
 - `pause N` - skip next N 'ticks' in script execution
 - `initialize` - reinitialize tool. Unload all certificates, forget all running PKI requests, reload CA certificates specified in the command line, 
 - `position <lat> <long> [alt]` - set current position and (optionally) altitude. All these values shall be in ITS format.
 - `pseudonym <cert id>` - change current AT certificate for all applications to the specified by the HashedId8 value

### CAM commands
CAM commands have the following syntax: `cam <command> [options]`. Following commands supported:
- `start` - start CAM.
- `stop` - stop CAM
- `rate <value>` - set CAM rate in Hz. (unsupported yet)

### DENM commands
DENM commands are not yet supported. Can be implemented by request.

### PKI commands
Following commands are supported:
- `enrol` - Run enrollment procedure.
- `auth` - Run authorization procedure.
