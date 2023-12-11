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
Use -D switch to get list of available interfaces. (like in tcpdump, lol).

In Linux you need to have SELinux permissions to access the network interface.
Please run `sudo setcap cap_net_raw,cap_net_admin=eip ./fsmsggen` to allow this access.

The tool has a ETSI UpperTester implementation. External tests system can interact with the tool using this interface.

The set of certificates is necessary to send and verify messages. Certificates can be generated using the certificate generation tool - 
part of the ETSI ITS Security test suite: [ItsCertGen](https://forge.etsi.org/rep/ITS/itscertgen/-/tree/release2). Please use release2 branch.

Please use certificate profiles from the [ETSI ITS Security Test Suite](https://forge.etsi.org/rep/ITS/TS.ITS/-/tree/master/data/certificates) or create your own set.

Certificates can be specified using -1 command line switch. You can provide the directory, single certificate file or (E)CTL file as an argument.

The minimal actions to start sending CAM messages are:
- put certificates in the path/to/certs (./POOL_CAM by default):
  - 1 RootCA certificate
  - 1 AA certificate
  - 1 AT certificate, with CAM permissions
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

## Command line scripts

Tool can execute simple command line scripts. There are generic commands and application specific commands:

### Generic commands
 - `load <path>`  - load data from path. Path can be a directory, certificate file, CTL or CRL file
 - `pause N` - skip next N rate ticks in script execution
 - `initialize` - reinitialize tool. Unload all certificates excepts CA ones from the command line, forget all PKI requests.
 - `position <lat> <long> [alt]` - set current position and (optionally) altitude. All these values in ITS format.
 - `pseudonym <cert id>` - change current AT certificate to the specified one 

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
