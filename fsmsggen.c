#define _CRT_SECURE_NO_WARNINGS

//#ifdef _MSC_VER
//#include <windows.h>
//#endif

#ifdef __GNUC__
#define __USE_GNU
#endif

#include <pcap.h>

#ifdef USE_LIBGPS
#include <gps.h>
#endif

#include "copts.h"
#include "cstr.h"
#include "cmem.h"
#include "cring.h"
#include "clog.h"
#include "cbyteswap.h"
#include "fitsec.h"
#include "fitsec_error.h"
#include "fitsec_time.h"
#include "uppertester/uppertester.h"

#include "msggen.h"
#include "gn_types.h"
#include "fsgpsd.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>

#include <netdb.h>

#ifdef WIN32
#define _MAC
 #include <windows.h>
 void usleep(__int64 usec);
 #ifdef _MSC_VER
  int gettimeofday(struct timeval* tp, struct timezone* tzp);
  time_t mkgmtime(struct tm *tim_p);
 #endif
#else
#include <unistd.h>
#include <sys/time.h>
#endif

static FitSecConfig cfg1;

static pchar_t* cfgfile = NULL;

#define ITS_UTC_EPOCH 1072915200

static FS3DLocation position = { 514743600, 56248900, 0 };
static unsigned long _msg_count = (unsigned long)-1;
static float _rate = 10; // 10Hz

static int _gn_src = 0;

char* _curStrTime = NULL;
pchar_t* _out = "out.pcap";
pchar_t* _in = NULL;
char* _iface = NULL;
int _iface_list = 0;

static int   _UTHandler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);
static int _changePseudonym = 0;
static int _o_secured = 1;
static int _o_verbose = 0;
static int _o_allow_loopback = 0;
static int _o_uppertester = 0;
static const char* _o_ut_addr = NULL;
static uint16_t _o_ut_port = 12345;
static const char * _o_dc = NULL;
int _gps_ch = -1;

static const char * _out_payload[] = {
    "raw", "gn"/*, "sec", "btp", "fs"*/
};

typedef struct ether_header_t ether_header_t;
__PACKED__(struct ether_header_t{

    uint8_t  dest[6];
    uint8_t  src[6];
    uint16_t type;
});

uint8_t buf[1024] = {
    // Ethernet header
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // destination: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // source MAC
    0x89, 0x47,                         // GeoNetworking
    0x12, 0x00, 0x05, 0x01,             // basic header
};

#define SHIFT_GN  14
#define SHIFT_SEC 18

static int copt_on_position(const copt_t* opt, const char* option, const copt_value_t* value);
//static int copt_on_msgType(const copt_t* opt, const char* option, const copt_value_t* value);
static int copt_on_gn_src_addr(const copt_t* opt, const char* option, const copt_value_t* value);
static int copt_on_ut_addr(const copt_t* opt, const char* option, const copt_value_t* value);
static int copt_on_verbose(const copt_t* opt, const char* option, const copt_value_t* value);
static int copt_on_load(const copt_t* opt, const char* option, const copt_value_t* value);
static int copt_on_set_dc(const copt_t* opt, const char* option, const copt_value_t* value);
#ifdef USE_LIBGPS
static int copt_on_gpsd(const copt_t* opt, const char* option, const copt_value_t* value);
#endif
static copt_t options [] = {
    { "h?", "help",     COPT_HELP,     NULL,          "Print this help page"},
    { "C",  "config",   COPT_CFGFILE,  &cfgfile,      "Config file"         },
//    { "m",  "type",     COPT_STR|COPT_CALLBACK, copt_on_msgType, "Message type" },
    { "n",  "count",    COPT_LONG,     &_msg_count,   "Message count" },
    { "i",  "iface",    COPT_STR,      &_iface,       "Network interface to send messages" },
    { "D",  "iface-list", COPT_BOOL,   &_iface_list,  "List network interfaces"},
    { "I",  "in",       COPT_PATH,     &_in,          "Input PCAP file name" },
    { "O",  "out",      COPT_PATH,     &_out,         "Output PCAP file name, 'none' for disable, (udp|tcp)://host:port for network stream" },
    { NULL, "out-payload", COPT_STRENUM,     &_out_payload,         "Output payload type for network stream: raw,gn. Default is raw" },
#define OPT_IDX_OUT_PAYLOAD 7
    { "r",  "rate",     COPT_FLOAT,    &_rate,        "Message rate in Hz" },
    { "t",  "time",     COPT_STR,      &_curStrTime,  "The ISO representation of starting time" },
    { "p",  "position", COPT_STR  | COPT_CALLBACK, copt_on_position,  "The position in form latitude:longitude" },
#ifdef USE_LIBGPS
    { "g",  "gpsd",     COPT_STR  | COPT_CALLBACK, copt_on_gpsd, "Connect to gpsd host:port" },
#endif
    { "s",  "srcaddr",  COPT_STR  | COPT_CALLBACK, copt_on_gn_src_addr,  "The GN source address" },
    { "u",  "ut",       COPT_BOOL | COPT_CALLBACK, copt_on_ut_addr, "Start UpperTester" },
    { "l",  "loopback", COPT_BOOL,     &_o_allow_loopback, "Receive packets sent by itself" },
    { "v",  "verbose",  COPT_BOOL | COPT_CALLBACK, copt_on_verbose,   "Be verbose (allow multiple -vvv)" },
    { "d",  "dc",       COPT_STR  | COPT_CALLBACK, copt_on_set_dc,  "Assign this DC to all CA certificates" },
    { "N",  "no-sec",   COPT_IBOOL ,   &_o_secured,   "Send non-secured packets" },
    { "1",  "load",     COPT_PATH|COPT_CALLBACK, copt_on_load,     "Load certificates or CTL/CRL data from file or directory"   },

    { NULL, NULL, COPT_END, NULL, NULL }
};

int loadCertificates(FitSec * e, const pchar_t * _path);
static int _strpdate(const char* s, struct tm* t);

static struct timeval _t_cur;
static long _tdelta = 0;

int FS3DPositionFromString(FS3DLocation * pos, const char * str);

static int copt_on_position(const copt_t* opt, const char* option, const copt_value_t* value)
{
    return FS3DPositionFromString(&position, value->v_str) ? 0 : -1;
}

#ifdef USE_LIBGPS
static int copt_on_gpsd(const copt_t* opt, const char* option, const copt_value_t* value)
{
    int ch = libgps_start(value->v_str);
    if(ch < 0)
        return -1;
    _gps_ch = ch;
    return 0;
}
#endif

static int copt_on_verbose(const copt_t* opt, const char* option, const copt_value_t* value)
{
    clog_level_t l = clog_level(0);
    if (value->v_boolean == 0) {
        if(l > 0){
            clog_set_level(0, l-1);
        }
    }else{
        if(l < CLOG_LASTLEVEL-1){
            clog_set_level(0, l+1);
        }
    }
    return 0;
}


static int copt_on_ut_addr(const copt_t* opt, const char* option, const copt_value_t* value)
{
    if (value->v_boolean == 0) {
        _o_uppertester = 0;
    }
    else {
        _o_uppertester = 1;
        if (value->v_boolean != 1) {
            char* d = cstrrchr(value->v_str, ':');
            if (d) {
                _o_ut_port = atoi(d + 1);
                *d = 0;
                if (d > value->v_str)
                    _o_ut_addr = value->v_str;
            }
            else {
                if (*value->v_str) {
                    if (strchr(value->v_str, '.')) {
                        _o_ut_addr = value->v_str;
                    }
                    else {
                        _o_ut_port = atoi(value->v_str);
                    }
                }
            }
        }
    }
    return 0;
}

typedef struct load_element_t {
    cring_t ring;
    const char * path;
    const char * dc;
}load_element_t;
static cring_t _o_load_elements = {&_o_load_elements, &_o_load_elements};
static int copt_on_load(const copt_t* opt, const char* option, const copt_value_t* value)
{
    load_element_t * e = cnew(load_element_t);
    if(e){
        e->path = value->v_str;
        e->dc = _o_dc;
        cring_enqueue(&_o_load_elements, &e->ring);
    }
    return 0;
}
static int copt_on_set_dc(const copt_t* opt, const char* option, const copt_value_t* value)
{
    if(cstrequal(value->v_str, "-")){
        _o_dc = NULL;
    }else{
        _o_dc = value->v_str;
    }
    return 0;
}

static MsgGenApp* _applications[10];
static size_t _applications_count = 0;

void setCurrentPosition(FS3DLocation * pos, FSTime64 * t){
#ifdef USE_LIBGPS
    if(_gps_ch>=0){
        FSGpsData data;
        if(libgps_get_data(_gps_ch, &data)){
            *pos = data.position;
            *t = data.time;
        }else{
            pos->latitude  = 0;
            pos->longitude = 0;
            if(t){
                *t = timeval2itstime64(&_t_cur) + _FSTime64from32(_tdelta);
            }
        }
    } else
#endif
    {
        if(t){
            *t = timeval2itstime64(&_t_cur) + _FSTime64from32(_tdelta);
        }
        *pos = position;
    }
}

void  MsgGenApp_Register(MsgGenApp* app)
{
    _applications[_applications_count++] = app;
}

static MsgGenApp * MsgGenApp_Select(const char* appName)
{
    for (size_t i = 0; i < _applications_count; i++) {
        if (cstrequal(appName, _applications[i]->appName)) {
            return _applications[i];
        }
    }
    return NULL;
}

static char _error_buffer[PCAP_ERRBUF_SIZE];

typedef struct {
    pcap_t* device;
    pcap_dumper_t* dumper;
    int out_fd;
}pcap_handler_t;
typedef void (proto_handler_fn)(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data);
static void _handler_none(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data);
static void _handler_file(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data);
static void _handler_iface(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data);
static void _handler_socket(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data);
static void _handler_read(uint8_t*, const struct pcap_pkthdr*,const uint8_t*);

static proto_handler_fn* _packet_handler = _handler_none;


static int copt_on_gn_src_addr(const copt_t* opt, const char* option, const copt_value_t* value)
{
    uint8_t* p = (uint8_t*)cstr_hex2bin_ex((char*)buf+6, 6, value->v_str, strlen(value->v_str), " \t\r\n:.,");
    if (p - buf != 12) {
        return -1;
    }
    _gn_src = 1;
    return 0;
}

static FSUT* ut = NULL;

static pcap_handler_t h = { NULL, NULL, 0 };

static const char * _cctates[] = {
    "UNKNOWN",
    "TRUSTED",
    "INVALID",
    ""
};

static bool _onEvent(FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{
    if (event == FSEvent_CertStatus) {
        FSCertificate * c = params->certStateChange.certificate;
        FSHashedId8 digest = cint64_hton(FSCertificate_Digest(c));
        printf("["cPrefixUint64"X](%s): %s => %s\n", digest, FSCertificate_Name(c), _cctates[params->certStateChange.from&3], _cctates[params->certStateChange.to&3]);
        if(_o_dc && (params->certStateChange.to & FSCERT_TRUSTED)) {
            printf("["cPrefixUint64"X]: Assign DC %s\n", digest, _o_dc);
            FSCertificate_SetDC(c, _o_dc, strlen(_o_dc));
        }
    }
    for (size_t i = 0; i < _applications_count; i++) {
        _applications[i]->onEvent(_applications[i], e, user, event, params);
    }
    
    return true;
}

int main(int argc, char** argv)
{
    FitSec* e;

#ifdef _MSC_VER
    SetDllDirectory("C:\\Windows\\System32\\Npcap\\");
#endif

    FitSecConfig_InitDefault(&cfg1);
    cfg1.flags |= FS_ALLOW_CERT_DUPLICATIONS;
    cfg1.cbOnEvent = _onEvent;
    cfg1.cbOnEventUser = NULL;

    int rc = coptions(argc, argv, COPT_NOERR_UNKNOWN | COPT_NOAUTOHELP | COPT_NOHELP_MSG, options);
    if (!COPT_ERC(rc)) {
        for (size_t i = 0; i < _applications_count; i++) {
            int n = _applications[i]->options(_applications[i], argc, argv);
            if (n < rc) {
                rc = n;
                if (COPT_ERC(rc))
                    break;
            }
        }
    }
    if (COPT_ERC(rc)) {
        coptions_help(stdout, argv[0], 0, options, "Message Generation");
        for (size_t i = 0; i < _applications_count; i++) {
            _applications[i]->options(_applications[i], 0, NULL);
        }
        return - 1;
    }
    argc = rc;
    if (_iface_list) {
        pcap_if_t* alldevsp = NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        if(0 > pcap_findalldevs(&alldevsp, errbuf)){
            mclog_error(PCAP, "%s", errbuf);
            return -1;
        }
        for (pcap_if_t* i = alldevsp; i; i = i->next) {
            printf("%s : %s\n", i->name, i->description);
            for (pcap_addr_t* a = i->addresses; a; a = a->next) {
                printf("    %s\n", inet_ntop(a->addr->sa_family, &a->addr->sa_data[2], errbuf, sizeof(errbuf)));
            }
        }
        return 0;
    }

    if(cstrequal(_out, "none")){
        _out = NULL;
    }

    const char * dev_name;
    if (_iface) {
        dev_name = _iface;
        h.device = pcap_open_live(_iface, 65535, PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_MAX_RESPONSIVENESS, 200, _error_buffer);
        _packet_handler = _handler_iface;
        _o_verbose = 1;
#ifdef WIN32
#ifndef OID_802_3_CURRENT_ADDRESS
#define OID_802_3_CURRENT_ADDRESS 0x01010102
#endif
        char mac[6] = { 0 };
        size_t l = sizeof(mac);
        pcap_oid_get_request(h.device, OID_802_3_CURRENT_ADDRESS, mac, &l);
        char buf[13];
        *cstr_bin2hex(buf, sizeof(buf), mac, 6) = 0;
        printf("MAC=%s\n", buf);
#endif
    }
    else {
        if (_in){
            h.device = pcap_open_offline(_in, _error_buffer);
            dev_name = _in;
        }else{
            h.device = pcap_open_dead(DLT_EN10MB, 65535);
            dev_name = _out;
        }
        if (h.device && _out) {
            pchar_t* host = NULL;
            struct addrinfo ai_hint = {
                .ai_family = AF_UNSPEC,
                .ai_socktype = SOCK_DGRAM
            };
            if(cstrnequal("udp://", _out, 6)){
                host = _out+6;
            }
            if(cstrnequal("tcp://", _out, 6)){
                ai_hint.ai_socktype = SOCK_STREAM;
                host = _out+6;
            }
            if(host){
                char * port = cstrchr(host, ':');
                if(port == NULL){
                    fprintf(stderr, "UDP: port must be specified for UDP stream\n");
                    return -1;
                }
                *(port++) = 0;
                struct addrinfo * ai_res = NULL;
                int rc = getaddrinfo (host, port, &ai_hint, &ai_res);
                if (rc != 0) {
                    fprintf(stderr, "%s:%s: %s\n", _out, port, gai_strerror(rc));
                    return -1;
                }
                rc = -1;
                for (struct addrinfo * rp = ai_res; rp != NULL; rp = rp->ai_next) {
                    rc = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                    if (rc > 0){
                        if(0 == connect(rc, rp->ai_addr, rp->ai_addrlen)){
                            h.out_fd = rc;
                            break;                  /* Success */
                        }
                        close(rc); rc = -1;
                    }
                }
                freeaddrinfo(ai_res);
                if(rc == -1){
                    fprintf(stderr, "%s:%s: %s\n", _out, port, gai_strerror(rc));
                    return -1;
                }
                _packet_handler = _handler_socket;
                h.out_fd = rc;
                h.dumper = NULL;
            }else{
                _packet_handler = _handler_file;
                h.dumper = pcap_dump_open(h.device, _out);
            }
        }
    }
    if (h.device == NULL) {
        mclog_error(PCAP, "%s: %s", dev_name, _error_buffer);
        return -1;
    }
    if(0 > pcap_setnonblock(h.device, 1, _error_buffer)){
        mclog_error(PCAP, "%s: %s", dev_name, _error_buffer);
    }

    gettimeofday(&_t_cur, NULL);
    
    if (_curStrTime) {
        struct tm t;
        if (0 > _strpdate(_curStrTime, &t)) {
            mclog_error(MAIN, "%s: Unknown time format\n", _curStrTime);
            return -1;
        }
        _tdelta = (long)((time_t)mkgmtime(&t) - _t_cur.tv_sec);
    }

    e = FitSec_New(&cfg1, "1");

    FSTime32 t = unix2itstime32(_t_cur.tv_sec + _tdelta);
    cring_foreach(load_element_t, l, _o_load_elements){
        _o_dc = l->dc;
        if( 0 > FitSec_LoadTrustData(e, t, l->path)){
            return -1;
        }
    }
    
    int arg = 1;
    if (_o_uppertester) {
        mclog_info(UT, "Start UpperTester Engine at %s:%u\n", _o_ut_addr, _o_ut_port);
        ut = FSUT_New(_o_ut_addr, _o_ut_port);
        for (size_t i = 0; i < _applications_count; i++) {
            if(_applications[i]->utHandler){
                mclog_info(UT, "    register %s\n", _applications[i]->appName);
                FSUT_RegisterHandler(ut, _applications[i]->utHandler, _applications[i]->utPtr ? _applications[i]->utPtr : e);
            }
        }
        FSUT_RegisterHandler(ut, _UTHandler, e);
        FSUT_Start(ut);
    }

    size_t icmd = 1;
    const struct timeval t_add = {0, 1000000 / _rate};
    for (size_t i = 0; i < _msg_count; i++) {
        FSUT_Message * um = NULL;
        if(arg < argc){ 
            if(i == icmd){
                if(0 == strcmp("pause", argv[arg])||0 == strcmp("wait", argv[arg])){
                    arg++;
                    if(arg < argc){
                        char * end = argv[arg];
                        uint32_t msec = strtoul(argv[arg], &end, 10);
                        if(end > argv[arg])
                            icmd += floor(_rate * msec ) - 1;
                        arg++;
                    }
                }else if(0 == strcmp("load", argv[arg])){
                    arg++;
                    if(arg < argc){
                        uint32_t t = unix2itstime32(_t_cur.tv_sec) + _tdelta;
                        FitSec_LoadTrustData(e, t, argv[arg]);
                        arg++;
                    }
                }else{
                    while(arg < argc){
                        int r = FSUT_CommandMessage(&um, argc - arg, argv + arg);
                        if(r <= 0){
                            arg++;
                        }else{
                            if(ut){
                                arg += r;
                                break;
                            }
                            mclog_warning(UT, "UpperTester must be started for script execution. Use -u option\n");
                            arg = argc;
                        }
                    }
                }
                icmd++;
            }
        }

        FSUT_Proceed(ut, um);
        if(um){
            free(um);
        }

        if (h.dumper == NULL) {
            pcap_dispatch(h.device, 1, _handler_read, (uint8_t*)e);
        }

        for (size_t i = 0; i < _applications_count; i++) {
            _applications[i]->process(_applications[i], e);
        }
       
        timeradd(&_t_cur, &t_add, &_t_cur);
        if(_packet_handler != _handler_file){
            struct timeval t_now;
            gettimeofday(&t_now, NULL);
            timersub(&_t_cur, &t_now, &t_now);
            if(( (t_now.tv_sec * 1000000) + t_now.tv_usec) > 0 ){
                usleep((t_now.tv_sec * 1000000) + t_now.tv_usec);
            }
        }
    }

    if (h.dumper) {
        pcap_dump_close(h.dumper);
    }

    pcap_close(h.device);
    
#ifdef USE_LIBGPS
    if(_gps_ch){
        libgps_stop(_gps_ch);
    }
#endif
    FitSec_Free(e);
    FSMessageInfo_Cleanup(); 
    return 0;
}

void GN_PrepareMessage(FSMessageInfo * m)
{
    m->message = (char*)&buf[SHIFT_SEC];
    m->messageSize = sizeof(buf) - SHIFT_SEC;
    m->sign.signerType = FS_SI_AUTO;
    setCurrentPosition(&m->position, &m->generationTime);
}

void GN_SendMessage(MsgGenApp * a, FSMessageInfo * m)
{
    uint8_t * g5 = ((uint8_t*)m->message) - SHIFT_SEC;
    if (!_gn_src && m->sign.cert) {
        FSHashedId8 id = FSCertificate_Digest(m->sign.cert);
        memcpy(g5 + 6, &id, 6);
    }

    if (m->payloadType == FS_PAYLOAD_UNSECURED) {
        g5[SHIFT_GN] = 0x11; // non secured packet
    }else{
        g5[SHIFT_GN] = 0x12; // secured packet
    }

    // inject in pcap
    struct pcap_pkthdr ph;
    ph.ts = _t_cur;
    ph.ts.tv_sec += _tdelta;
    ph.caplen = ph.len = (uint32_t) (m->messageSize + SHIFT_SEC);
    mclog_info(MAIN, "%s Msg sent app=%s gt="cPrefixUint64"u (%u bytes)\n",
            strlocaltime(ph.ts.tv_sec, ph.ts.tv_usec),
            a->appName, timeval2itstime64(&ph.ts), ph.len);
    _packet_handler(&h, &ph, g5);
}

void MsgGenApp_Send(FitSec * e, MsgGenApp * a) 
{
    FSMessageInfo m = {0};

    GN_PrepareMessage(&m);

    size_t len = a->fill(a, e, &m);
    if (len > 0) {
        GN_SendMessage(a, &m);
    }
}

static void _handler_none(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data)
{

}

static void _handler_file(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data)
{
    pcap_dump((uint8_t*)h->dumper, ph, data);
}

static void _handler_socket(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data)
{
    size_t len = ph->len;
    int n = copts_enum_value(options,OPT_IDX_OUT_PAYLOAD,_out_payload);
    if(n < 0 || n >= carraysize(_out_payload)){
        printf("ERROR OPT_IDX_OUT_PAYLOAD DEFINITION ");
        exit(-1);
    }
    if(n > 0){
        data += SHIFT_GN;
        len -= SHIFT_GN;
    }
    if(0 > send(h->out_fd, data, len, 0)){
        perror("send");
    }
}

static void _handler_iface(pcap_handler_t* h, struct pcap_pkthdr* ph, const uint8_t* data)
{
    pcap_inject(h->device, data, ph->len);
}

static void _handler_read(uint8_t* ptr, const struct pcap_pkthdr* ph, const uint8_t* data)
{
    FitSec* e = (FitSec*)ptr;
    if (ph->len > 0) {
        // check if GeoNetworking
        if(*(uint16_t*)(&data[12]) != 0x4789)
            return;
        if (_o_allow_loopback || memcmp(&data[6], &buf[6], 6)) {
            GNBasicHeader * bh = (GNBasicHeader *)&data[SHIFT_GN];
            FSMessageInfo m;
            m.message = (char*)(data + SHIFT_SEC);
            m.messageSize = ph->len - SHIFT_SEC;
            setCurrentPosition(&m.position, &m.generationTime);
            if(bh->nextHeader == 2) { // secured
                if (0 == FitSec_ParseMessage(e, &m)) {
                    // can not parse secured message
                    mclog_info(RECV, "%s Secured Message parsine error: %s\n",
                        stritsdate64(m.generationTime), 
                        FitSec_ErrorMessage(m.status)
                    );
                    return;
                }

                uint32_t flags = FSCertificate_GetState(m.sign.cert);
                const char * status = (flags & FSCERT_REVOKED) ? "revoked" : 
                                        (flags & FSCERT_INVALID) ? "invalid" :
                                            (flags & FSCERT_TRUSTED) ? "trusted" : "unknown";
                mclog_info(MAIN, "%s Message received (gt=%s cert="cPrefixUint64"X %s)\n",
                    stritsdate64(m.generationTime), 
                    stritstime64(m.generationTime),cint64_hton(FSCertificate_Digest(m.sign.cert)),
                    status);
                if (m.payloadType == FS_PAYLOAD_SIGNED) {
                    if (!FitSec_ValidateSignedMessage(e, &m)) {
                        mclog_info(RECV, "%s Secured Message validation error: %s\n",
                            stritsdate64(m.generationTime), 
                            FitSec_ErrorMessage(m.status)
                        );
                        return;
                    }
                }
            }else{
                m.payload = m.message;
                m.payloadSize = m.messageSize;
                m.payloadType = FS_PAYLOAD_UNSECURED;
            }
            GNCommonHeader * ch = (GNCommonHeader *)m.payload;
            GNExtendedHeader * eh = (GNExtendedHeader*)&ch[1];
            char * payload = (char *)eh;
            switch(ch->headerType >>4 ){
            case 1: //beacon
                payload += sizeof(eh->beacon);
                break;
            case 2: // GEOUNICAST
                payload += sizeof(eh->guc);
                break;
            case 3: // GEOANYCAST
                payload += sizeof(eh->gbc);
                break;
            case 4: // GEOBROADCAST
                payload += sizeof(eh->gbc);
                break;
            case 5: // TSB
                payload += sizeof(eh->tsb);
                break;
            case 6: // LS
                if((ch->headerType&0x0F) == 0){
                    payload+= sizeof(eh->lsreq);
                }else{
                    payload+= sizeof(eh->lsrep);
                }
                break;
            }
            FSUT_SendIndication(ut, FS_UtGnEventInd, payload, m.payload + m.payloadSize - payload);
            if(ch->nextHeader == 0x10 || ch->nextHeader == 0x20){ // BTP A or B
                BTPHeader * btp = (BTPHeader*)payload;
                // send to applications
                payload += sizeof(BTPHeader);
                m.payloadSize = m.payload + m.payloadSize - payload;
                m.payload = payload;
                for(size_t i=0; i<_applications_count; i++){
                    MsgGenApp* a = _applications[i];
                    if(a->receive){
                        a->receive(a, e, &m, cint16_hton(btp->dPort));
                    }
                }
            }
        }
    }
}

static int _strpdate(const char* s, struct tm* t)
{
    memset(t, 0, sizeof(struct tm));
    if (3 == sscanf(s, "%d-%d-%d", &t->tm_year, &t->tm_mon, &t->tm_mday)) {
        if (t->tm_year >= 1900 &&
            t->tm_mon >= 1 && t->tm_mon <= 12 &&
            t->tm_mday >= 1 && t->tm_mday <= 31) {
            t->tm_year -= 1900;
            t->tm_mon--;
            return 0;
        }
    }
    return -1;
}

static int _UTHandler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize)
{
    int size = *psize;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    switch (m->code) {
    case FS_UtInitialize: // utInitialize
        if (size >= sizeof(struct FSUTMsg_Initialize)) {
            FitSec_Clean(ptr);
            // load necessary certificates
            FSTime32 t = unix2itstime32(time(NULL) + _tdelta);
            cring_foreach(load_element_t, l, _o_load_elements){
                _o_dc = l->dc;
                if( 0 > FitSec_LoadTrustData(ptr, t, l->path)){
                    return -1;
                }
            }

            if (m->initialize.digest == 0 || FitSec_Select(ptr, FITSEC_AID_ANY, m->initialize.digest)) {
                mclog_info(MAIN, "%s UTInitialize (" cPrefixUint64 "X) - OK", strlocaltime(tv.tv_sec, tv.tv_usec), cint64_hton(m->initialize.digest));
            }
            else {
                const FSCertificate* c = FitSec_CurrentCertificate(ptr, FITSEC_AID_CAM);
                if (c && m->initialize.digest == FSCertificate_Digest(c)) {
                    mclog_info(MAIN, "%s UTInitialize (" cPrefixUint64 "X) - ALREADY", strlocaltime(tv.tv_sec, tv.tv_usec), cint64_hton(m->initialize.digest));
                }
                else {
                    mclog_info(MAIN, "%s UTInitialize (" cPrefixUint64 "X) - NOT FOUND", strlocaltime(tv.tv_sec, tv.tv_usec), cint64_hton(m->initialize.digest));
                    m->result.result = 0;
                }
            }
        }
        m->result.result = 1;
        m->code = FS_UtInitializeResult;
        *psize = sizeof(m->result);
        return 1;
    
    case FS_UtChangePosition: 
        if (size >= sizeof(struct FSUTMsg_ChangePosition)) {
            position.latitude += m->changePosition.deltaLatitude;
            position.latitude += m->changePosition.deltaLongitude;
        }
        m->result.result = 1;
        m->code = FS_UtChangePositionResult;
        *psize = sizeof(m->result);
        return 1;
    
    case FS_UtChangePseudonym: 
        if (size < sizeof(struct FSUTMsg_ChangePseudonym)) {
            _changePseudonym = 1;
        }
        m->result.result = 1;
        m->code = FS_UtChangePseudonymResult;
        *psize = sizeof(m->result);
        return 1;

    case FS_UtDenmTrigger:
        // send already prepared denm
        MsgGenApp_Send(ptr, MsgGenApp_Select("denm"));
        m->denmTriggerResult.code = FS_UtDenmTriggerResult;
        m->denmTriggerResult.result = 1;
        *psize = sizeof(m->denmTriggerResult);
        return 1;
    default:
        break;
    }
    return -1;
}
