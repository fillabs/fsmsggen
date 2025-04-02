#include "uppertester.h"

#include <cmem.h>
#include <cstr.h>
#include <cring.h>
#include <stdio.h>

typedef struct UTHandlerRecord{
    const char * name;
    int (*create)(FSUT_Message ** pmsg, int argc, char ** argv);
    const char * help;
} UTHandlerRecord;

static int _FSUT_ExecCommand_RC(FSUT_Message ** pmsg, const UTHandlerRecord * cmds, size_t ccnt, int argc, char ** argv, int rc_if_not_found)
{
    if(argc > 0){
        for(int i=0; i<ccnt; i++){
            if(0 == strcmp(argv[0], cmds[i].name)){
                return cmds[i].create(pmsg, argc, argv);
            }
        }
    }
    return rc_if_not_found;
}

int _FSUT_ExecCommand(FSUT_Message ** pmsg, const UTHandlerRecord * cmds, size_t ccnt, int argc, char ** argv)
{
    return _FSUT_ExecCommand_RC(pmsg, cmds, ccnt, argc, argv, -255);
}

int _FSUT_ExecCommandSet(FSUT_Message ** pmsg, const UTHandlerRecord * cmds, size_t ccnt, int argc, char ** argv)
{
    int i = 0;
    while(i<argc){
        int rc = _FSUT_ExecCommand_RC(pmsg, cmds, ccnt, argc - i, argv + i, 0);
        if(rc == 0) break;
        i += rc;
    }
    return i;
}

static int _cmd_UtInitialize(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtChangePosition(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtChangePseudonym(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtCam(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDenmTrigger(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDenmUpdate(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDenmTerminate(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDenm(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtGnTrigger(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtEnroll(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtAuth(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtCrl(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtCtl(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtECtl(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtVam(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtBeacon(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtGUC(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtGBC(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtGAC(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtSHB(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtTSB(FSUT_Message ** pmsg, int argc, char ** argv);

static int _cmd_UtCurvature(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtSpeed(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtHeading(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtAcceleration(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtLight(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDirection(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDirection(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtStationType(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtVehicleRole(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtEmbarkationStatus(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtPtActivation(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtDangerousGoods(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtLightbar(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtSiren(FSUT_Message ** pmsg, int argc, char ** argv);

static const UTHandlerRecord _msgnames[] = {
    {"initialize", _cmd_UtInitialize,     "<hex digest|0> - initialize IUT with given AT certificate or with any certificate if zero given"},
    {"position", _cmd_UtChangePosition,   "<latitude delta> <longitude delta> - change IUT position by given deltas"},
    {"pseudonym", _cmd_UtChangePseudonym, "change IUT AT certificate to any available"},
    {"cam", _cmd_UtCam,                   "<start|stop|rate <Hz> > - start/stop CAM generation or change CAM rate"},
    {"denm", _cmd_UtDenm,                 "<send|update|stop|terminate - unsupported yet"},
    {"vam", _cmd_UtVam,                   "<start|stop|join|lead|leader>"},
    {"gn", _cmd_UtGnTrigger,              "<beacon|guc|gbc|gac|shb|tsb>"},
    {"enrol" , _cmd_UtEnroll,             ""},
    {"auth" , _cmd_UtAuth,                ""},
    {"crl" , _cmd_UtCrl,                  ""},
    {"ctl" , _cmd_UtCtl,                  ""},
    {"ectl" , _cmd_UtECtl,                ""},
    
    {"beacon" , _cmd_UtBeacon,            "<start|stop>"},
    {"guc" , _cmd_UtGUC,                  "<addr> [lf <lifetime>] [tc <trafficClass>] [pl <hex payload>]"},
    {"gbc" , _cmd_UtGBC,                  "<circle|rect|ellipse> <latitude:longitude> <a> [b] [lf <lifetime>] [tc <trafficClass>] [pl <hex payload>]"},
    {"gac" , _cmd_UtGAC,                  "<circle|rect|ellipse> <latitude:longitude> <a> [b] [lf <lifetime>] [tc <trafficClass>] [pl <hex payload>]"},
    {"shb" , _cmd_UtSHB,                  "[tc <trafficClass>] [pl <hex payload>]"},
    {"tsb" , _cmd_UtTSB,                  "[lf <lifetime>] [nh <hop number>] [tc <trafficClass>] [pl <hex payload>]"},

    {"curv" ,         _cmd_UtCurvature,         "unsupported yet "},
    {"speed" ,        _cmd_UtSpeed,             "unsupported yet "},
    {"heading" ,      _cmd_UtHeading,           "unsupported yet "},
    {"acceleration" , _cmd_UtAcceleration,      "unsupported yet "},
    {"light" ,        _cmd_UtLight,             "unsupported yet "},
    {"direction" ,    _cmd_UtDirection,         "unsupported yet "},
    {"yaw" ,          _cmd_UtDirection,         "unsupported yet "},

    {"station" ,      _cmd_UtStationType,       "unsupported yet "},
    {"role" ,         _cmd_UtVehicleRole,       "unsupported yet "},
    {"embarkation" ,  _cmd_UtEmbarkationStatus, "unsupported yet "},
    {"pta" ,          _cmd_UtPtActivation,      "unsupported yet "},
    {"dgoods" ,       _cmd_UtDangerousGoods,    "unsupported yet "},
    {"lightbar" ,     _cmd_UtLightbar,          "unsupported yet "},
    {"siren" ,        _cmd_UtSiren,             "unsupported yet "},  
};

static const char * _help = 
    "initialize <hex digest|0>                     - initialize IUT with given AT certificate or with any certificate if zero given\n"
    "position   <latitude delta> <longitude delta> [altitude delta]\n"
    "                                              - change IUT position by given deltas\n"
    "pseudonym                                     - change IUT AT certificate to any available\n"
    "cam start                                     - start CA service\n"
    "cam stop                                      - stop CA service\n"
    "cam rate <Hz>                                 - change CA rate\n"
    "denm <send|update|stop|terminate>             - unsupported yet\n"
    "vam start                                     - start VRU service\n"
    "vam stop                                      - stop VRU service\n"
    "vam join                                      - activate VRU join claster\n"
    "vam lead|leader                               - operate as VRU cluster leader\n"
    "gn <beacon|guc|gbc|gac|shb|tsb> [params...]   - send geonetworking packed with given params. See below for possible parameters\n"
    "enrol [EA hex digest|EA name]                 - start enrolment process with given EA or any available if EA not given\n"
    "auth  [AA hex digest|AA name]                 - start authorization process with given AA or any available if AA not given\n"
    "crl|ctl|ectl [url]                            - download CRL/CTL/ECTL\n"
    "beacon <start|stop|send>                      - start/stop beacon sending or send 1 beacon packet\n"
    "guc <addr> [lf <lifetime>] [tc <trafficClass>] [pl <hex payload>]\n"
    "                                              - send GeoUniCast packet to given address [LS is not working yet]\n"
    "gbc <circle|rect|ellipse> <latitude:longitude> <a> [b] [lf <lifetime>] [tc <trafficClass>] [pl <hex payload>]\n"
    "                                              - send GeoBroadcast packet to given area\n"
    "gac <circle|rect|ellipse> <latitude:longitude> <a> [b] [lf <lifetime>] [tc <trafficClass>] [pl <hex payload>]\n"
    "                                              - send GeoAnycast packet to given area\n"
    "shb [tc <trafficClass>] [pl <hex payload>]    - send Single Hop Broadcast packet\n"
    "tsb [lf <lifetime>] [nh <hop number>] [tc <trafficClass>] [pl <hex payload>] - send TSB packet\n"
;

const char * FSUT_CommandHelp(const char * cmd)
{
    if(cmd){
        for (size_t i=0; i< arraysize(_msgnames); i++){
            if(cstrequal(cmd, _msgnames[i].name)){
                return _msgnames[i].help;
            }
        }
        return "Unknown command";
    }
    return _help;
}

int FSUT_CommandMessage(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _FSUT_ExecCommand_RC(pmsg, &_msgnames[0], arraysize(_msgnames), argc, argv, 0);
}

static void _pack_int16(uint8_t * p, int16_t v)
{
const uint8_t *s = (const uint8_t *)&v;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    p[1] = s[0];
    p[0] = s[1];
#else
    p[0] = s[0];
    p[1] = s[1];
#endif
}

static void _pack_int32(uint8_t * p, int32_t v)
{
const uint8_t *s = (const uint8_t *)&v;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    p[3] = s[0];
    p[2] = s[1];
    p[1] = s[2];
    p[0] = s[3];
#else
    p[0] = s[0];
    p[1] = s[1];
    p[2] = s[2];
    p[3] = s[3];
#endif
}

static int _cmd_read_uint8(uint8_t* pn, int argc, char ** argv)
{
    if(argc > 0){
        char * e = NULL;
        unsigned long n = strtoul(argv[0], &e, 0);
        if(n < 255 && *e == 0){
            *pn = (uint8_t)n;
            return 1;
        }
    }
    return -255;
}

static int _cmd_read_uint16(void* pn, int argc, char ** argv)
{
    if(argc > 0){
        char * e = NULL;
        unsigned long n = strtoul(argv[0], &e, 0);
        if(n <= 0xFFFF && *e == 0){
            _pack_int16(pn, n);
            return 1;
        }
    }
    return -255;
} 

static int _cmd_read_hexbuf(void* plen, uint8_t * buf, size_t maxsize, int argc, char ** argv)
{
    char * d = (char*)buf;
    char * e = cstr_hex2bin(d, maxsize, argv[0], cstrlen(argv[0]));
    if(e >= d){
        _pack_int16(plen, (e-d) );
        return 1;
    }
    return -255;
}

static int _cmd_read_lat_lon(void * plat, void * plon, const char * v)
{
    const char * e = NULL;
    long lat = strtol(v, (char**)&e, 10);
    if(e > v && *e == ':'){
        v = e+1;
        long lon = strtol(v, (char**)&e, 10);
        if(e > v && *e == 0){
            _pack_int32(plat, lat);
            _pack_int32(plon, lon);
            return 1;
        }
    }
    return -255;
}

static int _cmd_UtInitialize(FSUT_Message ** pmsg, int argc, char ** argv)
{
    if(argc > 0){
        FSUT_Message * m = malloc(sizeof(m->initialize));
        m->initialize.code = FS_UtInitialize;
        m->initialize.digest = 0;
        *pmsg = m;
        if(argc > 1){
            char * end = argv[1];
            m->initialize.digest = strtoull(argv[1], &end, 16);
            if(end > argv[1]){
                m->initialize.digest = cint64_hton(m->initialize.digest);
            return 2;
            return 2;
                return 2;
            }
        }
        return 1;
    }
    return -255;
}

static int _cmd_UtChangePosition(FSUT_Message ** pmsg, int argc, char ** argv)
{
    if(argc > 2){
        char * end;
        int ret = 3;
        FSUT_Message * m = malloc(sizeof(m->changePosition));
        m->changePosition.code = FS_UtChangePosition;
        end = argv[1];
        m->changePosition.deltaLatitude = strtol(argv[1], &end, 0);
        if(end  > argv[1]){
            end = argv[2];
            m->changePosition.deltaLongitude = strtol(argv[2], &end, 0);
            if(end  > argv[2]){
                if(argc > 3){
                    end = argv[3];
                    m->changePosition.deltaAltitude = strtol(argv[3], &end, 0);
                    if(0 == *end)
                        ret++;
                }
                *pmsg = m;
                return ret;
            }
        }
    }
err:
    return -255;
}

static int _cmd_UtChangePseudonym(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = malloc(sizeof(m->changePseudonym));
    m->changePseudonym.code = FS_UtChangePseudonym;
    *pmsg = m;
    return 1;
}

static int _cmd_UtCamStatus(FSUT_Message ** pmsg, int argc, char ** argv, uint8_t code, uint8_t state) {
    FSUT_Message * m = malloc(sizeof(m->camState));
    m->camState.code = code;
    m->camState.state = state;
    *pmsg = m;
    return 1;
}

static int _cmd_UtCamStart(FSUT_Message ** pmsg, int argc, char ** argv) {
    return _cmd_UtCamStatus(pmsg, argc, argv, FS_UtCamTrigger, 1);
}
static int _cmd_UtCamStop(FSUT_Message ** pmsg, int argc, char ** argv) {
    return _cmd_UtCamStatus(pmsg, argc, argv, FS_UtCamTrigger, 0);
}
static int _cmd_UtCamRate(FSUT_Message ** pmsg, int argc, char ** argv) {
    return -255;
}

static const UTHandlerRecord _cammsgnames[] = {
    {"start", _cmd_UtCamStart},
    {"stop",  _cmd_UtCamStop},
    {"rate",  _cmd_UtCamRate}
};

static int _cmd_UtCam(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return 1 + _FSUT_ExecCommand(pmsg, _cammsgnames, arraysize(_cammsgnames), argc - 1, argv + 1);
}

static const UTHandlerRecord _denmmsgnames[] = {
    {"send",       _cmd_UtDenmTrigger},
    {"update",     _cmd_UtDenmUpdate},
    {"stop",       _cmd_UtDenmTerminate},
    {"terminate",  _cmd_UtDenmTerminate}
};

static int _cmd_UtDenm(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return 1 + _FSUT_ExecCommand(pmsg, _denmmsgnames, arraysize(_denmmsgnames), argc - 1, argv + 1);
}

static int _cmd_UtDenmTrigger(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}

static int _cmd_UtDenmUpdate(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}

static int _cmd_UtDenmTerminate(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}

static int _cmd_UtSimpleMessage(FSUT_Message ** pmsg, uint8_t code)
{
    FSUT_Message * m = malloc(sizeof(m->code));
    m->code = code;
    *pmsg = m;
    return 1;
}

static int _cmd_UtEnroll(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtSimpleMessage(pmsg, FS_UtGenerateInnerEcRequest);
}

static int _cmd_UtAuth(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtSimpleMessage(pmsg, FS_UtGenerateInnerAtRequest);
}

static int _cmd_UtCrl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtSimpleMessage(pmsg, FS_UtPkiTriggerCrlRequest);
}

static int _cmd_UtCtl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtSimpleMessage(pmsg, FS_UtPkiTriggerRcaCtlRequest);
}

static int _cmd_UtECtl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtSimpleMessage(pmsg, FS_UtPkiTriggerTlmCtlRequest);
}

static int _cmd_UtVamStart(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtCamStatus(pmsg, argc, argv, FS_UtVamTrigger, 1);
}

static int _cmd_UtVamStop(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtCamStatus(pmsg, argc, argv, FS_UtVamTrigger, 0);
}

static int _cmd_UtVamCluster(FSUT_Message ** pmsg, int argc, char ** argv, uint8_t code)
{
    FSUT_Message * m = malloc(sizeof(m->vamCluster));
    m->vamCluster.code = code;
    m->vamCluster.clasterId = 0;
    *pmsg = m;
    if(argc > 1){
        char * end;
        unsigned long n = strtoul(argv[1], &end, 0);
        if(*end == 0) {
            m->vamCluster.clasterId = n;
            return 2;
        }
    }
    return 1;
}

static int _cmd_UtVamJoin(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return _cmd_UtVamCluster(pmsg, argc, argv, FS_UtVamJoin);
}

static int _cmd_UtVamLead(FSUT_Message ** pmsg, int argc, char ** argv) {
    return _cmd_UtVamCluster(pmsg, argc, argv, FS_UtVamLeader);
}

static const UTHandlerRecord _vammsgnames[] = {
    {"start", _cmd_UtVamStart},
    {"stop",  _cmd_UtVamStop},
    {"join",  _cmd_UtVamJoin},
    {"lead",  _cmd_UtVamLead},
    {"leader",  _cmd_UtVamLead}
};

static int _cmd_UtVam(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return 1 + _FSUT_ExecCommand(pmsg, _vammsgnames, arraysize(_vammsgnames), argc - 1, argv + 1);
}

static const UTHandlerRecord _gnmsgnames[] = {
    {"beacon" , _cmd_UtBeacon },
    {"guc" , _cmd_UtGUC },
    {"gbc" , _cmd_UtGBC },
    {"gac" , _cmd_UtGAC },
    {"shb" , _cmd_UtSHB },
    {"tsb" , _cmd_UtTSB }
};

static int _cmd_UtGnTrigger(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return 1 + _FSUT_ExecCommand(pmsg, _gnmsgnames, arraysize(_gnmsgnames), argc -1, argv + 1);
}


static int _cmd_UtGUC_lf(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint16(&m->guc.lifetime, argc-1, argv+1);
}

static int _cmd_UtGUC_tc(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint8(&m->guc.trafficClass, argc-1, argv+1);
}

static int _cmd_UtGUC_pl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_hexbuf(&m->guc.payloadLength, m->guc.payload, FSUT_MAX_MSG_SIZE-sizeof(m->guc), argc-1, argv+1);
}

static const UTHandlerRecord _gucargs[] = {
    {"lf" , _cmd_UtGUC_lf },
    {"tc" , _cmd_UtGUC_tc },
    {"pl" , _cmd_UtGUC_pl },
};

// guc <addr> 
//     [lf <lf>]
//     [tc <tc>]
//     [pl <hexpayload>]
static int _cmd_UtGUC(FSUT_Message ** pmsg, int argc, char ** argv)
{
    if(argc > 1){
        FSUT_Message * m = malloc(FSUT_MAX_MSG_SIZE);
        memset(m, 0, FSUT_MAX_MSG_SIZE);
        m->code = FS_UtGnTrigger_geoUnicast;
        *pmsg = m;

        // addr
        char * d = (char *)&m->guc.dst_addr[0];
        char * e = cstr_hex2bin(d, sizeof(m->guc.dst_addr), argv[1], cstrlen(argv[1]));
        if((e - d) == sizeof(m->guc.dst_addr))
            return 2 + ((argc > 2) ? _FSUT_ExecCommand(&m, _gucargs, arraysize(_gucargs), argc - 2, argv + 2) : 0);
    }
    return -255;
}

/*
static int _cmd_UtBeacon_Start(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtBeacon_Stop(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtBeacon_Send(FSUT_Message ** pmsg, int argc, char ** argv);

static const UTHandlerRecord _beaconargs[] = {
    {"start" , _cmd_UtBeacon_Start },
    {"stop" , _cmd_UtBeacon_Stop },
    {"send" , _cmd_UtBeacon_Send },
};
*/
static int _cmd_UtBeacon(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}

static int _cmd_UtGBC_circle(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtGBC_rect(FSUT_Message ** pmsg, int argc, char ** argv);
static int _cmd_UtGBC_ellipse(FSUT_Message ** pmsg, int argc, char ** argv);

static const UTHandlerRecord _gbcargs[] = {
    {"circle",  _cmd_UtGBC_circle },
    {"rect",    _cmd_UtGBC_rect },
    {"ellipse", _cmd_UtGBC_ellipse },
};

// gbc <circle|rect|ellipse> ...
static int _cmd_UtGBC(FSUT_Message ** pmsg, int argc, char ** argv)
{
    if(argc > 1){
        FSUT_Message * m = malloc(FSUT_MAX_MSG_SIZE);
        memset(m, 0, FSUT_MAX_MSG_SIZE);
        m->code = FS_UtGnTrigger_geoBroadcast;
        *pmsg = m;
        
        return 1 + _FSUT_ExecCommand(&m, _gbcargs, arraysize(_gbcargs), argc - 1, argv + 1);
    }
    return -255;
}


static int _cmd_UtGBC_lf(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint16(&m->gbc.lifetime, argc-1, argv+1);
}

static int _cmd_UtGBC_tc(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint8(&m->gbc.trafficClass, argc-1, argv+1);
}
static int _cmd_UtGBC_pl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_hexbuf(&m->gbc.payloadLength, m->gbc.payload, FSUT_MAX_MSG_SIZE-sizeof(m->gbc), argc-1, argv+1);
}

static const UTHandlerRecord _gbcargs2[] = {
    {"lf" , _cmd_UtGBC_lf },
    {"tc" , _cmd_UtGBC_tc },
    {"pl" , _cmd_UtGBC_pl },
};
// gbc circle <lat:lon radius>
//     [lf <lf>]
//     [tc <tc>]
//     [pl <hexpayload>]
static int _cmd_UtGBC_circle(FSUT_Message ** pmsg, int argc, char ** argv)
{
    if(argc > 2){
        FSUT_Message * m = (*pmsg);
        *pmsg = m;
        m->gbc.shape = 0;
        if(0 > _cmd_read_lat_lon(&m->gbc.latitude, &m->gbc.longitude, argv[1]))
            return 1-255;
        if(0 > _cmd_read_uint16(&m->gbc.a, 1, argv + 2))
            return 2-255;
        return 3 + _FSUT_ExecCommandSet(&m, _gucargs, arraysize(_gucargs), argc - 3, argv + 3);
    }
    return -255;
}

// gbc rect <lat:lon a b angle>
//     [lf <lf>]
//     [tc <tc>]
//     [pl <hexpayload>]
static int _cmd_UtGBC_rect(FSUT_Message ** pmsg, int argc, char ** argv)
{
    if(argc > 4){
        FSUT_Message * m = (*pmsg);
        m->gbc.shape = 1;
        *pmsg = m;
        if(0 > _cmd_read_lat_lon(&m->gbc.latitude, &m->gbc.longitude, argv[1]))
            return 1-255;
        if(0 > _cmd_read_uint16(&m->gbc.a, 1, argv+2))
            return 2-255;
        if(0 > _cmd_read_uint16(&m->gbc.b, 1, argv+3))
            return 3-255;
        if(0 > _cmd_read_uint16(&m->gbc.angle, 1, argv+4))
            return 4-255;
        return 5 + _FSUT_ExecCommand(&m, _gbcargs2, arraysize(_gbcargs2), argc - 5, argv + 5);
    }
    return -255;
}

// gbc ellipse <lat:lon a b angle>
//     [lf <lf>]
//     [tc <tc>]
//     [pl <hexpayload>]
static int _cmd_UtGBC_ellipse(FSUT_Message ** pmsg, int argc, char ** argv)
{
    int rc = _cmd_UtGBC_rect(pmsg, argc, argv);
    (*pmsg)->gbc.shape = 2;
    return rc;
}

static int _cmd_UtGAC(FSUT_Message ** pmsg, int argc, char ** argv)
{
    int rc = _cmd_UtGBC(pmsg, argc, argv);
    if(rc > 0){
        (*pmsg)->code = FS_UtGnTrigger_geoAnycast;
    }
    return rc;
}
static int _cmd_UtSHB_tc(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint8(&m->shb.trafficClass, argc-1, argv+1);
}
static int _cmd_UtSHB_pl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_hexbuf(&m->shb.payloadLength, m->shb.payload, FSUT_MAX_MSG_SIZE-sizeof(m->shb), argc-1, argv+1);
}

static const UTHandlerRecord _shbargs[] = {
    {"tc" , _cmd_UtSHB_tc },
    {"pl" , _cmd_UtSHB_pl },
};

//shb
//     [tc <tc>]
//     [pl <hexpayload>]
static int _cmd_UtSHB(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = malloc(FSUT_MAX_MSG_SIZE);
    memset(m, 0, FSUT_MAX_MSG_SIZE);
    m->code = FS_UtGnTrigger_shb;
    *pmsg = m;
    return 1 + _FSUT_ExecCommandSet(pmsg, _shbargs, arraysize(_shbargs), argc-1, argv+1);
}

static int _cmd_UtTSB_tc(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint8(&m->tsb.trafficClass, argc-1, argv+1);
}
static int _cmd_UtTSB_pl(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_hexbuf(&m->tsb.payloadLength, m->tsb.payload, FSUT_MAX_MSG_SIZE-sizeof(m->tsb), argc-1, argv+1);
}
static int _cmd_UtTSB_lf(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint16(&m->tsb.lifetime, argc-1, argv+1);
}
static int _cmd_UtTSB_nh(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = *pmsg;
    return 1 + _cmd_read_uint8(&m->tsb.hopNumber, argc-1, argv+1);
}

static const UTHandlerRecord _tsbargs[] = {
    {"tc" , _cmd_UtTSB_tc },
    {"nh" , _cmd_UtTSB_nh },
    {"lf" , _cmd_UtTSB_lf },
    {"pl" , _cmd_UtTSB_pl },
};

static int _cmd_UtTSB(FSUT_Message ** pmsg, int argc, char ** argv)
{
    FSUT_Message * m = malloc(FSUT_MAX_MSG_SIZE);
    memset(m, 0, FSUT_MAX_MSG_SIZE);
    m->code = FS_UtGnTrigger_tsb;
    *pmsg = m;
    
    return 1 + _FSUT_ExecCommand(&m, _tsbargs, arraysize(_tsbargs), argc - 1, argv + 1);
}

static int _cmd_UtCurvature(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtSpeed(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtHeading(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtAcceleration(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtLight(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtDirection(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtStationType(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtVehicleRole(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtEmbarkationStatus(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtPtActivation(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtDangerousGoods(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtLightbar(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
static int _cmd_UtSiren(FSUT_Message ** pmsg, int argc, char ** argv)
{
    return -255;
}
