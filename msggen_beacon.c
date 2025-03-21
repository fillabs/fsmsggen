#include "msggen.h"
#include "cmem.h"
#include "copts.h"

#include "gn_types.h"

static int _options (MsgGenApp* app, int argc, char* argv[]);
static size_t _fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static void _process (MsgGenApp * app, FitSec * e);
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);
static void _receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort);

static int  _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);

static MsgGenApp _app = {
    "gn", MsgGenApp_DefaultApp, _process, _options, _fill, _onEvent, _receive, _ut_handler
};

__INITIALIZER__(initializer_beacon) {
     MsgGenApp_Register(&_app);
}
static int _o_beacon = 0;
static int _o_seq_number = 0;
static int _o_max_hop_limit = 1;
#ifndef NO_SECURITY
static int _o_secured_beacon = 1;
#endif
static int copt_on_gn_rsu(const copt_t* opt, const char* option, const copt_value_t* value);

static copt_t options[] = {
    { "B", "beacon",         COPT_BOOL , &_o_beacon,          "Send beacon if CAM disabled" },
#ifndef NO_SECURITY
    { NULL, "gn-no-sec",  COPT_IBOOL             , &_o_secured_beacon, "Send non-secured beacon" },
    { NULL, "no-sec",     COPT_IBOOL|COPT_NOHELP , &_o_secured_beacon, NULL },
#endif
    { NULL, "gn-rsu",   COPT_BOOL | COPT_CALLBACK, copt_on_gn_rsu, "Set to true for static station [mobile]" },
    { NULL, "gn-max-hop-limit",   COPT_INT , &_o_max_hop_limit, "Maximum hop limit for non-single-hop [1]" },
    { NULL, NULL, COPT_END, NULL, NULL }
};

static int _options(MsgGenApp* app, int argc, char* argv[])
{
    if (argc == 0) {
        fprintf(stderr, "\n");
        coptions_help(stderr, "GN", 0, options, "");
        return 0;
    }
    return coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
}

static GNExtendedHeader _def_eh = {
    .gbc = {
        .sequenceNumber = 0
    }
    // other fields will be also set to 0
};

static GNCommonHeader _def_ch = {
    0x00, // nextHeader ANY
    0x10, // .headerType = Beacon
    0x02, // .trafficClass
    0x80, // .flags - mobile station
    0,    // .payload length
    1,    // .maxHopLimit
    0,    // .reserved2
};

static int copt_on_gn_rsu(const copt_t* opt, const char* option, const copt_value_t* value)
{
    _def_ch.flags = 0x00;
    return 0;
}

static void _process (MsgGenApp * app, FitSec * e)
{
    if(_o_beacon){
        MsgGenApp_Send(e, app);
    }
}
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{}

static int _prepare_payload(MsgGenApp* app, FitSec * e, FSMessageInfo* m){
    m->status = 0;
#ifndef NO_SECURITY
    if (_o_secured_beacon) {
        m->sign.ssp.aid = FITSEC_AID_GNMGMT;
        memset(m->sign.ssp.sspData.opaque, 0, sizeof(m->sign.ssp.sspData.opaque));
        m->sign.ssp.sspLen = 0;
        m->payloadType = FS_PAYLOAD_SIGNED;

        if( 0 >= FitSec_PrepareSignedMessage(e, m)){
            fprintf(stderr, "%-2s PREP %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "PrepareSignedMessage", m->status, FitSec_ErrorMessage(m->status));
            return 0;
        }
    }
    else
#endif
    {
        m->payloadType = FS_PAYLOAD_UNSECURED;
        m->payload = m->message;
    }
    return 1;
}

static size_t _fill(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    size_t len;

    if(!_prepare_payload(app, e, m)){
        return -1;
    }

    GNCommonHeader* ch = (GNCommonHeader*)m->payload;
    GNExtendedHeader* eh = (GNExtendedHeader*)(ch + 1);
    *ch = _def_ch;
    *eh = _def_eh;
    eh->beacon.srcPosVector.latitude = m->position.latitude;
    eh->beacon.srcPosVector.longitude = m->position.longitude;
    eh->beacon.srcPosVector.timestamp = (m->generationTime / 10000000);

    m->payloadSize =((const char*)&((&eh->beacon)[1])) - m->payload;
#ifndef NO_SECURITY
    if (_o_secured_beacon) {
        len = FitSec_FinalizeSignedMessage(e, m);
        if (len <= 0) {
            fprintf(stderr, "%-2s PREP %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "FinalizeSignedMessage", m->status, FitSec_ErrorMessage(m->status));
        }
    }else
#endif
    {
        len = m->messageSize = m->payloadSize;
    }
    return len;
}

static void _receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort)
{

}

static int  _ut_handler(FSUT* ut, void* ptr, FSUT_Message* utm, int * psize)
{
    if(utm->code >= FS_UtGnTrigger_geoUnicast && utm->code <= FS_UtGnEventInd) {
        FitSec* e = (FitSec*)ptr;
        FSMessageInfo m = {0};
        GN_PrepareMessage(&m);
        _prepare_payload(&_app, e, &m);

        GNCommonHeader* ch = (GNCommonHeader*)m.payload;
        GNExtendedHeader* eh = (GNExtendedHeader*)(ch + 1);
        *ch = _def_ch;
        *eh = _def_eh;
        switch (utm->code){
        case FS_UtGnTrigger_geoUnicast:
            ch->headerType = 0x20; // GUC
            ch->trafficClass = utm->guc.trafficClass;
            ch->maxHopLimit = _o_max_hop_limit;

            eh->guc.sequenceNumber = _o_seq_number++;
            eh->guc.srcPosVector.latitude = m.position.latitude;
            eh->guc.srcPosVector.longitude = m.position.longitude;
            eh->guc.srcPosVector.timestamp = (m.generationTime / 10000000);
            
            eh->guc.dstPosVector.latitude = m.position.latitude;
            eh->guc.dstPosVector.longitude = m.position.longitude;
            eh->guc.dstPosVector.timestamp = (m.generationTime / 10000000);
            memcpy(&eh->guc.dstPosVector.gnAddr, utm->guc.dst_addr, 8);
            
            m.payloadSize =((const char*)&((&eh->guc)[1])) - m.payload;
        break;
        case FS_UtGnTrigger_geoAnycast:
            ch->headerType = 0x30; // GAC
        case FS_UtGnTrigger_geoBroadcast:
            if(utm->code == FS_UtGnTrigger_geoBroadcast)
                ch->headerType = 0x40; // GBC
            ch->headerType |= (0x03 & utm->gbc.shape); 
            ch->trafficClass = utm->gbc.trafficClass;
            ch->maxHopLimit = _o_max_hop_limit;
            eh->gbc.sequenceNumber = _o_seq_number++;;
            eh->gbc.srcPosVector.latitude = m.position.latitude;
            eh->gbc.srcPosVector.longitude = m.position.longitude;
            eh->gbc.srcPosVector.timestamp = (m.generationTime / 10000000);
            eh->gbc.latitude = utm->gbc.latitude;
            eh->gbc.longitude = utm->gbc.longitude;
            eh->gbc.distanceA = utm->gbc.a;
            eh->gbc.distanceB = utm->gbc.b;
            eh->gbc.angle = utm->gbc.angle;
            
            m.payloadSize =((const char*)&((&eh->gbc)[1])) - m.payload;
        break;
        case FS_UtGnTrigger_shb:
            ch->headerType = 0x50; // TSB Single HOP
            ch->trafficClass = utm->shb.trafficClass;
            eh->shb.srcPosVector.latitude = m.position.latitude;
            eh->shb.srcPosVector.longitude = m.position.longitude;
            eh->shb.srcPosVector.timestamp = (m.generationTime / 10000000);

            m.payloadSize =((const char*)&((&eh->shb)[1])) - m.payload;
        break;
        case FS_UtGnTrigger_tsb:
            ch->headerType = 0x51; // TSB Multihop
            ch->trafficClass = utm->shb.trafficClass;
            ch->maxHopLimit = _o_max_hop_limit;
            eh->tsb.sequenceNumber = _o_seq_number++;
            eh->tsb.srcPosVector.latitude = m.position.latitude;
            eh->tsb.srcPosVector.longitude = m.position.longitude;
            eh->tsb.srcPosVector.timestamp = (m.generationTime / 10000000);
            m.payloadSize =((const char*)&((&eh->tsb)[1])) - m.payload;
        }
#ifndef NO_SECURITY
        if (_o_secured_beacon) {
            if(0 >= FitSec_FinalizeSignedMessage(e, &m)){
                fprintf(stderr, "%-2s PREP %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "FinalizeSignedMessage", m.status, FitSec_ErrorMessage(m.status));
            }
        }else
#endif
        {
            m.messageSize = m.payloadSize;
        }
        GN_SendMessage(&_app, &m);
    }
    return 0;
}
