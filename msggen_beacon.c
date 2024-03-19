#include "msggen.h"
#include "cmem.h"
#include "copts.h"

#include "gn_types.h"

static int _options (MsgGenApp* app, int argc, char* argv[]);
static size_t _fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static void _process (MsgGenApp * app, FitSec * e);
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);

static MsgGenApp _app = {
    "beacon", MsgGenApp_DefaultApp, _process, _options, _fill, _onEvent
};

__INITIALIZER__(initializer_beacon) {
     MsgGenApp_Register(&_app);
}
static int _o_beacon = 0;
static int _o_secured_beacon = 1;

static copt_t options[] = {
    { NULL, "beacon",         COPT_BOOL , &_o_beacon,          "Send beacon if CAM disabled" },
    { NULL, "no-sec-beacon",  COPT_IBOOL , &_o_secured_beacon, "Send non-secured beacon" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

static int _options(MsgGenApp* app, int argc, char* argv[])
{
    int rc = 0;
    if (argc == 0) {
        coptions_help(stderr, "BEACON", 0, options, "");
    }
    else {
        rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
    }
    return rc;
}

static GNExtendedHeader _def_eh = {
    .beacon = {
        .srcPosVector = {
            .gnAddr = {0},
            .timestamp = 0,
            .latitude = 0,
            .longitude = 0,
            .accAndSpeed = 0,
            .heading = 0
        }
    }
};

static GNCommonHeader _def_ch = {
    0x00, // nextHeader BTP-ANY
    0x10, // .headerType = e_beacon
    0x02, // .trafficClass
    0x80, // .flags
    0,    // .payload length
    1,    // .maxHopLimit
    0,    // .reserved2
};

static void _process (MsgGenApp * app, FitSec * e)
{
    if(_o_beacon){
        MsgGenApp_Send(e, app);
    }
}
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{}

static size_t _fill(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    size_t len;
    m->status = 0;
    if (_o_secured_beacon) {
        m->sign.ssp.aid = FITSEC_AID_GNMGMT;
        memset(m->sign.ssp.sspData.opaque, 0, sizeof(m->sign.ssp.sspData.opaque));
        m->sign.ssp.sspLen = 0;
        m->payloadType = FS_PAYLOAD_SIGNED;

        len = FitSec_PrepareSignedMessage(e, m);
        if (len <= 0) {
            fprintf(stderr, "%-2s PREP %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "PrepareSignedMessage", m->status, FitSec_ErrorMessage(m->status));
            return len;
        }
    }
    else {
        m->payloadType = FS_PAYLOAD_UNSECURED;
        m->payload = m->message;
    }

     GNCommonHeader* ch = (GNCommonHeader*)m->payload;
     GNExtendedHeader* eh = (GNExtendedHeader*)(ch + 1);
     *ch = _def_ch;
     *eh = _def_eh;
     eh->beacon.srcPosVector.latitude = m->position.latitude;
     eh->beacon.srcPosVector.longitude = m->position.longitude;
     eh->beacon.srcPosVector.timestamp = (m->generationTime / 10000000);

     m->payloadSize =((const char*)&((&eh->beacon)[1])) - m->payload;
     if (_o_secured_beacon) {
         len = FitSec_FinalizeSignedMessage(e, m);
         if (len <= 0) {
             fprintf(stderr, "%-2s PREP %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "FinalizeSignedMessage", m->status, FitSec_ErrorMessage(m->status));
         }
     }
     else {
         len = m->messageSize = m->payloadSize;
     }
    return len;
}
