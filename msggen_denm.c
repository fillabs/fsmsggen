#include "msggen.h"
#include "cmem.h"
#include "copts.h"

#include "DENM.h"
#include "gn_types.h"
#include "../uppertester/uppertester.h"

static void denm_process (MsgGenApp * app, FitSec * e);
static int denm_options (MsgGenApp* app, int argc, char* argv[]);
static size_t denm_fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static int  denm_ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);
static void denm_onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);

static MsgGenApp _denm = {
    "denm", 0, denm_process, denm_options, denm_fill, denm_onEvent, denm_ut_handler
};

__INITIALIZER__(initializer_denm) {
     MsgGenApp_Register(&_denm);
}

static const char* _o_stationTypes[] = {
    "",
    "unknown",      // 0
    "pedestrian",   // 1
    "cyclist",      // 2
    "moped",        // 3
    "motorcycle",   // 4
    "passengerCar", // 5
    "bus",          // 6
    "lightTruck",   // 7
    "heavyTruck",   // 8
    "trailer",         // 9
    "special", // 10
    "tram",            // 11
    "",                // 12
    "",                // 13
    "",                // 14
    "rsu",            // 15
    NULL
};

static const char * _o_btpTypes[] = {
    "NONE", "any", "btpA", "btpB", NULL
};

static int _o_secured = 1;

static DENM_t denm = {
    // ItsPduHeader
    { 2, MessageId_denm, 0x10101010 },
    // DecentralizedEnvironmentalNotificationMessage
    {
        // ManagementContainer
        {
            //ActionID (0, 0)
            {0, 0}    
        }        
    }
};

static int copt_on_termination(const copt_t* opt, const char* option, const copt_value_t* value);

static copt_t options[] = {
    { "I",  "station-id",       COPT_UINT ,     &denm.header.stationId, "Originating Station ID" },
    { "S",  "denm-action-sn",   COPT_UINT ,     &denm.denm.management.actionId.sequenceNumber, "Action Sequence number" },
    { NULL, "station-type",     COPT_STRENUM ,  _o_stationTypes,         "Station Type [unknown]" },
    { NULL, "denm-cancelation", COPT_BOOL | COPT_CALLBACK , copt_on_termination , "Generate cancelation message" },
    { NULL, "denm-negation",    COPT_BOOL | COPT_CALLBACK , copt_on_termination , "Generate negation message" },

    { "B",  "denm-btp-type",    COPT_STRENUM ,  _o_btpTypes, "BTP type (any|btpA|btpB) [default]" },
    { NULL, "no-sec-denm",      COPT_IBOOL ,   &_o_secured, "Send non-secured messages" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

static Termination_t _v_termination = Termination_isCancellation; 
static int copt_on_termination(const copt_t* opt, const char* option, const copt_value_t* value)
{
    if(denm.denm.management.termination == NULL){
        denm.denm.management.termination = &_v_termination;
    }
    *denm.denm.management.termination = (opt == &options[3]) ? Termination_isCancellation : Termination_isNegation;
    return 0;
}

static int denm_options(MsgGenApp* app, int argc, char* argv[])
{
    // init DENM
    denm.denm.management.actionId.originatingStationId = denm.header.stationId;

    int rc = 0;
    if (argc == 0) {
        coptions_help(stderr, "DENM", 0, options, "");
    }
    else {
        rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
        if (rc >= 0) {
            if (options[0].vptr != _o_stationTypes) {
                denm.denm.management.stationType = copts_enum_value(options, 0, _o_stationTypes)-1;
            }
        }
    }
    return rc;
}
static void denm_onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{}

static GNCommonHeader _def_ch = {
    0x20, // nextHeader BTP-B
    0x40, // .headerType = GeoBroadcast Circular
    0x00, // .trafficClass
    0x00, // .flags
    0,    // .payload length
    10,    // .maxHopLimit
    0,    // .reserved2
};

static GNExtendedHeader _def_eh = {
    .gbc = {
        .sequenceNumber = 0,
        .reserved = 0,
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

static void denm_process (MsgGenApp * app, FitSec * e)
{
    
}

static size_t denm_fill(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    size_t len;
    m->status = 0;

    if (_o_secured) {
        m->payloadType = FS_PAYLOAD_SIGNED;
        m->sign.ssp.aid = 37;
        memset(m->sign.ssp.sspData.opaque, 0, sizeof(m->sign.ssp.sspData.opaque));
        m->sign.ssp.sspLen = 4;
        m->sign.ssp.sspData.bits.version = 1;

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
    uint32_t * bh = (uint32_t*)&((&eh->gbc)[1]);
    bh[0] = 0x0000d207; // port 2002
    len = ((char*)&bh[1]) - m->payload;
    if(((const char **)options[5].vptr) != _o_btpTypes){
        ch->nextHeader = ((((const char **)options[5].vptr) - _o_btpTypes) - 1) * 0x10;
    }
    if(m->position.latitude || m->position.longitude){
        denm.denm.management.eventPosition.latitude = m->position.latitude;
        denm.denm.management.eventPosition.longitude = m->position.longitude;
    }else{
        denm.denm.management.eventPosition.latitude = Latitude_unavailable;
        denm.denm.management.eventPosition.longitude = Longitude_unavailable;
    }
    asn_uint642INTEGER(&denm.denm.management.referenceTime, m->generationTime/1000);
    asn_uint642INTEGER(&denm.denm.management.detectionTime, m->generationTime/1000); 
    
    eh->tsb.srcPosVector.latitude = m->position.latitude;
    eh->tsb.srcPosVector.longitude = m->position.longitude;
    eh->tsb.srcPosVector.timestamp = (uint32_t)(m->generationTime / 1000);

    asn_enc_rval_t rc = asn_encode_to_buffer(NULL, ATS_UNALIGNED_CANONICAL_PER, &asn_DEF_DENM, &denm, m->payload + len, m->payloadSize - len);
    if (rc.encoded < 0) {
        fprintf(stderr, "%-2s SEND %s:\t ERROR: %zu at %s\n", FitSec_Name(e), "asn_encode", rc.encoded, rc.failed_type->name);
        len = 0;
    }
    else {
        char* p = m->payload + len + rc.encoded;
        m->payloadSize = p - m->payload;

        ch->plLength = cint16_hton(rc.encoded + 4); // plus BTP
        if (_o_secured) {
            len = FitSec_FinalizeSignedMessage(e, m);
            if (len == 0) {
                fprintf(stderr, "%-2s SEND %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "FinalizeSignedMessage", m->status, FitSec_ErrorMessage(m->status));
            }
        }
        else {
            m->messageSize = p - m->message;
        }
    }
    return len;
}

static DeltaTimeMilliSecondPositive_t _v_transmissionInterval = 0;
static DeltaTimeSecond_t _v_validityDuration = 0;
static TrafficDirection_t _v_trafficDirection = TrafficDirection_allTrafficDirections;
static StandardLength3b_t _v_awarenessDiscance = StandardLength3b_lessThan50m;
static SituationContainer_t _v_situationContainer = {};

static int  denm_ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize)
{
    switch (m->code){
        case FS_UtDenmTrigger:
        {
            if(m->denmTrigger.flags & 0x80) {// validityDuration
                _v_validityDuration = *(DeltaTimeSecond_t*)&m->denmTrigger.validityDurationBuf[-1];
                _v_validityDuration = 0x00FFFFFF & cint32_ntoh(_v_validityDuration);
                denm.denm.management.validityDuration = &_v_validityDuration;
            }else{
                denm.denm.management.validityDuration = NULL;
            }
            if(m->denmTrigger.flags & 0x01) {// RelevanceTrafficDirection
                _v_trafficDirection = m->denmTrigger.relevanceTrafficDirection;
                denm.denm.management.trafficDirection = &_v_trafficDirection;
            }else{
                denm.denm.management.trafficDirection = NULL;
            }
            if(m->denmTrigger.flags & 0x04) {// TransmissionInterval 
                _v_transmissionInterval = m->denmTrigger.transmissionInterval;
                denm.denm.management.transmissionInterval = &_v_transmissionInterval;
            }
            if(m->denmTrigger.flags & 0x02) {// RepetitionInterval 
            }
            if(m->denmTrigger.flags & 0x40) {// RepetitionDuration
            }

            denm.denm.management.awarenessDistance = &_v_awarenessDiscance;
            _v_awarenessDiscance = m->denmTrigger.relevanceDistance;

            denm.denm.situation = &_v_situationContainer;
            _v_situationContainer.informationQuality = m->denmTrigger.infoQuality;
            _v_situationContainer.eventType.ccAndScc.present = m->denmTrigger.causeCode;
            _v_situationContainer.eventType.ccAndScc.choice.reserved0 = m->denmTrigger.subCauseCode;
    
            m->denmTriggerResult.sequenceNumber = denm.denm.management.actionId.sequenceNumber;
            m->denmTriggerResult.stationId =  denm.denm.management.actionId.originatingStationId;
            break;
        }
        case FS_UtDenmTermination:
            m->result.code = FS_UtDenmTerminationResult;
            m->result.result = 1;
            *psize = sizeof(m->result);
            return 1;
    }
    return 0;
}
