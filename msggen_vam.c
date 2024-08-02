#include "msggen.h"
#include "cmem.h"
#include "copts.h"

#include "payload/VAM.h"
#include "gn_types.h"
#include "../uppertester/uppertester.h"

#ifdef USE_LIBGPS
#include <gps.h>
#include <math.h>
const struct gps_data_t * get_gps_data();
#endif

static void _process (MsgGenApp * app, FitSec * e);
static int _options  (MsgGenApp* app, int argc, char* argv[]);
static size_t _fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);

static int   _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);

static MsgGenApp _app = {
    "vam", 0, _process, _options, _fill, _onEvent, _ut_handler
};

__INITIALIZER__(initializer_vam) {
     MsgGenApp_Register(&_app);
}

static int _o_secured = 1;
static int _o_btpA = 0;
static int _o_activated = 0;
static int _o_stationType = 0;

static const struct {
    const char *               option;
    TrafficParticipantType_t   tpType;
    VruProfileAndSubprofile_PR vruProfilePR;
    long                       subProfile;
} _st_types [] = {
    {"pedestrian",   TrafficParticipantType_pedestrian, VruProfileAndSubprofile_PR_pedestrian, VruSubProfilePedestrian_ordinary_pedestrian },
    {"roadworker",   TrafficParticipantType_pedestrian, VruProfileAndSubprofile_PR_pedestrian, VruSubProfilePedestrian_road_worker },
    
    {"bicyclist",    TrafficParticipantType_cyclist,         VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_bicyclist },
    {"wheelchair",   TrafficParticipantType_lightVruVehicle, VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_wheelchair_user },
    {"horserider",   TrafficParticipantType_animal,          VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_horse_and_rider },
    {"rollerskater", TrafficParticipantType_lightVruVehicle, VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_rollerskater },
    {"escooter",     TrafficParticipantType_cyclist,         VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_e_scooter },
    {"pedelec",      TrafficParticipantType_cyclist,         VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_pedelec },
    {"speedpedelec", TrafficParticipantType_cyclist,         VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_speed_pedelec },
    {"roadbike",     TrafficParticipantType_cyclist,         VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_roadbike },
    {"childrensbike",TrafficParticipantType_cyclist,         VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle, VruSubProfileBicyclist_childrensbike },
    {"moped",        TrafficParticipantType_moped,           VruProfileAndSubprofile_PR_motorcyclist, VruSubProfileMotorcyclist_moped },
    {"motorcycle",   TrafficParticipantType_motorcycle,      VruProfileAndSubprofile_PR_motorcyclist, VruSubProfileMotorcyclist_motorcycle },
    {"motorcycle-sidecar-right", TrafficParticipantType_motorcycle,      VruProfileAndSubprofile_PR_motorcyclist, VruSubProfileMotorcyclist_motorcycle_and_sidecar_right },
    {"motorcycle-sidecar-left", TrafficParticipantType_motorcycle,      VruProfileAndSubprofile_PR_motorcyclist, VruSubProfileMotorcyclist_motorcycle_and_sidecar_right  },
    {"animal",         TrafficParticipantType_animal,         VruProfileAndSubprofile_PR_animal, VruSubProfileAnimal_unavailable },
    {"wild-animal",    TrafficParticipantType_animal,         VruProfileAndSubprofile_PR_animal, VruSubProfileAnimal_wild_animal },
    {"farm-animal",    TrafficParticipantType_animal,         VruProfileAndSubprofile_PR_animal, VruSubProfileAnimal_farm_animal },
    {"service-animal", TrafficParticipantType_animal,         VruProfileAndSubprofile_PR_animal, VruSubProfileAnimal_service_animal }
};  

static int  _st_callback(const copt_t * opt, const char * option, const copt_value_t * value)
{
    if(cstrequal("list", value->v_str)){
        printf("Available station type options:\n");
        for(size_t i = 0; i < (sizeof(_st_types)/sizeof(_st_types[0])); i++){
            printf("  %s\n", _st_types[i].option);
        }
        return COPT_EHELP;
    }

    for(size_t i = 0; i < (sizeof(_st_types)/sizeof(_st_types[0])); i++){
        if(cstrequal(_st_types[i].option, value->v_str)){
            _o_stationType = i;
            return 0;
        }
    }
    return -1;
}

static copt_t options[] = {
    { "T",  "vam-station-type",  COPT_CALLBACK ,  _st_callback, "Station Type [pedestrian by default]. 'list' to show all variants" },
    { "B",  "vam-btpA",          COPT_BOOL ,    &_o_btpA, "Use BTP A [use btpB by default]" },
    { "V",  "vam-start",         COPT_BOOL ,    &_o_activated,  "Start sending VAM by default"},
    { NULL, "vam-no-sec",        COPT_IBOOL ,   &_o_secured,    "Send non-secured cam" },
    { NULL, NULL, COPT_END, NULL, NULL }
};

static VAM_t* vam = NULL;

static VruSizeClass_t _sizeClass = 2;
static VruLowFrequencyContainer_t vam_lfc = {
    .profileAndSubprofile = {
        .present = VruProfileAndSubprofile_PR_pedestrian,
        .choice = {
            .pedestrian = VruSubProfilePedestrian_unavailable
        }
    },
    .sizeClass = &_sizeClass
};
/*
static VruClusterInformationContainer_t vam_cic = {
    .vruClusterInformation = {
    }
};

static VruClusterOperationContainer_t vam_coc = {
    
};
*/
static int _options(MsgGenApp* app, int argc, char* argv[])
{
    // init VAM
    if (vam == NULL) {
        // register uppertester

        vam = cnew0(VAM_t);
        vam->header.messageId = MessageId_vam;
        vam->header.protocolVersion = 3;
        
        vam->vam.generationDeltaTime = 0;
        
        vam->vam.vamParameters.basicContainer.stationType = TrafficParticipantType_pedestrian;
        vam->vam.vamParameters.basicContainer.referencePosition.altitude.altitudeValue = AltitudeValue_unavailable;
        vam->vam.vamParameters.basicContainer.referencePosition.altitude.altitudeConfidence = AltitudeConfidence_unavailable;
        vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_unavailable;
        vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_unavailable;
        vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = Wgs84AngleValue_unavailable;

        memset(&vam->vam.vamParameters.vruHighFrequencyContainer, 0, sizeof(vam->vam.vamParameters.vruHighFrequencyContainer));
        vam->vam.vamParameters.vruHighFrequencyContainer.heading.value = Wgs84AngleValue_unavailable;
        vam->vam.vamParameters.vruHighFrequencyContainer.heading.confidence = Wgs84AngleConfidence_unavailable;
        vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedValue = SpeedValue_standstill;
        vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = SpeedConfidence_unavailable;
        vam->vam.vamParameters.vruHighFrequencyContainer.longitudinalAcceleration.longitudinalAccelerationValue = LongitudinalAccelerationValue_unavailable;
        vam->vam.vamParameters.vruHighFrequencyContainer.longitudinalAcceleration.longitudinalAccelerationConfidence = AccelerationConfidence_unavailable;
    }

    int rc = 0;
    if (argc == 0) {
        coptions_help(stderr, "VAM", 0, options, "");
    }
    else {
        rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
        if(rc < 0){
            return rc;
        }
    }

    vam->vam.vamParameters.basicContainer.stationType = _st_types[_o_stationType].tpType;

    vam_lfc.profileAndSubprofile.present = _st_types[_o_stationType].vruProfilePR;
    vam_lfc.profileAndSubprofile.choice.pedestrian = _st_types[_o_stationType].subProfile;

    return rc;
}

static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params)
{}

static GNCommonHeader _def_ch = {
    0x20, // nextHeader BTP-B
    0x50, // .headerType = SHB
    0x02, // .trafficClass
    0x80, // .flags
    0,    // .payload length
    1,    // .maxHopLimit
    0,    // .reserved2
};

static GNExtendedHeader _def_eh = {
    .shb = {
        .srcPosVector = {
            .gnAddr = {0},
            .timestamp = 0,
            .latitude = 0,
            .longitude = 0,
            .accAndSpeed = 0,
            .heading = 0
        },
        .reserved = 0
    }
};

static void _process (MsgGenApp * app, FitSec * e)
{
    if(_o_activated){
        MsgGenApp_Send(e, app); 
    }
}

static size_t _fill(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    size_t len;
    m->status = 0;

    if (_o_secured) {
        m->payloadType = FS_PAYLOAD_SIGNED;
        m->sign.ssp.aid = 638;
        memset(m->sign.ssp.sspData.opaque, 0, sizeof(m->sign.ssp.sspData.opaque));
        m->sign.ssp.sspLen = 1;
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
    uint32_t * bh = (uint32_t*)&((&eh->shb)[1]);
    bh[0] = 0x0000e207; // port 2018
    len = ((char*)&bh[1]) - m->payload;
    if (_o_btpA) {
        ch->nextHeader = 0x10;
    }

    vam->header.stationId = 0x10101010;//(unsigned long)FSCertificate_Digest(m->cert);
    if(m->position.latitude || m->position.longitude){
        vam->vam.vamParameters.basicContainer.referencePosition.latitude = m->position.latitude;
        vam->vam.vamParameters.basicContainer.referencePosition.longitude = m->position.longitude;
    }else{
        vam->vam.vamParameters.basicContainer.referencePosition.latitude = Latitude_unavailable;
        vam->vam.vamParameters.basicContainer.referencePosition.longitude = Longitude_unavailable;
    }

    eh->shb.srcPosVector.latitude = m->position.latitude;
    eh->shb.srcPosVector.longitude = m->position.longitude;
    eh->shb.srcPosVector.timestamp = (uint32_t)(m->generationTime / 1000);

    vam->vam.generationDeltaTime = eh->shb.srcPosVector.timestamp % 65536;

#ifdef USE_LIBGPS
    const struct gps_data_t * gps = get_gps_data();
    if(gps){
        if( gps->fix.mode >= 2 ){
            if(isfinite(gps->fix.epy) && isfinite(gps->fix.epx)){
                vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = abs(floor(gps->fix.epy * 100.0));
                if(vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength >= SemiAxisLength_outOfRange)
                    vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_outOfRange;
                vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = abs(floor(gps->fix.epx * 100.0));
                if(vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength >= SemiAxisLength_outOfRange)
                    vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_outOfRange;
                vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = 0;
                if(gps->fix.epx < gps->fix.epx){
                    long n = vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength;
                    vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = 
                        vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength;
                    vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = n;
                    vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = 90;
                }
            }else {
                vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_unavailable;
                vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_unavailable;
                vam->vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = Wgs84AngleValue_unavailable;
            }

            if(gps->set & SPEED_SET){
                /* speed */
                vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedValue = (long)floor(gps->fix.speed * 100.0);
                if(vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedValue > SpeedValue_outOfRange)
                    vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedValue = SpeedValue_outOfRange;
                if(isfinite(gps->fix.eps)){
                    vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = (long)floor(gps->fix.eps*100.0);
                    if(vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence > SpeedConfidence_outOfRange)
                        vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = SpeedConfidence_outOfRange;
                }else{
                    vam->vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = SpeedConfidence_unavailable;
                }
            }

            if(gps->set & TRACK_SET){
                /* heading */
                vam->vam.vamParameters.vruHighFrequencyContainer.heading.value = (long)floor(gps->fix.track*10);
                if(isfinite(gps->fix.epd)){
                    vam->vam.vamParameters.vruHighFrequencyContainer.heading.confidence = abs((long)floor(gps->fix.epd*10));
                    if(vam->vam.vamParameters.vruHighFrequencyContainer.heading.confidence > Wgs84AngleConfidence_outOfRange)
                        vam->vam.vamParameters.vruHighFrequencyContainer.heading.confidence = Wgs84AngleConfidence_outOfRange;
                }else{
                    vam->vam.vamParameters.vruHighFrequencyContainer.heading.confidence = Wgs84AngleConfidence_unavailable;
                }
            }
        }
    }
#endif

    asn_enc_rval_t rc = asn_encode_to_buffer(NULL, ATS_UNALIGNED_CANONICAL_PER, &asn_DEF_VAM, vam, m->payload + len, m->payloadSize - len);
    if (rc.encoded < 0) {
        fprintf(stderr, "%-2s SEND %s:\t ERROR: %zu at %s\n", FitSec_Name(e), "asn_encode", rc.encoded, rc.failed_type->name);
        len = 0;
    }
    else {
        char* p = m->payload + len + rc.encoded;
        m->payloadSize = p - m->payload;

        ch->plLength = cint16_hton((unsigned short)(rc.encoded + 4)); // plus BTP
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

static int  _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize)
{
    switch (m->code){
        case FS_UtVamTrigger:
            _o_activated = m->camState.state;
            break;
    }
    return 0;
}

