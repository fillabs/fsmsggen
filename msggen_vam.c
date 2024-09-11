#include "msggen.h"
#include "cmem.h"
#include "copts.h"
#include "clog.h"
#include "fitsec_time.h"

#include "payload/VAM.h"
#include "gn_types.h"
#include "../uppertester/uppertester.h"
#include "fsgpsd.h"
#include <math.h>


static void _process (MsgGenApp * app, FitSec * e);
static int _options  (MsgGenApp* app, int argc, char* argv[]);
static size_t _fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);
static void _receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort);

static int   _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);

static MsgGenApp _app = {
    "vam", 0, _process, _options, _fill, _onEvent, _receive, _ut_handler
};

__INITIALIZER__(initializer_vam) {
     MsgGenApp_Register(&_app);
}

static int _o_secured = 1;
static int _o_btpA = 0;
static int _o_activated = 0;
static int _o_stationType = 0;
static int _o_join = 0;
static int _o_leader = 0;
#define O_CLUSTER_DEFAULT 100 // by default clusterId 100
static long _o_cluster_id = 0;

static Shape_t _vam_cl_info_shape = {
    .present = Shape_PR_circular,
    .choice.circular = {
        .radius = 500 // 5 meters
    }
};

static const pchar_t * _o_vam_xer = NULL;
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
    { "T",  "station-type",      COPT_CALLBACK | COPT_NOHELP ,  _st_callback,   NULL },
    { NULL, "vam-station-type",  COPT_CALLBACK ,                _st_callback,   "Station Type [pedestrian by default]. 'list' to show all variants" },
    { NULL, "vam-join",          COPT_BOOL ,                    &_o_join,       "join the cluster" },   
    { NULL, "vam-leader",        COPT_BOOL ,                    &_o_leader,     "lead the cluster" },   
    { NULL, "vam-claster",       COPT_LONG ,                    &_o_cluster_id, "use this clusterId to join or lead" },
    { NULL, "vam-claster-radius",COPT_LONG ,                    &_vam_cl_info_shape.choice.circular.radius, "use this claster radius (in centimeters) [500 cm]" },
    { "B",  "btpA",              COPT_BOOL | COPT_NOHELP ,      &_o_btpA,       NULL },
    { NULL, "vam-btpA",          COPT_BOOL ,                    &_o_btpA,       "Use BTP A for VAM [use btpB by default]" },
    { "V",  "vam-start",         COPT_BOOL ,                    &_o_activated,  "Start sending VAM by default"},
    { NULL, "vam-no-sec",        COPT_IBOOL ,                   &_o_secured,    "Send non-secured cam" },
    { NULL, "no-sec",            COPT_IBOOL | COPT_NOHELP,      &_o_secured,    NULL },
    { NULL, "vam-template",      COPT_PATH ,                    &_o_vam_xer,    "Load this VAM template" },
    { NULL, NULL, COPT_END, NULL, NULL }
};

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

static VAM_t _vam = {
    .header = {
        .protocolVersion = 3,
        .messageId = MessageId_vam,
        .stationId = 0x10101010
    },
    .vam = {
        .generationDeltaTime = 0,
        .vamParameters = {
            .basicContainer = {
                .stationType = TrafficParticipantType_pedestrian,
                .referencePosition = {
                    .latitude = Latitude_unavailable,
                    .longitude = Longitude_unavailable,
                    .positionConfidenceEllipse = {
                        .semiMajorAxisLength = SemiAxisLength_unavailable,
                        .semiMinorAxisLength = SemiAxisLength_unavailable,
                        .semiMajorAxisOrientation = Wgs84AngleValue_unavailable
                    },
                    .altitude = {
                        .altitudeValue = AltitudeValue_unavailable,
                        .altitudeConfidence = AltitudeConfidence_unavailable
                    }
                }

            },
            .vruHighFrequencyContainer = {
	            .heading = {
                    .value = Wgs84AngleValue_unavailable,
                    .confidence = Wgs84AngleConfidence_unavailable
                },
                .speed = {
                    .speedValue = SpeedValue_standstill,
                    .speedConfidence = SpeedConfidence_unavailable
                },
	            .longitudinalAcceleration = {
                    .longitudinalAccelerationValue = LongitudinalAccelerationValue_unavailable,
                    .longitudinalAccelerationConfidence = AccelerationConfidence_unavailable
                }
            }
        }
    }
};

static ClusterJoinInfo_t _vam_cl_join_info = {
    .joinTime = 3
};
static VruClusterOperationContainer_t _vam_cl_join_container = {
    .clusterJoinInfo = &_vam_cl_join_info
};
static VruClusterInformationContainer_t _vam_cl_info_container = {
    .vruClusterInformation = {
        .clusterBoundingBoxShape = &_vam_cl_info_shape,
        .clusterId = &_o_cluster_id,
        .clusterCardinalitySize = 1
    }
};

/*
static asn_TYPE_operation_t _op_DebugInteger;
static asn_enc_rval_t _op_DebugInteger_uper_encoder(const struct asn_TYPE_descriptor_s *type_descriptor,
                                                 const asn_per_constraints_t *constraints, const void *struct_ptr,
                                                 asn_per_outp_t *per_output)
{
    return asn_OP_NativeInteger.uper_encoder(type_descriptor, constraints, struct_ptr, per_output);
}
*/
static int _options(MsgGenApp* app, int argc, char* argv[])
{
    // init VAM

    if (argc == 0) {
        fprintf(stderr, "\n");
        coptions_help(stderr, "VAM", 0, options, "");
        return 0;
    }
    int rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
    if(rc >= 0){
        if(_o_vam_xer){
            // load from template
            char * ebuf = NULL;
            char * buf = cstraload(&ebuf, _o_vam_xer);
            if(buf == NULL){
                mclog_fatal(VAM, "%s: no XER template file found", _o_vam_xer);
                return -1;
            }

            asn_dec_rval_t rc_d = asn_decode(NULL, ATS_BASIC_XER, &asn_DEF_VAM, (void**)&_vam, buf, ebuf - buf);
            if(rc_d.code != RC_OK){
                mclog_fatal(VAM, "%s: error in XER template at pos %n", _o_vam_xer, rc_d.consumed);
                return -1;
            }
        }else{
            _vam.vam.vamParameters.vruLowFrequencyContainer = &vam_lfc;
            _vam.vam.vamParameters.basicContainer.stationType = _st_types[_o_stationType].tpType;
            vam_lfc.profileAndSubprofile.present = _st_types[_o_stationType].vruProfilePR;
            vam_lfc.profileAndSubprofile.choice.pedestrian = _st_types[_o_stationType].subProfile;
        }
        if(_o_join){
            if(_o_leader){
                mclog_fatal(VAM, "can not lead and join cluster at the same time");
                return -1;
            }
        }else{
            if(_o_cluster_id){
                _o_leader = 1;
            }
            if(_o_leader){
                if(_o_cluster_id == 0){
                    _o_cluster_id = O_CLUSTER_DEFAULT;
                }
                _vam_cl_info_container.vruClusterInformation.clusterId = &_o_cluster_id;
                _vam.vam.vamParameters.vruClusterInformationContainer = &_vam_cl_info_container;
            }
        }
/*    
        _op_DebugInteger = *asn_DEF_Wgs84AngleValue.op;
        asn_DEF_Wgs84AngleValue.op = &_op_DebugInteger;
        _op_DebugInteger.uper_encoder = _op_DebugInteger_uper_encoder;
*/
    }
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

FSTime64 _stopSendingTime = 0;

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

    if(m->position.latitude || m->position.longitude){
        _vam.vam.vamParameters.basicContainer.referencePosition.latitude = m->position.latitude;
        _vam.vam.vamParameters.basicContainer.referencePosition.longitude = m->position.longitude;
    }else{
        _vam.vam.vamParameters.basicContainer.referencePosition.latitude = Latitude_unavailable;
        _vam.vam.vamParameters.basicContainer.referencePosition.longitude = Longitude_unavailable;
    }

    eh->shb.srcPosVector.latitude = m->position.latitude;
    eh->shb.srcPosVector.longitude = m->position.longitude;
    eh->shb.srcPosVector.timestamp = (uint32_t)(m->generationTime / 1000);

    _vam.vam.generationDeltaTime = eh->shb.srcPosVector.timestamp % 65536;

#ifdef USE_LIBGPS
    FSGpsData gd;
    if(libgps_get_data(0, &gd) > 0){
        if(isfinite(gd.dy) && isfinite(gd.dx)){
            _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = abs(floor(gd.dy * 100.0));
            if(_vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength >= SemiAxisLength_outOfRange)
                _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_outOfRange;
            _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = abs(floor(gd.dx * 100.0));
            if(_vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength >= SemiAxisLength_outOfRange)
                _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_outOfRange;
            _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = 0;
            if(gd.dx < gd.dx){
                long n = _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength;
                _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = 
                    _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength;
                _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = n;
                _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = 90;
            }
        }else {
            _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_unavailable;
            _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_unavailable;
            _vam.vam.vamParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = Wgs84AngleValue_unavailable;
        }

        /* speed */
        _vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedValue = gd.speed;
        if(_vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedValue > SpeedValue_outOfRange)
            _vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedValue = SpeedValue_outOfRange;
        if(isfinite(gd.ds)){
            _vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = (long)floor(gd.ds*100.0);
            if(_vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence > SpeedConfidence_outOfRange)
                _vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = SpeedConfidence_outOfRange;
        }else{
            _vam.vam.vamParameters.vruHighFrequencyContainer.speed.speedConfidence = SpeedConfidence_unavailable;
        }

        /* heading */
        _vam.vam.vamParameters.vruHighFrequencyContainer.heading.value = gd.heading;
        if(isfinite(gd.dh)){
            _vam.vam.vamParameters.vruHighFrequencyContainer.heading.confidence = abs((long)floor(gd.dh*10));
            if(_vam.vam.vamParameters.vruHighFrequencyContainer.heading.confidence > Wgs84AngleConfidence_outOfRange)
                _vam.vam.vamParameters.vruHighFrequencyContainer.heading.confidence = Wgs84AngleConfidence_outOfRange;
        }else{
            _vam.vam.vamParameters.vruHighFrequencyContainer.heading.confidence = Wgs84AngleConfidence_unavailable;
        }
    }
#endif
    if(_o_join) {
        if(_o_cluster_id) {
            _vam.vam.vamParameters.vruClusterOperationContainer = &_vam_cl_join_container;
            if(_vam_cl_join_info.clusterId != _o_cluster_id){
                _vam_cl_join_info.clusterId = _o_cluster_id;
                _stopSendingTime = m->generationTime + (_vam_cl_join_info.joinTime * 256000);
            }else{
                if(m->generationTime > _stopSendingTime){
                    return 0; // send nothing
                }
            }
        }
    }

    asn_enc_rval_t rc = asn_encode_to_buffer(NULL, ATS_UNALIGNED_CANONICAL_PER, &asn_DEF_VAM, &_vam, m->payload + len, m->payloadSize - len);
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

static void _receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort)
{
    if(btpPort == 2018){
        mclog_info(VRU, "%s VAM received",
            stritstime64(m->generationTime) 
        );
        if(_o_join){
            if(_o_cluster_id == 0){
                // decode VAM
                VAM_t rvam = {}, *prvam = &rvam;
                
                asn_dec_rval_t rc_d = asn_decode(NULL, ATS_UNALIGNED_BASIC_PER, &asn_DEF_VAM, (void**)&prvam, m->payload, m->payloadSize);
                if(rc_d.code == RC_OK){
                    if(rvam.vam.vamParameters.vruClusterInformationContainer){
                        if(rvam.vam.vamParameters.vruClusterInformationContainer->vruClusterInformation.clusterId){
                            _o_cluster_id = *rvam.vam.vamParameters.vruClusterInformationContainer->vruClusterInformation.clusterId;
                        }
                    }
                    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_VAM, &rvam);
                }
            }
        }
    }
}


static int  _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize)
{
    switch (m->code){
        case FS_UtVamTrigger:
            _o_activated = m->camState.state;
            break;
        case FS_UtVamJoin:
            _o_join = 1;
            _o_leader = 0;
            _o_cluster_id = m->vamCluster.clasterId;
            _vam.vam.vamParameters.vruClusterInformationContainer = NULL;
            break;
        case FS_UtVamLeader:
            _o_join = 0;
            _o_leader = 1;
            _vam.vam.vamParameters.vruClusterOperationContainer = NULL;
            _vam.vam.vamParameters.vruClusterInformationContainer = &_vam_cl_info_container;
            break;
    }
    return 0;
}

