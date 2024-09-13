#ifdef USE_LIBGPS
#include <gps.h>
#include <math.h>
#endif

#include "msggen.h"
#include "cmem.h"
#include "copts.h"
#include "fsgpsd.h"

#include "payload/CAM.h"
#include "gn_types.h"
#include "../uppertester/uppertester.h"

static void cam_process (MsgGenApp * app, FitSec * e);
static int cam_options  (MsgGenApp* app, int argc, char* argv[]);
static size_t cam_fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static void cam_onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);
static void cam_receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort);

static int   cam_ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);

#define MAX_PATH_POINTS 23

static MsgGenApp _app = {
    "cam", 0, cam_process, cam_options, cam_fill, cam_onEvent, cam_receive, cam_ut_handler
};

__INITIALIZER__(initializer_cam) {
     MsgGenApp_Register(&_app);
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

static int _o_secured = 1;
static int _o_btpA = 0;
static int _o_activated = 1;
static float _o_rate = 10; // 10Hz
static float _o_cam_rate = 10; // 10Hz

static copt_t options[] = {
    { "T",  "cam-station-type",  COPT_STRENUM ,  _o_stationTypes, "Station Type [unknown]" },
    { "B",  "cam-btpA",          COPT_BOOL ,    &_o_btpA, "Use BTP A [use btpB by default]" },
    { "C",  "cam-stop",          COPT_IBOOL ,   &_o_activated, "Do not start CAM by default" },
    { NULL, "cam-no-sec",        COPT_IBOOL ,   &_o_secured, "Send non-secured cam" },
    { NULL, "no-sec",            COPT_IBOOL ,   &_o_secured, NULL },
    { "r",  "rate",              COPT_FLOAT|COPT_NOHELP,    &_o_rate, NULL },
    { NULL,  "cam-rate",         COPT_FLOAT,     &_o_cam_rate, "Set CAM sending rate [10Hz]" },

    { NULL, NULL, COPT_END, NULL, NULL }
};

static CAM_t _cam  = {
    .header = {
        .protocolVersion = 2,
        .messageId = MessageId_cam,
        .stationId = 0
    },
    .cam = {
        .generationDeltaTime = 0,
        .camParameters = {
	        .basicContainer = {
                .stationType = TrafficParticipantType_passengerCar,
                .referencePosition = {
                    .altitude = {
                        .altitudeValue = AltitudeValue_unavailable,
                        .altitudeConfidence = AltitudeConfidence_unavailable,
                    },
                    .positionConfidenceEllipse = {
                        .semiMajorAxisLength = SemiAxisLength_unavailable,
                        .semiMinorAxisLength = SemiAxisLength_unavailable,
                        .semiMajorAxisOrientation = Wgs84AngleValue_unavailable
                    }
                }
            },
            .highFrequencyContainer = {
                .present = HighFrequencyContainer_PR_basicVehicleContainerHighFrequency,
                .choice = {
                    .basicVehicleContainerHighFrequency = {
                        .heading = {
                            .headingValue = HeadingValue_unavailable,
                            .headingConfidence = HeadingConfidence_unavailable
                        },
                        .speed = {
                            .speedValue = SpeedValue_standstill,
                            .speedConfidence = SpeedConfidence_unavailable
                        },
                        .driveDirection = DriveDirection_unavailable,
                        .vehicleLength = {
                            .vehicleLengthValue = VehicleLengthValue_unavailable,
                            .vehicleLengthConfidenceIndication = VehicleLengthConfidenceIndication_unavailable
                        },
                        .vehicleWidth = VehicleWidth_unavailable,
                        .longitudinalAcceleration = {
                            .value = AccelerationValue_unavailable,
                            .confidence = AccelerationConfidence_unavailable
                        },
                        .curvature = {
                            .curvatureValue = CurvatureValue_unavailable,
                            .curvatureConfidence = CurvatureConfidence_unavailable
                        },
                        .curvatureCalculationMode = CurvatureCalculationMode_unavailable,
                        .yawRate = {
                            .yawRateValue = YawRateValue_unavailable,
                            .yawRateConfidence = YawRateConfidence_unavailable
                        }
                    }
                }
            }
        }
    }
};

typedef struct PathPointEx {
    PathPoint_t point;
    long deltaTimeValue;
    int idx;
}PathPointEx_t;

static PathPointEx_t _pathHistoryArrayData[MAX_PATH_POINTS] = {};
static PathPoint_t * _pathHistoryArray[MAX_PATH_POINTS] = {};

static void * asn_seq_move_up (void * asn_set_of_x) {
	asn_anonymous_set_ *as = _A_SET_FROM_VOID(asn_set_of_x);
	if(as->count < as->size) {
        as->array--;
        as->count ++;
        return as->array[0];
    }
    int i = as->size-1;
    void * p = as->array[i];
    for(;i>0;i--){
        as->array[i] = as->array[i-1];
    }
    as->array[0] = p;
    return p;
}
static void asn_seq_reset(void * asn_set_of_x) {
	asn_anonymous_set_ *as = _A_SET_FROM_VOID(asn_set_of_x);
    as->array += as->count;
    as->count = 0;
}

static uint8_t _exteriorLights_buf[] = {0};
static LowFrequencyContainer_t _lfc = {
    .present = LowFrequencyContainer_PR_basicVehicleContainerLowFrequency,
    .choice = {
        .basicVehicleContainerLowFrequency = {
            .vehicleRole = VehicleRole_default,
            .exteriorLights = {
                .buf = &_exteriorLights_buf[0],
                .size = 1,
                .bits_unused = 0
            },
            .pathHistory = {
                .list = {
                    &_pathHistoryArray[MAX_PATH_POINTS],
                    0, MAX_PATH_POINTS, NULL
                }
            }
        }
    }
};

static int cam_options(MsgGenApp* app, int argc, char* argv[])
{
    if (argc == 0) {
        fprintf(stderr, "\n");
        coptions_help(stderr, "CAM", 0, options, "");
        return 0;
    }

    int rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
    if (rc >= 0){

        if (options[0].vptr != _o_stationTypes) {
            _cam.cam.camParameters.basicContainer.stationType = copts_enum_value(options, 0, _o_stationTypes)-1;
        }

        if(_o_cam_rate != _o_rate ) _o_rate = _o_cam_rate;

        // init path points
        for(int i=0; i<(sizeof(_pathHistoryArray)/sizeof(_pathHistoryArray[0])); i++) {
            _pathHistoryArrayData[i].idx = i;
            _pathHistoryArrayData[i].point.pathDeltaTime = &_pathHistoryArrayData[i].deltaTimeValue;
            _pathHistoryArray[i] = &_pathHistoryArrayData[i].point;
        }

        if(_cam.cam.camParameters.basicContainer.stationType == TrafficParticipantType_roadSideUnit){
            _cam.cam.camParameters.highFrequencyContainer.present = HighFrequencyContainer_PR_rsuContainerHighFrequency;
            _cam.cam.camParameters.highFrequencyContainer.choice.rsuContainerHighFrequency.protectedCommunicationZonesRSU = NULL;
        }
    }
    return rc;
}
static void cam_onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params)
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

static void cam_process (MsgGenApp * app, FitSec * e)
{
    if(_o_activated){
        FSMessageInfo m = {0};
        GN_PrepareMessage(&m);
        uint64_t r = m.generationTime % (int)floor(1000000/_o_rate); 
        if(100000 > r){
            if(0 < cam_fill(app, e, &m)){
                GN_SendMessage(app, &m);
            }
        }
    }
}

typedef struct SentCamData {
    FSTime64 t;
    FS3DLocation p;
}SentCamData_t;

static SentCamData_t _last_LFC = {};

static size_t cam_fill(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    size_t len;
    m->status = 0;

    if (_o_secured) {
        m->payloadType = FS_PAYLOAD_SIGNED;
        m->sign.ssp.aid = 36;
        memset(m->sign.ssp.sspData.opaque, 0, sizeof(m->sign.ssp.sspData.opaque));
        m->sign.ssp.sspLen = 3;
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
    bh[0] = 0x0000d107; // port 2001
    len = ((char*)&bh[1]) - m->payload;
    if (_o_btpA) {
        ch->nextHeader = 0x10;
    }

    _cam.header.stationId = 0x10101010;//(unsigned long)FSCertificate_Digest(m->cert);
    _cam.cam.generationDeltaTime = (m->generationTime % 65536);
    if(m->position.latitude || m->position.longitude){
        _cam.cam.camParameters.basicContainer.referencePosition.latitude = m->position.latitude;
        _cam.cam.camParameters.basicContainer.referencePosition.longitude = m->position.longitude;
    }else{
        _cam.cam.camParameters.basicContainer.referencePosition.latitude = Latitude_unavailable;
        _cam.cam.camParameters.basicContainer.referencePosition.longitude = Longitude_unavailable;
    }

    eh->shb.srcPosVector.latitude = m->position.latitude;
    eh->shb.srcPosVector.longitude = m->position.longitude;
    eh->shb.srcPosVector.timestamp = (uint32_t)(m->generationTime / 1000);

#ifdef USE_LIBGPS
    FSGpsData gd;
    if(0 < libgps_get_data(0, &gd)){
        if(isfinite(gd.dx) && isfinite(gd.dx)){
            _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = abs(floor(gd.dy * 100.0));
            if(_cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength >= SemiAxisLength_outOfRange)
                _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_outOfRange;
            _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = abs(floor(gd.dx * 100.0));
            if(_cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength >= SemiAxisLength_outOfRange)
                _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_outOfRange;
            _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = 0;
            if(gd.dx < gd.dx){
                long n = _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength;
                _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = 
                    _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength;
                _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = n;
                _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = 90;
            }
        }else {
            _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisLength = SemiAxisLength_unavailable;
            _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMinorAxisLength = SemiAxisLength_unavailable;
            _cam.cam.camParameters.basicContainer.referencePosition.positionConfidenceEllipse.semiMajorAxisOrientation = Wgs84AngleValue_unavailable;
        }
        if(_cam.cam.camParameters.basicContainer.stationType != TrafficParticipantType_roadSideUnit){
            /* speed */
            _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue = gd.speed;
            if(_cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue > SpeedValue_outOfRange)
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue = SpeedValue_outOfRange;
            if(isfinite(gd.ds)){
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence = (long)floor(gd.ds*100.0);
                if(_cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence > SpeedConfidence_outOfRange)
                    _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence = SpeedConfidence_outOfRange;
            }else{
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence = SpeedConfidence_unavailable;
            }

            /* heading */
            _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingValue = gd.heading;
            if(isfinite(gd.dh)){
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingConfidence = abs((long)floor(gd.dh*10));
                if(_cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingConfidence > HeadingConfidence_outOfRange)
                    _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingConfidence = HeadingConfidence_outOfRange;
            }else{
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.heading.headingConfidence = HeadingConfidence_unavailable;
            }
        }
    }
#endif
    if( (m->generationTime - _last_LFC.t) > 500000){
        _cam.cam.camParameters.lowFrequencyContainer = &_lfc;
        if(_last_LFC.t){
            long deltaLatitude, deltaLongitude;
            deltaLatitude = m->position.latitude - _last_LFC.p.latitude;
            deltaLongitude = m->position.longitude - _last_LFC.p.longitude;
            if(deltaLatitude != 0 || deltaLongitude != 0){
                if(deltaLatitude < -131071 || deltaLatitude > 131071 || deltaLongitude < -131071 || deltaLongitude > 131071) {
                    asn_seq_reset(&_lfc.choice.basicVehicleContainerLowFrequency.pathHistory.list);
                }else{
                    PathPoint_t * p = asn_seq_move_up (&_lfc.choice.basicVehicleContainerLowFrequency.pathHistory.list);
                    (*p->pathDeltaTime) = m->generationTime - _last_LFC.t;
                    p->pathPosition.deltaLatitude = deltaLatitude;
                    p->pathPosition.deltaLongitude = deltaLongitude;
                    p->pathPosition.deltaAltitude = m->position.elevation - _last_LFC.p.elevation;
                }
            }
        }
        _last_LFC.t = m->generationTime;
        _last_LFC.p = m->position;
    } else {
        _cam.cam.camParameters.lowFrequencyContainer = NULL;
    }

    asn_enc_rval_t rc = asn_encode_to_buffer(NULL, ATS_UNALIGNED_CANONICAL_PER, &asn_DEF_CAM, &_cam, m->payload + len, m->payloadSize - len);
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

static void cam_receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort)
{
    
}

static int  cam_ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize)
{
    switch (m->code){
        case FS_UtCamTrigger:
            _o_activated = m->camState.state;
            break;

        case FS_UtCamTrigger_changeSpeed:
        {
            if(_cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue == SpeedValue_unavailable){
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue = 0;
            }
            _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedConfidence = 20; // 20cm/sec
            _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue += m->changeSpeed.speed;
            if(_cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue < 0)
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue = 0;
            else if (_cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue > 16382)
                _cam.cam.camParameters.highFrequencyContainer.choice.basicVehicleContainerHighFrequency.speed.speedValue = 16382;
            break;
        }
    }
    return 0;
}

