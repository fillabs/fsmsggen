#include <math.h>

#include "msggen.h"
#include "cmem.h"
#include "copts.h"
#include "clog.h"
#include "fitsec_time.h"

#include "payload/CollectivePerceptionMessage.h"
#include "gn_types.h"
#include "../uppertester/uppertester.h"
#ifdef USE_LIBGPS
#include "fsgpsd.h"
#endif

static void _process (MsgGenApp * app, FitSec * e);
static int _options  (MsgGenApp* app, int argc, char* argv[]);
static size_t _fill  (MsgGenApp* app, FitSec * e, FSMessageInfo* m);
static void _onEvent (MsgGenApp * app, FitSec* e, void* user, FSEventId event, const FSEventParam* params);
static void _receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort);

static int   _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize);

static MsgGenApp _app = {
    "cpm", 0, _process, _options, _fill, _onEvent, _receive, _ut_handler
};

__INITIALIZER__(initializer_cpm) {
     MsgGenApp_Register(&_app);
}

#ifndef NO_SECURITY
static int _o_secured = 1;
#endif
static int _o_stationId = DEFAULT_STATION_ID;
static int _o_rate = 1; // 1Hz
static const char * _o_export = NULL;

static int  _o_cpm_new(const copt_t * opt, const char * option, const copt_value_t * value);
static int  _o_cpm_xer(const copt_t * opt, const char * option, const copt_value_t * value);
static int  _o_cpm_object(const copt_t * opt, const char * option, const copt_value_t * value);
static int  _o_cpm_position(const copt_t * opt, const char * option, const copt_value_t * value);

static copt_t options[] = {
    { NULL, "cpm-new",           COPT_BOOL|COPT_CALLBACK,   &_o_cpm_new,             "Add new default CPM message to the message set"},
    { NULL, "cpm-xer",           COPT_STR|COPT_CALLBACK,    &_o_cpm_xer,      "Set the path to the main CPM XER template"},
    { NULL, "cpm-obj",           COPT_STR|COPT_CALLBACK,    &_o_cpm_object,   "Add CPM object = N:<objtype|path to XER of PerceivedObject>[:position]"},
    { NULL, "cpm-pos",           COPT_STR|COPT_CALLBACK,    &_o_cpm_position, "Set CPM object position = N:lat:lon"
#ifdef USE_LIBGPS
                                                                                                                     " | gpsd url)"
#endif    
    },
    { NULL, "cpm-rate",          COPT_INT ,                 &_o_rate,         "CPM sending rate [1Hz]" },
    { NULL, "cpm-export-template",COPT_STR ,                 &_o_export,       "Export CPM template" },
    
#ifndef NO_SECURITY
    { NULL, "cpm-no-sec",      COPT_IBOOL ,               &_o_secured,      "Send non-secured cam"   },
    { NULL, "no-sec",          COPT_IBOOL|COPT_NOHELP,    &_o_secured,      NULL },
#endif    
    { "I",  "station-id",      COPT_UINT|COPT_NOHELP,     &_o_stationId, NULL },
    { NULL, NULL, COPT_END, NULL, NULL },
    { "r", "rate",             COPT_INT|COPT_NOHELP ,     &_o_rate, NULL}
};

static CollectivePerceptionMessage_t * _cpms [10] = {};
static size_t _cpms_count = 0;

/*
static Identifier1B_t __sensorIds[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};

static SequenceOfIdentifier1B_t _sensorIds = {
    .list = {
        .array = {&__sensorIds[1]}, .count = 1, .size  = 1
    }
};

static ObjectDimension_t _objectDimensionZ_pedestrian = {20, 1};
static ObjectDimension_t _objectDimensionX_pedestrian = {5,  1};
static ObjectDimension_t _objectDimensionY_pedestrian = {5,  1};
static ObjectPerceptionQuality_t _objectPerceptionQuality = 10;


static ObjectClassDescription_t _classification_pedestrian = {
    .list = {
        .array = {}
    }
}
*/

enum {
    cpm_objectClass_pedestrian_90,
    cpm_objectClass_pedestrian_10,
    cpm_objectClass_bicycle_90,
    cpm_objectClass_bicycle_10,
    cpm_objectClass_roadworker_90,
    cpm_objectClass_car_90,
    cpm_objectClass_car_10,
    cpm_objectClass_track_90,
    cpm_objectClass_bus_90,
    cpm_objectClass_moto_90,
};


static ObjectClassWithConfidence_t _objectClassWithConfidence [] = {
    [cpm_objectClass_pedestrian_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vruSubClass,
            .choice = {
                .vruSubClass = {
                    .present = VruProfileAndSubprofile_PR_pedestrian,
                    .choice = {
                        .pedestrian = VruSubProfilePedestrian_ordinary_pedestrian
                    }
                }
            }
        },
        .confidence = 90
    },
    [cpm_objectClass_pedestrian_10] = {
        .objectClass = {
            .present = ObjectClass_PR_vruSubClass,
            .choice = {
                .vruSubClass = {
                    .present = VruProfileAndSubprofile_PR_pedestrian,
                    .choice = {
                        .pedestrian = VruSubProfilePedestrian_ordinary_pedestrian
                    }
                }
            }
        },
        .confidence = 10
    },
    [cpm_objectClass_bicycle_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vruSubClass,
            .choice = {
                .vruSubClass = {
                    .present = VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle,
                    .choice = {
                        .bicyclistAndLightVruVehicle = VruSubProfileBicyclist_bicyclist
                    }
                }
            }
        },
        .confidence = 90
    },
    [cpm_objectClass_bicycle_10] = {
        .objectClass = {
            .present = ObjectClass_PR_vruSubClass,
            .choice = {
                .vruSubClass = {
                    .present = VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle,
                    .choice = {
                        .bicyclistAndLightVruVehicle = VruSubProfileBicyclist_bicyclist
                    }
                }
            }
        },
        .confidence = 10
    },
    [cpm_objectClass_roadworker_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vruSubClass,
            .choice = {
                .vruSubClass = {
                    .present = VruProfileAndSubprofile_PR_pedestrian,
                    .choice = {
                        .pedestrian = VruSubProfilePedestrian_road_worker
                    }
                }
            }
        },
        .confidence = 90
    },
    [cpm_objectClass_car_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vehicleSubClass,
            .choice = {
                .vehicleSubClass = TrafficParticipantType_passengerCar
            }
        },
        .confidence = 90
    },
    [cpm_objectClass_car_10] = {
        .objectClass = {
            .present = ObjectClass_PR_vehicleSubClass,
            .choice = {
                .vehicleSubClass = TrafficParticipantType_passengerCar
            }
        },
        .confidence = 10
    },
    [cpm_objectClass_track_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vehicleSubClass,
            .choice = {
                .vehicleSubClass = TrafficParticipantType_lightTruck
            }
        },
        .confidence = 90
    },
    [cpm_objectClass_bus_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vehicleSubClass,
            .choice = {
                .vehicleSubClass = TrafficParticipantType_bus
            }
        },
        .confidence = 90
    },
    [cpm_objectClass_moto_90] = {
        .objectClass = {
            .present = ObjectClass_PR_vehicleSubClass,
            .choice = {
                .vehicleSubClass = TrafficParticipantType_motorcycle
            }
        },
        .confidence = 90
    },
};
static ObjectClassWithConfidence_t * _classifications[] = {
    //pedestrian
    &_objectClassWithConfidence[cpm_objectClass_pedestrian_90], // pedestrian-90%
    &_objectClassWithConfidence[cpm_objectClass_bicycle_10], // bicycle - 10%
    //roadworker
    &_objectClassWithConfidence[cpm_objectClass_roadworker_90], // roadworker-90%
    &_objectClassWithConfidence[cpm_objectClass_pedestrian_10], // pedestrian-10%
    //bicycle
    &_objectClassWithConfidence[cpm_objectClass_bicycle_90], // bicycle-90%
    &_objectClassWithConfidence[cpm_objectClass_pedestrian_10], // pedestrian-10%
    //moto
    &_objectClassWithConfidence[cpm_objectClass_moto_90], // moto-90%
    &_objectClassWithConfidence[cpm_objectClass_bicycle_10], // bicycle-10%
    //car
    &_objectClassWithConfidence[cpm_objectClass_car_90], // car-90%
    &_objectClassWithConfidence[cpm_objectClass_bicycle_10], // bicycle-10%
    //track
    &_objectClassWithConfidence[cpm_objectClass_track_90], // track-90%
    &_objectClassWithConfidence[cpm_objectClass_car_10], // car-10%
    //bus
    &_objectClassWithConfidence[cpm_objectClass_bus_90], // bus-90%
    &_objectClassWithConfidence[cpm_objectClass_car_10], // car-10%
};


static struct {
    const char * name;
    ObjectDimension_t sizeX, sizeY, sizeZ;
    ObjectPerceptionQuality_t quality;
    ObjectClassDescription_t description;
} _objClasses[] = {
    {
        .name = "pedestrian",
        .sizeX={ 6, 1},  // 60+-10 cm
        .sizeY={ 6, 1}, // 60+-10 cm
        .sizeZ={ 20, 1}, // 200+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[0],
                .count=2
            }
        }
    },{
        .name = "roadworker",
        .sizeX={ 6, 1},  // 60+-10 cm
        .sizeY={ 6, 1}, // 60+-10 cm
        .sizeZ={ 20, 1}, // 200+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[2],
                .count=2
            }
        }
    },
    {
        .name = "bicycle",
        .sizeX={ 20, 1}, // 200+-10 cm
        .sizeY={ 8, 1},  // 80+-10 cm
        .sizeZ={ 20, 1}, // 200+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[4],
                .count=2
            }
        }
    },
    {
        .name = "moto",
        .sizeX={ 20, 1}, // 200+-10 cm
        .sizeY={ 8, 1},  // 80+-10 cm
        .sizeZ={ 20, 1}, // 200+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[6],
                .count=2
            }
        }
    },
    {
        .name = "car",
        .sizeX={ 40, 1}, // 400+-10 cm
        .sizeY={ 30, 1}, // 300+-10 cm
        .sizeZ={ 20, 1}, // 200+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[8],
                .count=2
            }
        }
    },
    {
        .name = "track",
        .sizeX={ 100, 5}, // 10m+-50 cm
        .sizeY={ 50, 1}, // 5m+-10 cm
        .sizeZ={ 30, 1}, // 3m+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[10],
                .count=2
            }
        }
    },
    {
        .name = "bus",
        .sizeX={ 100, 5}, // 10m+-50 cm
        .sizeY={ 50, 1}, // 5m+-10 cm
        .sizeZ={ 30, 1}, // 3m+-10 cm
        .quality = 10,
        .description = {
            .list = {
                .array = &_classifications[12],
                .count=2
            }
        }
    }
};

int FS3DPositionFromString(FS3DLocation * pos, const char * str);
static CollectivePerceptionMessage_t * _cpm_create_default();
static void                            _cpm_po_update_position(PerceivedObject_t *po, const FS3DLocation * base);
static void                            _cpm_po_update_sensors(PerceivedObject_t * po, CollectivePerceptionMessage_t * cpm);
static int                             _cpm_po_set_position(PerceivedObject_t *po, char * pos);
static PerceivedObject_t *             _cpm_po_new(Identifier2B_t id);
static SensorInformation_t *           _cpm_add_sensor(CollectivePerceptionMessage_t * cpm, Identifier1B_t sensorId, SensorType_t type);
static void                            _cpm_add_object(CollectivePerceptionMessage_t * cpm, PerceivedObject_t * po);

static int  _o_cpm_new(const copt_t * opt, const char * option, const copt_value_t * value)
{
    _cpms[_cpms_count++] = _cpm_create_default();
    return 0;
}

static int _o_cpm_xer(const copt_t * opt, const char * option, const copt_value_t * value)
{
    // load from template
    char * buf, * ebuf = NULL;
    ebuf = cstraload(&buf, value->v_str);
    if(ebuf == NULL){
        mclog_fatal(CPM, "%s: no CPM XER template file found", value->v_str);
        return -1;
    }

    CollectivePerceptionMessage_t * cpm = NULL;
    asn_dec_rval_t rc_d = asn_decode(NULL, ATS_BASIC_XER, &asn_DEF_CollectivePerceptionMessage, (void**)&cpm, buf, ebuf - buf);
    if(rc_d.code != RC_OK){
        mclog_fatal(CPM, "%s: error in XER template at pos %n", value->v_str, rc_d.consumed);
        return -1;
    }
    _cpms[_cpms_count++] = cpm;
    free(buf);
    return 0;
}

WrappedCpmContainer_t * _cpm_container_of(CollectivePerceptionMessage_t * cpm, CpmContainerId_t id){
    for(int i=0; i< cpm->payload.cpmContainers.list.count; i++){
        if(cpm->payload.cpmContainers.list.array[i]->containerId == id){
            return cpm->payload.cpmContainers.list.array[i];
        }
    }
    return NULL;
}

static void free_WrappedCpmContainer(WrappedCpmContainer_t * wc) {
    SEQUENCE_free(&asn_DEF_WrappedCpmContainer, wc, ASFM_FREE_EVERYTHING);
}
static void free_SensorInformation(SensorInformation_t * si){
    SEQUENCE_free(&asn_DEF_SensorInformation, si, ASFM_FREE_EVERYTHING);
}
static void free_PerceivedObject(PerceivedObject_t * po){
    SEQUENCE_free(&asn_DEF_PerceivedObject, po, ASFM_FREE_EVERYTHING);
}

static CollectivePerceptionMessage_t * _cpm_create_default() {
    CollectivePerceptionMessage_t * cpm = cnew0(CollectivePerceptionMessage_t);
    cpm->payload.cpmContainers.list.free = free_WrappedCpmContainer;
    cpm->header.protocolVersion = 3;
    cpm->header.messageId = MessageId_cpm;

    asn_ulong2INTEGER(&cpm->payload.managementContainer.referenceTime, 0);

    // add default sensor
    WrappedCpmContainer_t * wc = cnew0(WrappedCpmContainer_t);
    ASN_SEQUENCE_ADD(&cpm->payload.cpmContainers.list, wc);
    wc->containerId = CpmContainerId_sensorInformationContainer;
    wc->containerData.present = WrappedCpmContainer__containerData_PR_SensorInformationContainer;
    wc->containerData.choice.SensorInformationContainer.list.free = free_SensorInformation;
    SensorInformation_t * si = cnew0(SensorInformation_t);
    ASN_SEQUENCE_ADD(&wc->containerData.choice.SensorInformationContainer.list, si);
    si->sensorId = 100;

    //add RSU container
    wc = cnew0(WrappedCpmContainer_t);
    ASN_SEQUENCE_ADD(&cpm->payload.cpmContainers.list, wc);
    wc->containerId = CpmContainerId_originatingRsuContainer;
    wc->containerData.present = WrappedCpmContainer__containerData_PR_OriginatingRsuContainer;
    return cpm;
}

static SensorInformation_t * _cpm_add_sensor(CollectivePerceptionMessage_t * cpm, Identifier1B_t sensorId, SensorType_t type){
    WrappedCpmContainer_t * wc = _cpm_container_of(cpm, CpmContainerId_sensorInformationContainer);
    SensorInformation_t * si;
    if(wc == NULL){
        // add default sensor
        wc = cnew0(WrappedCpmContainer_t);
        wc->containerId = CpmContainerId_sensorInformationContainer;
        wc->containerData.present = WrappedCpmContainer__containerData_PR_SensorInformationContainer;
        wc->containerData.choice.SensorInformationContainer.list.free = free_SensorInformation;
        ASN_SEQUENCE_ADD(&cpm->payload.cpmContainers.list, wc);
    }else{
        for(int i=0; i<wc->containerData.choice.SensorInformationContainer.list.count; i++){
            si = wc->containerData.choice.SensorInformationContainer.list.array[i];
            if(si->sensorId == sensorId){
                return si;
            }
        }
    }

    si = cnew0(SensorInformation_t);
    ASN_SEQUENCE_ADD(&wc->containerData.choice.SensorInformationContainer.list, si);
    si->sensorId = 100;
    si->sensorType = type;
    return si;
}

static PerceivedObject_t * _cpm_po_new(Identifier2B_t id) {
    PerceivedObject_t * po = cnew0(PerceivedObject_t);
    if(id){
        po->objectId = cnew0(Identifier2B_t);
        *po->objectId = id;
    }
    po->position.xCoordinate.confidence = CoordinateConfidence_unavailable;
    po->position.yCoordinate.confidence = CoordinateConfidence_unavailable;
    return po;
}
static void _cpm_po_update_sensors(PerceivedObject_t * po, CollectivePerceptionMessage_t * cpm)
{
    if(po->sensorIdList == NULL){
        po->sensorIdList = cnew0(SequenceOfIdentifier1B_t);
        po->sensorIdList->list.free = (void (*)(Identifier1B_t *))free;
    }
    if(po->sensorIdList->list.count == 0){
        SensorInformation_t * si;
        // associate object with single existing sensor if no sensor id exist in the object data
        // search for sensors in the cpm
        WrappedCpmContainer_t * wc = _cpm_container_of(_cpms[_cpms_count-1], CpmContainerId_sensorInformationContainer);
        if(wc == NULL || wc->containerData.choice.SensorInformationContainer.list.count == 0){
            si = _cpm_add_sensor(_cpms[_cpms_count-1], 100, SensorType_undefined);
        }else{
            // get the 1st sensor
            si = wc->containerData.choice.SensorInformationContainer.list.array[0];
        }
        Identifier1B_t * sensorId = malloc(sizeof(Identifier1B_t));
        *sensorId = si->sensorId;
        ASN_SEQUENCE_ADD(&po->sensorIdList->list, sensorId);
    }
}

static void _cpm_add_object(CollectivePerceptionMessage_t * cpm, PerceivedObject_t * po)
{
    WrappedCpmContainer_t * wc = _cpm_container_of(cpm, CpmContainerId_perceivedObjectContainer);
    if(wc == NULL){
        wc = cnew0(WrappedCpmContainer_t);
        wc->containerId = CpmContainerId_perceivedObjectContainer;
        wc->containerData.present = WrappedCpmContainer__containerData_PR_PerceivedObjectContainer;
        wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.free = free_PerceivedObject;
        ASN_SEQUENCE_ADD(&cpm->payload.cpmContainers.list, wc); // add to the last CPM
    }
    ASN_SEQUENCE_ADD(&wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list, po);
    _cpm_po_update_sensors(po, cpm);

}

static int _lastObjID = 500;
static int  _o_cpm_object(const copt_t * opt, const char * option, const copt_value_t * value)
{
    PerceivedObject_t * po = NULL;

    // check for XER
    char * p=NULL, *pos=NULL;
    int id = strtoul(value->v_str, &p, 10);
    if(p && ':' == *p){
        p++;
    }else{
        id = _lastObjID++;
        p = value->v_str;
    }
    pos = strchr(p, ':');
    if(pos){
        *pos++ = 0;
    }
    for(int i=0; i<carraysize(_objClasses); i++){
      if(cstrequal(_objClasses[i].name, p)){
        po = _cpm_po_new(id);
        po->objectDimensionX = &_objClasses[i].sizeX;
        po->objectDimensionY = &_objClasses[i].sizeY;
        po->objectDimensionZ = &_objClasses[i].sizeZ;
        po->classification = &_objClasses[i].description;
        break;
      }
    }
    if(po == NULL){
        char *xer = NULL;
        p = cstraload(&xer, p);
        if(p > xer){
            asn_dec_rval_t rc_d = asn_decode(NULL, ATS_BASIC_XER, &asn_DEF_PerceivedObject, (void**)&po, xer, p - xer);
            free(xer);
            if(rc_d.code != RC_OK){
                mclog_fatal(CPM, "%s: error in PerceivedObjet XER template at pos %n", value->v_str, rc_d.consumed);
                return -1;
            }
        }else{
            fprintf(stderr, "%s: CPM object XER template is not found or invalid object type\n", value->v_str);
            fprintf(stderr, "Use one of the following types: pedestrian, roadworker, bicycle, moto, car, track, bus\n"
                            "or set path to a PerceivedObject XER representation\n");

            return -1;
        }
    }
    if(pos && 0 > _cpm_po_set_position(po, pos)){
        return -1;
    }

    if(_cpms_count == 0){
        // init default CPM
        _cpms[_cpms_count++] = _cpm_create_default();
    }

    // allways add PO in the last created CPM
    _cpm_add_object(_cpms[_cpms_count-1], po);
    return 0;
}

typedef struct POPositionTrack POPositionTrack;
struct POPositionTrack{
    POPositionTrack * next;
    PerceivedObject_t *po;
    const char* url;
    int ch;
    FS3DLocation  pos;
    int relative;
};
static POPositionTrack * _positionTracks = NULL;

static void _cpm_po_update_position(PerceivedObject_t *po, const FS3DLocation * base){
    POPositionTrack * tr = _positionTracks;
    for(;tr; tr=tr->next){
        if(po == tr->po){
            po->position.yCoordinate.confidence = CoordinateConfidence_unavailable;
            po->position.xCoordinate.confidence = CoordinateConfidence_unavailable;
            po->position.xCoordinate.value = tr->pos.longitude - base->longitude;
            po->position.yCoordinate.value = tr->pos.latitude - base->latitude;
#ifdef USE_LIBGPS
            FSGpsData g;
            if(tr->ch >= 0){
                if(0 < libgps_get_data(tr->ch, &g)){
                    if(isfinite(g.dx) && isfinite(g.dy)){
                        po->position.yCoordinate.confidence = abs(floor(g.dy * 10.0));
                        po->position.xCoordinate.confidence = abs(floor(g.dx * 10.0));
                    }
                    po->position.xCoordinate.value = g.position.longitude - base->longitude;
                    po->position.yCoordinate.value = g.position.latitude - base->latitude;
                }
            }else
#endif
            {
                if(tr->relative){
                    po->position.xCoordinate.value = tr->pos.longitude;
                    po->position.yCoordinate.value = tr->pos.latitude;
                }
            }
            if(po->position.xCoordinate.value > CartesianCoordinateLarge_positiveOutOfRange) po->position.xCoordinate.value = CartesianCoordinateLarge_positiveOutOfRange;
            if(po->position.xCoordinate.value < CartesianCoordinateLarge_negativeOutOfRange) po->position.xCoordinate.value = CartesianCoordinateLarge_negativeOutOfRange;
        
            if(po->position.yCoordinate.value > CartesianCoordinateLarge_positiveOutOfRange) po->position.xCoordinate.value = CartesianCoordinateLarge_positiveOutOfRange;
            if(po->position.yCoordinate.value < CartesianCoordinateLarge_negativeOutOfRange) po->position.xCoordinate.value = CartesianCoordinateLarge_negativeOutOfRange;
            break;
        }
    }
}

static int _cpm_po_set_position(PerceivedObject_t *po, char * pos){
    POPositionTrack * tr;
#ifdef USE_LIBGPS
    if(cstrnequal("gpsd://", pos, 7)){
        int ch;
        tr = _positionTracks;
        while(tr){
            if(cstrequal(tr->url, pos)){
                if(po != tr->po){
                    ch = tr->ch;
                    goto add_tr;
                }
                return 0;
            }
            tr = tr->next;
        }
        ch = libgps_start(pos+7);
        if(ch < 0){
            return -1;
        }
add_tr:
        tr = cnew(POPositionTrack);
        tr->ch = ch;
    }else
#endif
    {
        tr = cnew0(POPositionTrack);
        tr->ch = -1;
        if((*pos == 'R' || *pos == 'r') && pos[1] == ':' ){
            pos += 2;
            tr->relative = 1;
        }
        if(!FS3DPositionFromString(&tr->pos, pos)){
            fprintf(stderr, "%s: Position error", pos);
            free(tr);
            return -1;
        }
    }
    tr->po = po;
    tr->url = pos;
    tr->next = _positionTracks;
    _positionTracks = tr;
    return 0;
}

static int  _o_cpm_position(const copt_t * opt, const char * option, const copt_value_t * value)
{
    char * e = NULL;
    int id = strtoul(value->v_str, &e, 10);
    if(id == 0 || e <= value->v_str || *e != ':'){
        fprintf(stderr, "%s: CPM object position format error. Use 'ID:<LAT:LON>'"
#ifdef USE_LIBGPS
                                                                                 "|<gpsd:// url>"
#endif
      "\n", value->v_str);
        return -1;
    }
    // search for object ID
    CollectivePerceptionMessage_t * cpm;
    for(size_t n=0; n<_cpms_count; n++){
        cpm = _cpms[n];
        WrappedCpmContainer_t * wc = _cpm_container_of(cpm, CpmContainerId_perceivedObjectContainer);
        if(wc){
            for(size_t i=0; i<wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.count; i++){
                PerceivedObject_t * po = wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.array[i];
                if(po->objectId && *po->objectId == id){
                    return _cpm_po_set_position(po, e+1);
                }                    
            }
        }
    }
    fprintf(stderr, "CPM object %d not found\n", id);
    return -1;
}

/*
static asn_TYPE_operation_t _op_debug;
static asn_enc_rval_t SEQUENCE_encode_uper_debug(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const asn_per_constraints_t *constraints, const void *struct_ptr,
    asn_per_outp_t *per_output
){
    return SEQUENCE_encode_uper(type_descriptor, constraints, struct_ptr, per_output);
}
static asn_enc_rval_t INTEGER_encode_uper_debug(
    const struct asn_TYPE_descriptor_s *type_descriptor,
    const asn_per_constraints_t *constraints, const void *struct_ptr,
    asn_per_outp_t *per_output
){
    return INTEGER_encode_uper(type_descriptor, constraints, struct_ptr, per_output);
}
*/

static int _options(MsgGenApp* app, int argc, char* argv[])
{
    int rc = 0;
    
    if (argc == 0) {
        coptions_help_ex(stderr, NULL, 0, options, "CP options:", NULL, NULL);
    }
    else {
        rc = coptions(argc, argv, COPT_NOREORDER | COPT_NOAUTOHELP | COPT_NOERR_UNKNOWN | COPT_NOERR_MSG, options);
        if(rc < 0){
            return rc;
        }
        // create CPM if not yet created
/*        
        if(_cpms_count == 0){
            // no objects and no perception regions
            _cpms[_cpms_count++] = _cpm_create_default();
        }
        _cpms[0]->header.stationId = _o_stationId;
*/
        if(_cpms_count > 1){
            // postprocess CPM messages
            for(size_t i=0; i<_cpms_count; i++){
                MessageSegmentationInfo_t * si = cnew0(MessageSegmentationInfo_t);
                si->thisMsgNo = i;
                si->totalMsgNo = _cpms_count;
                _cpms[i]->payload.managementContainer.segmentationInfo = si;
            }
        }
        if(_o_export){
            if(_cpms_count == 0){
                // no objects and no perception regions
                _cpms[_cpms_count++] = _cpm_create_default();
            }
            _cpms[0]->header.stationId = _o_stationId;
            // add test perceived object and perception region in the CPM
            CollectivePerceptionMessage_t * cpm = _cpms[0];
            PerceivedObject_t * po = _cpm_po_new(0);
            po->objectId = cnew0(Identifier2B_t);
            po->velocity = cnew0(Velocity3dWithConfidence_t);
            po->velocity->present = Velocity3dWithConfidence_PR_cartesianVelocity;
            po->velocity->choice.cartesianVelocity.xVelocity.confidence = SpeedConfidence_unavailable;
            po->velocity->choice.cartesianVelocity.yVelocity.confidence = SpeedConfidence_unavailable;
            po->acceleration = cnew0(Acceleration3dWithConfidence_t);
            po->acceleration->present = Acceleration3dWithConfidence_PR_cartesianAcceleration;
            po->acceleration->choice.cartesianAcceleration.xAcceleration.confidence = AccelerationConfidence_unavailable;
            po->acceleration->choice.cartesianAcceleration.yAcceleration.confidence = AccelerationConfidence_unavailable;
            po->angles = cnew0(EulerAnglesWithConfidence_t);
            po->angles->zAngle.confidence = AngleConfidence_unavailable;
            po->objectDimensionZ = cnew(ObjectDimension_t);
            po->objectDimensionZ->value=20;
            po->objectDimensionZ->confidence=1;
            po->objectDimensionX = cnew(ObjectDimension_t);
            po->objectDimensionX->value=20;
            po->objectDimensionX->confidence=1;
            po->objectDimensionY = cnew(ObjectDimension_t);
            po->objectDimensionY->value=20;
            po->objectDimensionY->confidence=1;
            po->objectPerceptionQuality = cnew(ObjectPerceptionQuality_t);
            *po->objectPerceptionQuality = 10;
            po->classification = cnew0(ObjectClassDescription_t);
            po->position.yCoordinate.confidence = CoordinateConfidence_unavailable;
            po->position.xCoordinate.confidence = CoordinateConfidence_unavailable;

            ObjectClassWithConfidence_t * oc;
            oc = cnew(ObjectClassWithConfidence_t);
            ASN_SEQUENCE_ADD(&po->classification->list, oc);
            oc->objectClass.present = ObjectClass_PR_vehicleSubClass;
            oc->objectClass.choice.vehicleSubClass = TrafficParticipantType_unknown;
            oc->confidence = 80;

            oc = cnew(ObjectClassWithConfidence_t);
            ASN_SEQUENCE_ADD(&po->classification->list, oc);
            oc->objectClass.present = ObjectClass_PR_vehicleSubClass;
            oc->objectClass.choice.vehicleSubClass = TrafficParticipantType_bus;
            oc->confidence = 20;

            _cpm_add_object(_cpms[_cpms_count-1], po);

            WrappedCpmContainer_t * wc = _cpm_container_of(cpm, CpmContainerId_perceptionRegionContainer);
            if(wc == NULL){
                wc = cnew0(WrappedCpmContainer_t);
                ASN_SEQUENCE_ADD(&cpm->payload.cpmContainers.list, wc);
                wc->containerId = CpmContainerId_perceptionRegionContainer;
                wc->containerData.present = WrappedCpmContainer__containerData_PR_PerceptionRegionContainer;
                PerceptionRegion_t * pr = cnew0(PerceptionRegion_t);
                ASN_SEQUENCE_ADD(&wc->containerData.choice.PerceptionRegionContainer.list, pr);
                pr->perceptionRegionType.present = ReportingType_PR_reportingAllNonPermanentObjects;
                pr->perceptionRegionType.choice.reportingAllNonPermanentObjects.present = Shape_PR_rectangular;
                pr->perceptionRegionType.choice.reportingAllNonPermanentObjects.choice.rectangular.semiLength = 10;
                pr->perceptionRegionType.choice.reportingAllNonPermanentObjects.choice.rectangular.semiBreadth = 10;
                pr->perceptionRegionShape.present = Shape_PR_rectangular;
                pr->perceptionRegionShape.choice.rectangular.semiLength = 10;
                pr->perceptionRegionShape.choice.rectangular.semiBreadth = 10;
                // add all perceived objects here
                wc = _cpm_container_of(cpm, CpmContainerId_perceivedObjectContainer);
                if(wc && wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.count > 0){
                    pr->numberOfPerceivedObjects = cnew0(CardinalNumber1B_t);
                    *pr->numberOfPerceivedObjects = wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.count;
                    pr->perceivedObjectIds = cnew0(PerceivedObjectIds_t);
                    wc = _cpm_container_of(cpm, CpmContainerId_perceivedObjectContainer);
                    if(wc){
                        for(int i=0; i<wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.count; i++){
                            PerceivedObject_t * po = wc->containerData.choice.PerceivedObjectContainer.perceivedObjects.list.array[i];
                            if(po->objectId){
                                ASN_SEQUENCE_ADD(&pr->perceivedObjectIds->list, po->objectId);
                            }
                        }
                    }
                }
            }

            char * buf = malloc(65535);
            asn_enc_rval_t rc = asn_encode_to_buffer(NULL, ATS_BASIC_XER, &asn_DEF_CollectivePerceptionMessage, _cpms[0], buf, 65535);
            if (rc.encoded < 0) {
                fprintf(stderr, "CPM export error at %s\n", rc.failed_type->name);
                free(buf);
                return COPT_ERROR;
            }
            if(cstrnsave(buf, rc.encoded, _o_export)-buf == rc.encoded){
                fprintf(stderr, "CPM exported to %s (%lu bytes)\n", _o_export, (long unsigned int)rc.encoded);
            }else{
                fprintf(stderr, "Can not export CPM to %s (%lu bytes)\n", _o_export, (long unsigned int)rc.encoded);
            }
            free(buf);
            return COPT_ERROR;
        }
/*        
        _op_debug = asn_OP_INTEGER;
        _op_debug.uper_encoder = INTEGER_encode_uper_debug;
        asn_DEF_TimestampIts.op = &_op_debug;
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

static size_t _fill_cpm(MsgGenApp* app, FitSec * e, FSMessageInfo* m, CollectivePerceptionMessage_t * cpm);
static FSTime64 _lastSent = 0;
static void _process (MsgGenApp * app, FitSec * e)
{
    if(_cpms_count > 0){
        FSMessageInfo m = {0};
        GN_PrepareMessage(&m);
        uint64_t tdif = m.generationTime - _lastSent;
        if(tdif > floor(1000000.0/_o_rate)){
            _lastSent = m.generationTime;
            for(size_t i=0; i< _cpms_count; i++){
                _fill_cpm(app, e, &m, _cpms[i]);
                GN_SendMessage(app, &m);
            }
        }
    }
}

static size_t _fill(MsgGenApp* app, FitSec * e, FSMessageInfo* m)
{
    if(_cpms_count > 0){
        return _fill_cpm(app, e, m, _cpms[0]);
    }
    return 0;
}

static size_t _fill_cpm(MsgGenApp* app, FitSec * e, FSMessageInfo* m, CollectivePerceptionMessage_t * cpm)
{

    size_t len;
    m->status = 0;

#ifndef NO_SECURITY
    if (_o_secured) {
        m->payloadType = FS_PAYLOAD_SIGNED;
        m->sign.ssp.aid = 639;
        memset(m->sign.ssp.sspData.opaque, 0, sizeof(m->sign.ssp.sspData.opaque));
        m->sign.ssp.sspLen = 1;
        m->sign.ssp.sspData.bits.version = 1;

        len = FitSec_PrepareSignedMessage(e, m);
        if (len <= 0) {
            fprintf(stderr, "%-2s PREP %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "PrepareSignedMessage", m->status, FitSec_ErrorMessage(m->status));
            return len;
        }
    }
    else
#endif
    {
        m->payloadType = FS_PAYLOAD_UNSECURED;
        m->payload = m->message;
    }

    GNCommonHeader* ch = (GNCommonHeader*)m->payload;
    GNExtendedHeader* eh = (GNExtendedHeader*)(ch + 1);

    *ch = _def_ch;
    *eh = _def_eh;
    uint32_t * bh = (uint32_t*)&((&eh->shb)[1]);
    bh[0] = 0x0000d907; // port 2009
    len = ((char*)&bh[1]) - m->payload;

    if(m->position.latitude || m->position.longitude){
        cpm->payload.managementContainer.referencePosition.latitude = m->position.latitude;
        cpm->payload.managementContainer.referencePosition.longitude = m->position.longitude;
    }else{
        cpm->payload.managementContainer.referencePosition.latitude = Latitude_unavailable;
        cpm->payload.managementContainer.referencePosition.longitude = Longitude_unavailable;
    }

    eh->shb.srcPosVector.latitude = m->position.latitude;
    eh->shb.srcPosVector.longitude = m->position.longitude;
    eh->shb.srcPosVector.timestamp = (uint32_t)(m->generationTime / 1000);

    asn_long2INTEGER(&cpm->payload.managementContainer.referenceTime, eh->shb.srcPosVector.timestamp);

    for(int cnt=0; cnt < cpm->payload.cpmContainers.list.count; cnt++){
        WrappedCpmContainer_t * wc = cpm->payload.cpmContainers.list.array[cnt];
        switch(wc->containerData.present){
            case WrappedCpmContainer__containerData_PR_PerceivedObjectContainer:
            {
                PerceivedObjectContainer_t * poc = &wc->containerData.choice.PerceivedObjectContainer;
                for(int i=0; i < poc->perceivedObjects.list.count; i++){
                    PerceivedObject_t * po = poc->perceivedObjects.list.array[i];
                    _cpm_po_update_position(po, &m->position);
                }
                break;
            }
            default:
                break;
        }
    }

    asn_enc_rval_t rc = asn_encode_to_buffer(NULL, ATS_UNALIGNED_CANONICAL_PER, &asn_DEF_CollectivePerceptionMessage, cpm, m->payload + len, m->payloadSize - len);
    if (rc.encoded < 0) {
        fprintf(stderr, "%-2s SEND %s:\t ERROR: at %s\n", e?FitSec_Name(e):"CPM", "asn_encode", rc.failed_type->name);
        len = 0;
    }
    else {
        char* p = m->payload + len + rc.encoded;
        m->payloadSize = p - m->payload;

        ch->plLength = cint16_hton((unsigned short)(rc.encoded + 4)); // plus BTP
#ifndef NO_SECURITY
        if (_o_secured) {
            len = FitSec_FinalizeSignedMessage(e, m);
            if (len == 0) {
                fprintf(stderr, "%-2s SEND %s:\t ERROR: 0x%08X %s\n", FitSec_Name(e), "FinalizeSignedMessage", m->status, FitSec_ErrorMessage(m->status));
            }
        }
        else
#endif
        {
            m->messageSize = p - m->message;
        }
    }
    return len;
}

static void _receive (MsgGenApp * app, FitSec* e, FSMessageInfo * m, uint16_t btpPort)
{
    if(btpPort == 2009){
        mclog_info(VRU, "%s CPM received",
            stritstime64(m->generationTime) 
        );
    }
}


static int  _ut_handler(FSUT* ut, void* ptr, FSUT_Message* m, int * psize)
{
    return 0;
}
