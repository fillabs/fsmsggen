#ifndef uppertester_h
#define uppertester_h

#include "cmem.h"
#include "citstime.h"
#include <inttypes.h>
typedef struct FSUT FSUT;
#define FSUT_MAX_MSG_SIZE 128
#define FSUT_DEFAULT_PORT 12345


typedef union  FSUT_Message FSUT_Message;

enum {
    FS_UtInitialize = 0x00,
    FS_UtInitializeResult = 0x01,
    FS_UtChangePosition = 0x02,
    FS_UtChangePositionResult = 0x03,
    FS_UtChangePseudonym = 0x04,
    FS_UtChangePseudonymResult = 0x05,

    FS_UtCamTrigger = 0x20,
    FS_UtCamTriggerResult = 0x21,
    FS_UtCamEventInd = 0x23,
    FS_UtCamTrigger_changeCurvature = 0x30,
    FS_UtCamTrigger_changeSpeed = 0x31,
    FS_UtCamTrigger_setAccelerationControlStatus = 0x32,
    FS_UtCamTrigger_setExteriorLightsStatus = 0x33,
    FS_UtCamTrigger_changeHeading = 0x34,
    FS_UtCamTrigger_setDriveDirection = 0x35,
    FS_UtCamTrigger_changeYawRate = 0x36,
    FS_UtCamTrigger_setStationType = 0x39,
    FS_UtCamTrigger_setVehicleRole = 0x3a,
    FS_UtCamTrigger_setEmbarkationStatus = 0x3b,
    FS_UtCamTrigger_setPtActivation = 0x3c,
    FS_UtCamTrigger_setDangerousGoods = 0x3d,
    FS_UtCamTrigger_setLightBarSiren = 0x3e,

    FS_UtDenmTrigger = 0x10,
    FS_UtDenmTriggerResult = 0x11,
    FS_UtDenmUpdate = 0x12,
    FS_UtDenmUpdateResult = 0x13,
    FS_UtDenmTermination = 0x14,
    FS_UtDenmTerminationResult = 0x15,
    FS_UtDenmEventInd = 0x17,

    FS_UtGnTriggerResult = 0x41,
    FS_UtGnTrigger_geoUnicast = 0x50,
    FS_UtGnTrigger_geoBroadcast = 0x51,
    FS_UtGnTrigger_geoAnycast = 0x52,
    FS_UtGnTrigger_shb = 0x53,
    FS_UtGnTrigger_tsb = 0x54,
    FS_UtGnEventInd = 0x55,

    FS_UtGenerateInnerEcRequest = 0xD0,
    FS_UtGenerateInnerAtRequest = 0xD1,
    FS_UtGenerateInnerEcResult  = 0xD2,
    FS_UtGenerateInnerAtResult  = 0xD2,
    FS_UtPkiTriggerInd          = 0xD3,
    FS_UtPkiTriggerRcaCtlRequest= 0xD4,
    FS_UtPkiTriggerTlmCtlRequest= 0xD5,
    FS_UtPkiTriggerCrlRequest   = 0xD6,

    FS_UtVamTrigger = 0xE0,
    FS_UtVamLeader = 0xE1,
    FS_UtVamJoin = 0xE2,
};

__PACKED__(struct FSUTMsg_Initialize {
    uint8_t  code;
    uint64_t digest;
});
__PACKED__(struct FSUTMsg_Result {
    uint8_t code;
    uint8_t result;
});
__PACKED__(struct FSUTMsg_SetCamState {
    uint8_t code;
    uint8_t state; // 0 - stop, 1 - start
});

__PACKED__(struct FSUTMsg_ChangePosition {
    uint8_t code;
    int32_t deltaLatitude;
    int32_t deltaLongitude;
    int32_t deltaAltitude;
});

__PACKED__(struct FSUTMsg_ChangePseudonym {
    uint8_t code;
});
__PACKED__(struct FSUTMsg_ChangeCurvature {
    uint8_t code;
    int16_t curvature;
});
__PACKED__(struct FSUTMsg_ChangeSpeed {
    uint8_t code;
    int16_t speed;
});
__PACKED__(struct FSUTMsg_SetAccelerationControlStatus {
    uint8_t code;
    uint8_t status;
});
__PACKED__(struct FSUTMsg_SetExteriorLightsStatus {
    uint8_t code;
    uint8_t status;
});
__PACKED__(struct FSUTMsg_ChangeHeading {
    uint8_t  code;
    uint16_t heading;
});
__PACKED__(struct FSUTMsg_SetDriveDirection {
    uint8_t code;
    uint8_t direction; // 0 - forward, 1 - Backward, 2 - unavailable
});
__PACKED__(struct FSUTMsg_ChangeYawRate {
    uint8_t code;
    int16_t yawRate;
});
__PACKED__(struct FSUTMsg_SetStationType {
    uint8_t code;
    uint8_t type;
});
__PACKED__(struct FSUTMsg_SetVehicleRole {
    uint8_t code;
    uint8_t role;
});
__PACKED__(struct FSUTMsg_SetEmbarkationStatus {
    uint8_t code;
    uint8_t status;
});
__PACKED__(struct FSUTMsg_SetPtActivation {
    uint8_t code;
    uint8_t type;
    uint8_t length;
    uint8_t data[];
});
__PACKED__(struct FSUTMsg_SetDangerousGoods {
    uint8_t code;
    uint8_t status;
});
__PACKED__(struct FSUTMsg_SetLightBarSiren {
    uint8_t code;
    uint8_t status;
});

__PACKED__(struct FSUTMsg_DenmTrigger {
    uint8_t  code;
    uint8_t  flags;
    uint8_t  detectionTimeBuf[6];
    uint8_t  validityDurationBuf[3];
    uint8_t  repetitionDurationBuf[3];
    uint8_t  infoQuality;
    uint8_t  causeCode;
    uint8_t  subCauseCode;
    uint8_t  relevanceDistance;
    uint8_t  relevanceTrafficDirection;
    uint16_t transmissionInterval;
    uint16_t repetitionInterval;
    uint8_t  alacarteLength;
    uint8_t  alacarte[];
});

__PACKED__(struct FSUTMsg_DenmTriggerResult {
    uint8_t  code;
    uint8_t  result;
    uint32_t stationId;
    uint16_t sequenceNumber;
});

__PACKED__(struct FSUTMsg_DenmTerminate {
    uint8_t  code;
    uint32_t stationId;
    uint16_t sequenceNumber;
});

__PACKED__(struct FSUTMsg_Indication {
    uint8_t  code;
    uint16_t pduLength;
    uint8_t  pdu[];
});

__PACKED__(struct FSUTMsg_PkiTriggerInd {
    uint8_t  code;
    uint8_t  state;
});

__PACKED__(struct FSUTMsg_PkiTrustTrigger {
    uint8_t   code;
    char      path[1];
});

__PACKED__(struct FSUTMsg_VamCluster {
    uint8_t   code;
    long      clasterId;
});

__PACKED__(struct FSUTMsg_GeoUnicast {
    uint8_t   code;
    uint8_t   dst_addr[8];
    uint16_t  lifetime;
    uint8_t   trafficClass;
    uint16_t  payloadLength;
    uint8_t   payload[1];
});

__PACKED__(struct FSUTMsg_GeoBroadcast {
    uint8_t   code;
    uint8_t   shape;
    uint16_t  lifetime;
    uint8_t   trafficClass;
    uint8_t   reserved[3];
    uint32_t  latitude;
    uint32_t  longitude;
    uint16_t  a;
    uint16_t  b;
    uint16_t  angle;
    uint16_t  payloadLength;
    uint8_t   payload[1];
});

__PACKED__(struct FSUTMsg_SHB {
    uint8_t   code;
    uint8_t   trafficClass;
    uint16_t  payloadLength;
    uint8_t   payload[1];
});

__PACKED__(struct FSUTMsg_TSB {
    uint8_t   code;
    uint8_t   hopNumber;
    uint16_t  lifetime;
    uint8_t   trafficClass;
    uint16_t  payloadLength;
    uint8_t   payload[1];
});


__PACKED__(union FSUT_Message {
    uint8_t                          code;
    struct FSUTMsg_Initialize        initialize;
    struct FSUTMsg_SetCamState       camState;
    struct FSUTMsg_Result            result;
    struct FSUTMsg_ChangePosition    changePosition;
    struct FSUTMsg_ChangePseudonym   changePseudonym;
    // CAM
    struct FSUTMsg_ChangeCurvature              changeCurvature;
    struct FSUTMsg_ChangeSpeed                  changeSpeed;
    struct FSUTMsg_SetAccelerationControlStatus setAccStatus;
    struct FSUTMsg_SetExteriorLightsStatus      setExtLight;
    struct FSUTMsg_ChangeHeading                changeHeading;
    struct FSUTMsg_SetDriveDirection            setDriveDirection;
    struct FSUTMsg_ChangeYawRate                changeYawRate;
    struct FSUTMsg_SetStationType               setStationType;
    struct FSUTMsg_SetVehicleRole               setVehicleRole;
    struct FSUTMsg_SetEmbarkationStatus         setEmbarkationStatus;
    struct FSUTMsg_SetPtActivation              setPtActivation;
    struct FSUTMsg_SetDangerousGoods            setDangerousGoods;
    struct FSUTMsg_SetLightBarSiren             setLightBarSiren;
    //DENM
    struct FSUTMsg_DenmTrigger       denmTrigger;
    struct FSUTMsg_DenmTerminate     denmTerminate;

    struct FSUTMsg_Indication        indication;
    struct FSUTMsg_DenmTriggerResult denmTriggerResult;
    
    struct FSUTMsg_PkiTriggerInd     pkiState;

    struct FSUTMsg_PkiTrustTrigger   pkiTrust;
    
    struct FSUTMsg_SetCamState       vamState;
    struct FSUTMsg_VamCluster        vamCluster;

    struct FSUTMsg_GeoUnicast        guc;
    struct FSUTMsg_GeoBroadcast      gbc;
    struct FSUTMsg_SHB               shb;
    struct FSUTMsg_TSB               tsb;
});

FSUT* FSUT_New(const char* local_addr, const char* remote_addr);
void  FSUT_Free(FSUT* ut);

/** @return   -1 - error. do not send answer
  *          >=0 - send answer with this RC
  */
typedef int   (*FSUT_Handler_fn) (FSUT* ut, void* ptr, FSUT_Message* msg, int * msgLen);

void  FSUT_RegisterHandler(FSUT* ut, FSUT_Handler_fn handler, void* ptr);

int   FSUT_Start(FSUT* ut);
void  FSUT_Stop(FSUT* ut);

int   FSUT_Run(FSUT* ut);
int   FSUT_Proceed(FSUT* ut, FSUT_Message * m, struct timeval* ptv);

int   FSUT_onUTMessage(FSUT* ut, const char* buf, size_t size);
int   FSUT_SendMessage(FSUT* ut, const FSUT_Message * msg, size_t size); // size can be 0 to use default value
int   FSUT_SendIndication(FSUT* ut, uint8_t code, const char* buf, size_t size);
void  FSUT_EnqueueIndication(FSUT* ut, uint8_t code, const char* buf, size_t size);

int   FSUT_CommandMessage(FSUT_Message ** pmsg, int argc, char ** argv);

const char * FSUT_CommandHelp(const char * msg);
#endif
