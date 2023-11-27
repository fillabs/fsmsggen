#ifndef uppertester_h
#define uppertester_h
#include "cmem.h"
#include <inttypes.h>
typedef struct FSUT FSUT;
#define FSUT_MAX_MSG_SIZE 128

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
    uint8_t  pdu[0];
});

__PACKED__(struct FSUTMsg_PkiTriggerInd {
    uint8_t  code;
    uint8_t  state;
});

__PACKED__(union FSUT_Message {
    uint8_t                          code;
    struct FSUTMsg_Initialize        initialize;
    struct FSUTMsg_SetCamState       camState;
    struct FSUTMsg_Result            result;
    struct FSUTMsg_ChangePosition    changePosition;
    struct FSUTMsg_ChangePseudonym   changePseudonym;
    // CAM
    struct FSUTMsg_ChangeCurvature   changeCurvature;
    struct FSUTMsg_ChangeSpeed       changeSpeed;
    //DENM
    struct FSUTMsg_DenmTrigger       denmTrigger;
    struct FSUTMsg_DenmTerminate     denmTerminate;

    struct FSUTMsg_Indication        indication;
    struct FSUTMsg_DenmTriggerResult denmTriggerResult;
    
    struct FSUTMsg_PkiTriggerInd     pkiState;
});

FSUT* FSUT_New(const char* bind_host, int bind_port);
void  FSUT_Free(FSUT* ut);

/** @return   -1 - error. do not send answer
  *          >=0 - send answer with this RC
  */
typedef int   (*FSUT_Handler_fn) (FSUT* ut, void* ptr, FSUT_Message* msg, int * msgLen);

void  FSUT_RegisterHandler(FSUT* ut, FSUT_Handler_fn handler, void* ptr);

int   FSUT_Start(FSUT* ut);
void  FSUT_Stop(FSUT* ut);

int   FSUT_Run(FSUT* ut);
int   FSUT_Proceed(FSUT* ut, FSUT_Message * m);

int   FSUT_onUTMessage(FSUT* ut, const char* buf, size_t size);
int   FSUT_SendIndication(FSUT* ut, uint8_t code, const char* buf, size_t size);
void  FSUT_EnqueueIndication(FSUT* ut, uint8_t code, const char* buf, size_t size);

int   FSUT_CommandMessage(FSUT_Message ** pmsg, int argc, char ** argv);

#endif
