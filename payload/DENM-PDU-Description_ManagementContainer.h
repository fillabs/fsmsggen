/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/DENM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "ActionId.h"
#include "TimestampIts.h"
#include "Termination.h"
#include "ReferencePosition.h"
#include "StandardLength3b.h"
#include "TrafficDirection.h"
#include "DeltaTimeSecond.h"
#include "DeltaTimeMilliSecondPositive.h"
#include "StationType.h"
#include <constr_SEQUENCE.h>
#ifndef	_DENM_PDU_Description_ManagementContainer_H_
#define	_DENM_PDU_Description_ManagementContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* DENM-PDU-Description_ManagementContainer */
typedef struct DENM_PDU_Description_ManagementContainer {
	ActionId_t	 actionId;
	TimestampIts_t	 detectionTime;
	TimestampIts_t	 referenceTime;
	Termination_t	*termination;	/* OPTIONAL */
	ReferencePosition_t	 eventPosition;
	StandardLength3b_t	*awarenessDistance;	/* OPTIONAL */
	TrafficDirection_t	*trafficDirection;	/* OPTIONAL */
	DeltaTimeSecond_t	*validityDuration;	/* DEFAULT 600 */
	DeltaTimeMilliSecondPositive_t	*transmissionInterval;	/* OPTIONAL */
	StationType_t	 stationType;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} DENM_PDU_Description_ManagementContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_DENM_PDU_Description_ManagementContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_DENM_PDU_Description_ManagementContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_DENM_PDU_Description_ManagementContainer_1[10];

#ifdef __cplusplus
}
#endif

#endif	/* _DENM_PDU_Description_ManagementContainer_H_ */
#include <asn_internal.h>
