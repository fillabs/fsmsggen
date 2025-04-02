/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "PedalStatus.h"
#include "SaeAutomationLevel.h"
#include "AutomationControl.h"
#include "AccelerationControl.h"
#include "AccelerationControlExtension.h"
#include <constr_SEQUENCE.h>
#ifndef	_VehicleMovementControl_H_
#define	_VehicleMovementControl_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* VehicleMovementControl */
typedef struct VehicleMovementControl {
	PedalStatus_t	 accelerationPedalStatus;
	PedalStatus_t	 brakePedalStatus;
	SaeAutomationLevel_t	*saeAutomationLevel;	/* OPTIONAL */
	AutomationControl_t	*automationControl;	/* OPTIONAL */
	AccelerationControl_t	*accelerationControl;	/* OPTIONAL */
	AccelerationControlExtension_t	*accelerationControlExtension;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VehicleMovementControl_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VehicleMovementControl;
extern asn_SEQUENCE_specifics_t asn_SPC_VehicleMovementControl_specs_1;
extern asn_TYPE_member_t asn_MBR_VehicleMovementControl_1[6];

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleMovementControl_H_ */
#include <asn_internal.h>
