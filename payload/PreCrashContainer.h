/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Description"
 * 	found in "asn1/DENM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "PerceivedObject.h"
#include "StationId.h"
#include "DeltaTimeMilliSecondPositive.h"
#include "ObjectFace.h"
#include "StandardLength12b.h"
#include <constr_SEQUENCE.h>
#ifndef	_PreCrashContainer_H_
#define	_PreCrashContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PreCrashContainer */
typedef struct PreCrashContainer {
	PerceivedObject_t	 perceivedPreCrashObject;
	StationId_t	*objectStationId;	/* OPTIONAL */
	DeltaTimeMilliSecondPositive_t	*timeToCollision;	/* OPTIONAL */
	ObjectFace_t	*impactSection;	/* OPTIONAL */
	StandardLength12b_t	*estimatedBrakingDistance;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PreCrashContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PreCrashContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_PreCrashContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_PreCrashContainer_1[5];

#ifdef __cplusplus
}
#endif

#endif	/* _PreCrashContainer_H_ */
#include <asn_internal.h>
