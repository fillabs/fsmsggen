/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "StationId.h"
#include "SafeDistanceIndicator.h"
#include "DeltaTimeTenthOfSecond.h"
#include <constr_SEQUENCE.h>
#ifndef	_SafeDistanceIndication_H_
#define	_SafeDistanceIndication_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SafeDistanceIndication */
typedef struct SafeDistanceIndication {
	StationId_t	*subjectStation;	/* OPTIONAL */
	SafeDistanceIndicator_t	 safeDistanceIndicator;
	DeltaTimeTenthOfSecond_t	*timeToCollision;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SafeDistanceIndication_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SafeDistanceIndication;
extern asn_SEQUENCE_specifics_t asn_SPC_SafeDistanceIndication_specs_1;
extern asn_TYPE_member_t asn_MBR_SafeDistanceIndication_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _SafeDistanceIndication_H_ */
#include <asn_internal.h>
