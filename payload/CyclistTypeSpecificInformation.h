/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "VruSubProfileBicyclist.h"
#include "VruMovementControl.h"
#include <constr_SEQUENCE.h>
#ifndef	_CyclistTypeSpecificInformation_H_
#define	_CyclistTypeSpecificInformation_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CyclistTypeSpecificInformation */
typedef struct CyclistTypeSpecificInformation {
	VruSubProfileBicyclist_t	*vruSubProfileBicyclist;	/* OPTIONAL */
	VruMovementControl_t	*vruMovementControl;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CyclistTypeSpecificInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CyclistTypeSpecificInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_CyclistTypeSpecificInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_CyclistTypeSpecificInformation_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _CyclistTypeSpecificInformation_H_ */
#include <asn_internal.h>
