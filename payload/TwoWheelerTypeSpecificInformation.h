/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "CyclistTypeSpecificInformation.h"
#include <constr_CHOICE.h>
#ifndef	_TwoWheelerTypeSpecificInformation_H_
#define	_TwoWheelerTypeSpecificInformation_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TwoWheelerTypeSpecificInformation_PR {
	TwoWheelerTypeSpecificInformation_PR_NOTHING,	/* No components present */
	TwoWheelerTypeSpecificInformation_PR_cyclist
	/* Extensions may appear below */
	
} TwoWheelerTypeSpecificInformation_PR;

/* TwoWheelerTypeSpecificInformation */
typedef struct TwoWheelerTypeSpecificInformation {
	TwoWheelerTypeSpecificInformation_PR present;
	union TwoWheelerTypeSpecificInformation_u {
		CyclistTypeSpecificInformation_t	 cyclist;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TwoWheelerTypeSpecificInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TwoWheelerTypeSpecificInformation;
extern asn_CHOICE_specifics_t asn_SPC_TwoWheelerTypeSpecificInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_TwoWheelerTypeSpecificInformation_1[1];
extern asn_per_constraints_t asn_PER_type_TwoWheelerTypeSpecificInformation_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _TwoWheelerTypeSpecificInformation_H_ */
#include <asn_internal.h>
