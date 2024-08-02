/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "AccelerationPolarWithZ.h"
#include "AccelerationCartesian.h"
#include <constr_CHOICE.h>
#ifndef	_Acceleration3dWithConfidence_H_
#define	_Acceleration3dWithConfidence_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Acceleration3dWithConfidence_PR {
	Acceleration3dWithConfidence_PR_NOTHING,	/* No components present */
	Acceleration3dWithConfidence_PR_polarAcceleration,
	Acceleration3dWithConfidence_PR_cartesianAcceleration
} Acceleration3dWithConfidence_PR;

/* Acceleration3dWithConfidence */
typedef struct Acceleration3dWithConfidence {
	Acceleration3dWithConfidence_PR present;
	union Acceleration3dWithConfidence_u {
		AccelerationPolarWithZ_t	 polarAcceleration;
		AccelerationCartesian_t	 cartesianAcceleration;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Acceleration3dWithConfidence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Acceleration3dWithConfidence;
extern asn_CHOICE_specifics_t asn_SPC_Acceleration3dWithConfidence_specs_1;
extern asn_TYPE_member_t asn_MBR_Acceleration3dWithConfidence_1[2];
extern asn_per_constraints_t asn_PER_type_Acceleration3dWithConfidence_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Acceleration3dWithConfidence_H_ */
#include <asn_internal.h>
