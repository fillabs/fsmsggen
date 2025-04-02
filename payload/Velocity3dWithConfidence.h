/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "VelocityPolarWithZ.h"
#include "VelocityCartesian.h"
#include <constr_CHOICE.h>
#ifndef	_Velocity3dWithConfidence_H_
#define	_Velocity3dWithConfidence_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Velocity3dWithConfidence_PR {
	Velocity3dWithConfidence_PR_NOTHING,	/* No components present */
	Velocity3dWithConfidence_PR_polarVelocity,
	Velocity3dWithConfidence_PR_cartesianVelocity
} Velocity3dWithConfidence_PR;

/* Velocity3dWithConfidence */
typedef struct Velocity3dWithConfidence {
	Velocity3dWithConfidence_PR present;
	union Velocity3dWithConfidence_u {
		VelocityPolarWithZ_t	 polarVelocity;
		VelocityCartesian_t	 cartesianVelocity;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Velocity3dWithConfidence_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Velocity3dWithConfidence;
extern asn_CHOICE_specifics_t asn_SPC_Velocity3dWithConfidence_specs_1;
extern asn_TYPE_member_t asn_MBR_Velocity3dWithConfidence_1[2];
extern asn_per_constraints_t asn_PER_type_Velocity3dWithConfidence_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _Velocity3dWithConfidence_H_ */
#include <asn_internal.h>
