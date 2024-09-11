/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "CartesianAngleValue.h"
#include "AngleConfidence.h"
#include <constr_SEQUENCE.h>
#ifndef	_CartesianAngle_H_
#define	_CartesianAngle_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CartesianAngle */
typedef struct CartesianAngle {
	CartesianAngleValue_t	 value;
	AngleConfidence_t	 confidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CartesianAngle_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CartesianAngle;
extern asn_SEQUENCE_specifics_t asn_SPC_CartesianAngle_specs_1;
extern asn_TYPE_member_t asn_MBR_CartesianAngle_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _CartesianAngle_H_ */
#include <asn_internal.h>
