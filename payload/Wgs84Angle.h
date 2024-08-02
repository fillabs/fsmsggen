/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "Wgs84AngleValue.h"
#include "Wgs84AngleConfidence.h"
#include <constr_SEQUENCE.h>
#ifndef	_Wgs84Angle_H_
#define	_Wgs84Angle_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wgs84Angle */
typedef struct Wgs84Angle {
	Wgs84AngleValue_t	 value;
	Wgs84AngleConfidence_t	 confidence;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Wgs84Angle_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Wgs84Angle;
extern asn_SEQUENCE_specifics_t asn_SPC_Wgs84Angle_specs_1;
extern asn_TYPE_member_t asn_MBR_Wgs84Angle_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _Wgs84Angle_H_ */
#include <asn_internal.h>
