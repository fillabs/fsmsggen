/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "VehicleLengthValue.h"
#include "TrailerPresenceInformation.h"
#include <constr_SEQUENCE.h>
#ifndef	_VehicleLengthV2_H_
#define	_VehicleLengthV2_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* VehicleLengthV2 */
typedef struct VehicleLengthV2 {
	VehicleLengthValue_t	 vehicleLengthValue;
	TrailerPresenceInformation_t	 trailerPresenceInformation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VehicleLengthV2_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VehicleLengthV2;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleLengthV2_H_ */
#include <asn_internal.h>
