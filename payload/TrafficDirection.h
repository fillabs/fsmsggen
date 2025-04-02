/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_TrafficDirection_H_
#define	_TrafficDirection_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TrafficDirection {
	TrafficDirection_allTrafficDirections	= 0,
	TrafficDirection_sameAsReferenceDirection_upstreamOfReferencePosition	= 1,
	TrafficDirection_sameAsReferenceDirection_downstreamOfReferencePosition	= 2,
	TrafficDirection_oppositeToReferenceDirection	= 3
} e_TrafficDirection;

/* TrafficDirection */
typedef long	 TrafficDirection_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TrafficDirection_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TrafficDirection;
extern const asn_INTEGER_specifics_t asn_SPC_TrafficDirection_specs_1;
asn_struct_free_f TrafficDirection_free;
asn_constr_check_f TrafficDirection_constraint;
per_type_decoder_f TrafficDirection_decode_uper;
per_type_encoder_f TrafficDirection_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TrafficDirection_H_ */
#include <asn_internal.h>
