/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_RelevanceTrafficDirection_H_
#define	_RelevanceTrafficDirection_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum RelevanceTrafficDirection {
	RelevanceTrafficDirection_allTrafficDirections	= 0,
	RelevanceTrafficDirection_upstreamTraffic	= 1,
	RelevanceTrafficDirection_downstreamTraffic	= 2,
	RelevanceTrafficDirection_oppositeTraffic	= 3
} e_RelevanceTrafficDirection;

/* RelevanceTrafficDirection */
typedef long	 RelevanceTrafficDirection_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_RelevanceTrafficDirection_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_RelevanceTrafficDirection;
extern const asn_INTEGER_specifics_t asn_SPC_RelevanceTrafficDirection_specs_1;
asn_struct_free_f RelevanceTrafficDirection_free;
asn_struct_print_f RelevanceTrafficDirection_print;
asn_constr_check_f RelevanceTrafficDirection_constraint;
ber_type_decoder_f RelevanceTrafficDirection_decode_ber;
der_type_encoder_f RelevanceTrafficDirection_encode_der;
jer_type_encoder_f RelevanceTrafficDirection_encode_jer;
per_type_decoder_f RelevanceTrafficDirection_decode_uper;
per_type_encoder_f RelevanceTrafficDirection_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _RelevanceTrafficDirection_H_ */
#include <asn_internal.h>
