/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_DeltaLongitude_H_
#define	_DeltaLongitude_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum DeltaLongitude {
	DeltaLongitude_unavailable	= 131072
} e_DeltaLongitude;

/* DeltaLongitude */
typedef long	 DeltaLongitude_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_DeltaLongitude_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_DeltaLongitude;
asn_struct_free_f DeltaLongitude_free;
asn_constr_check_f DeltaLongitude_constraint;
per_type_decoder_f DeltaLongitude_decode_uper;
per_type_encoder_f DeltaLongitude_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _DeltaLongitude_H_ */
#include <asn_internal.h>
