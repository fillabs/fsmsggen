/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_ConfidenceLevel_H_
#define	_ConfidenceLevel_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ConfidenceLevel {
	ConfidenceLevel_unavailable	= 101
} e_ConfidenceLevel;

/* ConfidenceLevel */
typedef long	 ConfidenceLevel_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ConfidenceLevel_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ConfidenceLevel;
asn_struct_free_f ConfidenceLevel_free;
asn_constr_check_f ConfidenceLevel_constraint;
ber_type_decoder_f ConfidenceLevel_decode_ber;
der_type_encoder_f ConfidenceLevel_encode_der;
per_type_decoder_f ConfidenceLevel_decode_uper;
per_type_encoder_f ConfidenceLevel_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ConfidenceLevel_H_ */
#include <asn_internal.h>
