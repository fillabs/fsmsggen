/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_Position1d_H_
#define	_Position1d_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Position1d {
	Position1d_outOfRange	= 8190,
	Position1d_unavailable	= 8191
} e_Position1d;

/* Position1d */
typedef long	 Position1d_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_Position1d_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_Position1d;
asn_struct_free_f Position1d_free;
asn_constr_check_f Position1d_constraint;
per_type_decoder_f Position1d_decode_uper;
per_type_encoder_f Position1d_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _Position1d_H_ */
#include <asn_internal.h>
