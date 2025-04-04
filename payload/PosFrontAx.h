/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_PosFrontAx_H_
#define	_PosFrontAx_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PosFrontAx {
	PosFrontAx_outOfRange	= 19,
	PosFrontAx_unavailable	= 20
} e_PosFrontAx;

/* PosFrontAx */
typedef long	 PosFrontAx_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PosFrontAx_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PosFrontAx;
asn_struct_free_f PosFrontAx_free;
asn_constr_check_f PosFrontAx_constraint;
per_type_decoder_f PosFrontAx_decode_uper;
per_type_encoder_f PosFrontAx_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PosFrontAx_H_ */
#include <asn_internal.h>
