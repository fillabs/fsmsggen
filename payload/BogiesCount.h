/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_BogiesCount_H_
#define	_BogiesCount_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum BogiesCount {
	BogiesCount_outOfRange	= 100,
	BogiesCount_unavailable	= 101
} e_BogiesCount;

/* BogiesCount */
typedef long	 BogiesCount_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_BogiesCount;
asn_struct_free_f BogiesCount_free;
asn_constr_check_f BogiesCount_constraint;
per_type_decoder_f BogiesCount_decode_uper;
per_type_encoder_f BogiesCount_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _BogiesCount_H_ */
#include <asn_internal.h>
