/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_HeadingValue_H_
#define	_HeadingValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HeadingValue {
	HeadingValue_wgs84North	= 0,
	HeadingValue_wgs84East	= 900,
	HeadingValue_wgs84South	= 1800,
	HeadingValue_wgs84West	= 2700,
	HeadingValue_doNotUse	= 3600,
	HeadingValue_unavailable	= 3601
} e_HeadingValue;

/* HeadingValue */
typedef long	 HeadingValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_HeadingValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_HeadingValue;
asn_struct_free_f HeadingValue_free;
asn_constr_check_f HeadingValue_constraint;
ber_type_decoder_f HeadingValue_decode_ber;
der_type_encoder_f HeadingValue_encode_der;
per_type_decoder_f HeadingValue_decode_uper;
per_type_encoder_f HeadingValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _HeadingValue_H_ */
#include <asn_internal.h>
