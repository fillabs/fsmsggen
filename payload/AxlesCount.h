/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_AxlesCount_H_
#define	_AxlesCount_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AxlesCount {
	AxlesCount_outOfRange	= 1001,
	AxlesCount_unavailable	= 1002
} e_AxlesCount;

/* AxlesCount */
typedef long	 AxlesCount_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AxlesCount;
asn_struct_free_f AxlesCount_free;
asn_constr_check_f AxlesCount_constraint;
ber_type_decoder_f AxlesCount_decode_ber;
der_type_encoder_f AxlesCount_encode_der;
per_type_decoder_f AxlesCount_decode_uper;
per_type_encoder_f AxlesCount_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AxlesCount_H_ */
#include <asn_internal.h>
