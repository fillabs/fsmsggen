/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_OtherSubClass_H_
#define	_OtherSubClass_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum OtherSubClass {
	OtherSubClass_unknown	= 0,
	OtherSubClass_singleObject	= 1,
	OtherSubClass_multipleObjects	= 2,
	OtherSubClass_bulkMaterial	= 3
} e_OtherSubClass;

/* OtherSubClass */
typedef long	 OtherSubClass_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_OtherSubClass_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_OtherSubClass;
asn_struct_free_f OtherSubClass_free;
asn_constr_check_f OtherSubClass_constraint;
ber_type_decoder_f OtherSubClass_decode_ber;
der_type_encoder_f OtherSubClass_encode_der;
per_type_decoder_f OtherSubClass_decode_uper;
per_type_encoder_f OtherSubClass_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _OtherSubClass_H_ */
#include <asn_internal.h>