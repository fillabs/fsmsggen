/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_AccessTechnologyClass_H_
#define	_AccessTechnologyClass_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AccessTechnologyClass {
	AccessTechnologyClass_any	= 0,
	AccessTechnologyClass_itsg5Class	= 1,
	AccessTechnologyClass_ltev2xClass	= 2,
	AccessTechnologyClass_nrv2xClass	= 3
	/*
	 * Enumeration is extensible
	 */
} e_AccessTechnologyClass;

/* AccessTechnologyClass */
typedef long	 AccessTechnologyClass_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AccessTechnologyClass_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AccessTechnologyClass;
extern const asn_INTEGER_specifics_t asn_SPC_AccessTechnologyClass_specs_1;
asn_struct_free_f AccessTechnologyClass_free;
asn_constr_check_f AccessTechnologyClass_constraint;
ber_type_decoder_f AccessTechnologyClass_decode_ber;
der_type_encoder_f AccessTechnologyClass_encode_der;
per_type_decoder_f AccessTechnologyClass_decode_uper;
per_type_encoder_f AccessTechnologyClass_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AccessTechnologyClass_H_ */
#include <asn_internal.h>
