/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_StandardLength3b_H_
#define	_StandardLength3b_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum StandardLength3b {
	StandardLength3b_lessThan50m	= 0,
	StandardLength3b_lessThan100m	= 1,
	StandardLength3b_lessThan200m	= 2,
	StandardLength3b_lessThan500m	= 3,
	StandardLength3b_lessThan1000m	= 4,
	StandardLength3b_lessThan5km	= 5,
	StandardLength3b_lessThan10km	= 6,
	StandardLength3b_over10km	= 7
} e_StandardLength3b;

/* StandardLength3b */
typedef long	 StandardLength3b_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_StandardLength3b_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_StandardLength3b;
extern const asn_INTEGER_specifics_t asn_SPC_StandardLength3b_specs_1;
asn_struct_free_f StandardLength3b_free;
asn_constr_check_f StandardLength3b_constraint;
ber_type_decoder_f StandardLength3b_decode_ber;
der_type_encoder_f StandardLength3b_encode_der;
per_type_decoder_f StandardLength3b_decode_uper;
per_type_encoder_f StandardLength3b_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _StandardLength3b_H_ */
#include <asn_internal.h>
