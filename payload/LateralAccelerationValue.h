/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_LateralAccelerationValue_H_
#define	_LateralAccelerationValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LateralAccelerationValue {
	LateralAccelerationValue_negativeOutOfRange	= -160,
	LateralAccelerationValue_positiveOutOfRange	= 160,
	LateralAccelerationValue_unavailable	= 161
} e_LateralAccelerationValue;

/* LateralAccelerationValue */
typedef long	 LateralAccelerationValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LateralAccelerationValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LateralAccelerationValue;
asn_struct_free_f LateralAccelerationValue_free;
asn_constr_check_f LateralAccelerationValue_constraint;
ber_type_decoder_f LateralAccelerationValue_decode_ber;
der_type_encoder_f LateralAccelerationValue_encode_der;
per_type_decoder_f LateralAccelerationValue_decode_uper;
per_type_encoder_f LateralAccelerationValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _LateralAccelerationValue_H_ */
#include <asn_internal.h>
