/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_LongitudinalAccelerationValue_H_
#define	_LongitudinalAccelerationValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LongitudinalAccelerationValue {
	LongitudinalAccelerationValue_negativeOutOfRange	= -160,
	LongitudinalAccelerationValue_positiveOutOfRange	= 160,
	LongitudinalAccelerationValue_unavailable	= 161
} e_LongitudinalAccelerationValue;

/* LongitudinalAccelerationValue */
typedef long	 LongitudinalAccelerationValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LongitudinalAccelerationValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LongitudinalAccelerationValue;
asn_struct_free_f LongitudinalAccelerationValue_free;
asn_constr_check_f LongitudinalAccelerationValue_constraint;
per_type_decoder_f LongitudinalAccelerationValue_decode_uper;
per_type_encoder_f LongitudinalAccelerationValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _LongitudinalAccelerationValue_H_ */
#include <asn_internal.h>
