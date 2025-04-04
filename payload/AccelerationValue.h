/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_AccelerationValue_H_
#define	_AccelerationValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AccelerationValue {
	AccelerationValue_negativeOutOfRange	= -160,
	AccelerationValue_positiveOutOfRange	= 160,
	AccelerationValue_unavailable	= 161
} e_AccelerationValue;

/* AccelerationValue */
typedef long	 AccelerationValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AccelerationValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AccelerationValue;
asn_struct_free_f AccelerationValue_free;
asn_constr_check_f AccelerationValue_constraint;
per_type_decoder_f AccelerationValue_decode_uper;
per_type_encoder_f AccelerationValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AccelerationValue_H_ */
#include <asn_internal.h>
