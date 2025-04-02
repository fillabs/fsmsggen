/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_LongitudinalLanePositionValue_H_
#define	_LongitudinalLanePositionValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LongitudinalLanePositionValue {
	LongitudinalLanePositionValue_outOfRange	= 32766,
	LongitudinalLanePositionValue_unavailable	= 32767
} e_LongitudinalLanePositionValue;

/* LongitudinalLanePositionValue */
typedef long	 LongitudinalLanePositionValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LongitudinalLanePositionValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LongitudinalLanePositionValue;
asn_struct_free_f LongitudinalLanePositionValue_free;
asn_constr_check_f LongitudinalLanePositionValue_constraint;
per_type_decoder_f LongitudinalLanePositionValue_decode_uper;
per_type_encoder_f LongitudinalLanePositionValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _LongitudinalLanePositionValue_H_ */
#include <asn_internal.h>
