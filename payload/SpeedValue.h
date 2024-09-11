/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_SpeedValue_H_
#define	_SpeedValue_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SpeedValue {
	SpeedValue_standstill	= 0,
	SpeedValue_outOfRange	= 16382,
	SpeedValue_unavailable	= 16383
} e_SpeedValue;

/* SpeedValue */
typedef long	 SpeedValue_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_SpeedValue_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_SpeedValue;
asn_struct_free_f SpeedValue_free;
asn_constr_check_f SpeedValue_constraint;
per_type_decoder_f SpeedValue_decode_uper;
per_type_encoder_f SpeedValue_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _SpeedValue_H_ */
#include <asn_internal.h>
