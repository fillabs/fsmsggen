/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_LanePosition_H_
#define	_LanePosition_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum LanePosition {
	LanePosition_offTheRoad	= -1,
	LanePosition_innerHardShoulder	= 0,
	LanePosition_outerHardShoulder	= 14
} e_LanePosition;

/* LanePosition */
typedef long	 LanePosition_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_LanePosition_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_LanePosition;
asn_struct_free_f LanePosition_free;
asn_constr_check_f LanePosition_constraint;
per_type_decoder_f LanePosition_decode_uper;
per_type_encoder_f LanePosition_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _LanePosition_H_ */
#include <asn_internal.h>
