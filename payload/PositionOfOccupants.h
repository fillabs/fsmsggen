/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <BIT_STRING.h>
#ifndef	_PositionOfOccupants_H_
#define	_PositionOfOccupants_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PositionOfOccupants {
	PositionOfOccupants_row1LeftOccupied	= 0,
	PositionOfOccupants_row1RightOccupied	= 1,
	PositionOfOccupants_row1MidOccupied	= 2,
	PositionOfOccupants_row1NotDetectable	= 3,
	PositionOfOccupants_row1NotPresent	= 4,
	PositionOfOccupants_row2LeftOccupied	= 5,
	PositionOfOccupants_row2RightOccupied	= 6,
	PositionOfOccupants_row2MidOccupied	= 7,
	PositionOfOccupants_row2NotDetectable	= 8,
	PositionOfOccupants_row2NotPresent	= 9,
	PositionOfOccupants_row3LeftOccupied	= 10,
	PositionOfOccupants_row3RightOccupied	= 11,
	PositionOfOccupants_row3MidOccupied	= 12,
	PositionOfOccupants_row3NotDetectable	= 13,
	PositionOfOccupants_row3NotPresent	= 14,
	PositionOfOccupants_row4LeftOccupied	= 15,
	PositionOfOccupants_row4RightOccupied	= 16,
	PositionOfOccupants_row4MidOccupied	= 17,
	PositionOfOccupants_row4NotDetectable	= 18,
	PositionOfOccupants_row4NotPresent	= 19
} e_PositionOfOccupants;

/* PositionOfOccupants */
typedef BIT_STRING_t	 PositionOfOccupants_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PositionOfOccupants_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PositionOfOccupants;
asn_struct_free_f PositionOfOccupants_free;
asn_constr_check_f PositionOfOccupants_constraint;
per_type_decoder_f PositionOfOccupants_decode_uper;
per_type_encoder_f PositionOfOccupants_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PositionOfOccupants_H_ */
#include <asn_internal.h>
