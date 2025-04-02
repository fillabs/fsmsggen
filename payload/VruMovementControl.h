/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_VruMovementControl_H_
#define	_VruMovementControl_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VruMovementControl {
	VruMovementControl_unavailable	= 0,
	VruMovementControl_braking	= 1,
	VruMovementControl_hardBraking	= 2,
	VruMovementControl_stopPedaling	= 3,
	VruMovementControl_brakingAndStopPedaling	= 4,
	VruMovementControl_hardBrakingAndStopPedaling	= 5,
	VruMovementControl_noReaction	= 6
} e_VruMovementControl;

/* VruMovementControl */
typedef long	 VruMovementControl_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VruMovementControl_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VruMovementControl;
asn_struct_free_f VruMovementControl_free;
asn_constr_check_f VruMovementControl_constraint;
per_type_decoder_f VruMovementControl_decode_uper;
per_type_encoder_f VruMovementControl_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VruMovementControl_H_ */
#include <asn_internal.h>
