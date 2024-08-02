/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_AccidentSubCauseCode_H_
#define	_AccidentSubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AccidentSubCauseCode {
	AccidentSubCauseCode_unavailable	= 0,
	AccidentSubCauseCode_multiVehicleAccident	= 1,
	AccidentSubCauseCode_heavyAccident	= 2,
	AccidentSubCauseCode_accidentInvolvingLorry	= 3,
	AccidentSubCauseCode_accidentInvolvingBus	= 4,
	AccidentSubCauseCode_accidentInvolvingHazardousMaterials	= 5,
	AccidentSubCauseCode_accidentOnOppositeLane	= 6,
	AccidentSubCauseCode_unsecuredAccident	= 7,
	AccidentSubCauseCode_assistanceRequested	= 8
} e_AccidentSubCauseCode;

/* AccidentSubCauseCode */
typedef long	 AccidentSubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AccidentSubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AccidentSubCauseCode;
asn_struct_free_f AccidentSubCauseCode_free;
asn_constr_check_f AccidentSubCauseCode_constraint;
ber_type_decoder_f AccidentSubCauseCode_decode_ber;
der_type_encoder_f AccidentSubCauseCode_encode_der;
per_type_decoder_f AccidentSubCauseCode_decode_uper;
per_type_encoder_f AccidentSubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AccidentSubCauseCode_H_ */
#include <asn_internal.h>
