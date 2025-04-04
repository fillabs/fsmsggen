/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_PositioningSolutionType_H_
#define	_PositioningSolutionType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PositioningSolutionType {
	PositioningSolutionType_noPositioningSolution	= 0,
	PositioningSolutionType_sGNSS	= 1,
	PositioningSolutionType_dGNSS	= 2,
	PositioningSolutionType_sGNSSplusDR	= 3,
	PositioningSolutionType_dGNSSplusDR	= 4,
	PositioningSolutionType_dR	= 5,
	/*
	 * Enumeration is extensible
	 */
	PositioningSolutionType_manuallyByOperator	= 6
} e_PositioningSolutionType;

/* PositioningSolutionType */
typedef long	 PositioningSolutionType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PositioningSolutionType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PositioningSolutionType;
extern const asn_INTEGER_specifics_t asn_SPC_PositioningSolutionType_specs_1;
asn_struct_free_f PositioningSolutionType_free;
asn_constr_check_f PositioningSolutionType_constraint;
per_type_decoder_f PositioningSolutionType_decode_uper;
per_type_encoder_f PositioningSolutionType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PositioningSolutionType_H_ */
#include <asn_internal.h>
