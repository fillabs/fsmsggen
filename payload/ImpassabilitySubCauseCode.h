/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_ImpassabilitySubCauseCode_H_
#define	_ImpassabilitySubCauseCode_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ImpassabilitySubCauseCode {
	ImpassabilitySubCauseCode_unavailable	= 0,
	ImpassabilitySubCauseCode_flooding	= 1,
	ImpassabilitySubCauseCode_dangerOfAvalanches	= 2,
	ImpassabilitySubCauseCode_blastingOfAvalanches	= 3,
	ImpassabilitySubCauseCode_landslips	= 4,
	ImpassabilitySubCauseCode_chemicalSpillage	= 5,
	ImpassabilitySubCauseCode_winterClosure	= 6,
	ImpassabilitySubCauseCode_sinkhole	= 7,
	ImpassabilitySubCauseCode_earthquakeDamage	= 8,
	ImpassabilitySubCauseCode_fallenTrees	= 9,
	ImpassabilitySubCauseCode_rockfalls	= 10,
	ImpassabilitySubCauseCode_sewerOverflow	= 11,
	ImpassabilitySubCauseCode_stormDamage	= 12,
	ImpassabilitySubCauseCode_subsidence	= 13,
	ImpassabilitySubCauseCode_burstPipe	= 14,
	ImpassabilitySubCauseCode_burstWaterMain	= 15,
	ImpassabilitySubCauseCode_fallenPowerCables	= 16,
	ImpassabilitySubCauseCode_snowDrifts	= 17
} e_ImpassabilitySubCauseCode;

/* ImpassabilitySubCauseCode */
typedef long	 ImpassabilitySubCauseCode_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ImpassabilitySubCauseCode_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ImpassabilitySubCauseCode;
asn_struct_free_f ImpassabilitySubCauseCode_free;
asn_constr_check_f ImpassabilitySubCauseCode_constraint;
per_type_decoder_f ImpassabilitySubCauseCode_decode_uper;
per_type_encoder_f ImpassabilitySubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ImpassabilitySubCauseCode_H_ */
#include <asn_internal.h>
