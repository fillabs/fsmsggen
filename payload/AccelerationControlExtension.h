/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <BIT_STRING.h>
#ifndef	_AccelerationControlExtension_H_
#define	_AccelerationControlExtension_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AccelerationControlExtension {
	AccelerationControlExtension_rearCrossTrafficAlertEngaged	= 0,
	AccelerationControlExtension_emergencyBrakeRearEngaged	= 1,
	AccelerationControlExtension_assistedParkingLongitudinalEngaged	= 2
} e_AccelerationControlExtension;

/* AccelerationControlExtension */
typedef BIT_STRING_t	 AccelerationControlExtension_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AccelerationControlExtension_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AccelerationControlExtension;
asn_struct_free_f AccelerationControlExtension_free;
asn_constr_check_f AccelerationControlExtension_constraint;
per_type_decoder_f AccelerationControlExtension_decode_uper;
per_type_encoder_f AccelerationControlExtension_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AccelerationControlExtension_H_ */
#include <asn_internal.h>
