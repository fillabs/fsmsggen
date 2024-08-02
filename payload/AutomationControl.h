/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <BIT_STRING.h>
#ifndef	_AutomationControl_H_
#define	_AutomationControl_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AutomationControl {
	AutomationControl_emergencySteeringSystemEngaged	= 0,
	AutomationControl_autonomousEmergencySteeringEngaged	= 1,
	AutomationControl_automaticLaneChangeEngaged	= 2,
	AutomationControl_laneKeepingAssistEngaged	= 3,
	AutomationControl_assistedParkingLateralEngaged	= 4,
	AutomationControl_emergencyAssistEngaged	= 5
} e_AutomationControl;

/* AutomationControl */
typedef BIT_STRING_t	 AutomationControl_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_AutomationControl_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_AutomationControl;
asn_struct_free_f AutomationControl_free;
asn_constr_check_f AutomationControl_constraint;
ber_type_decoder_f AutomationControl_decode_ber;
der_type_encoder_f AutomationControl_encode_der;
per_type_decoder_f AutomationControl_decode_uper;
per_type_encoder_f AutomationControl_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AutomationControl_H_ */
#include <asn_internal.h>