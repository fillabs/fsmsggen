/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_VehicleLengthConfidenceIndication_H_
#define	_VehicleLengthConfidenceIndication_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VehicleLengthConfidenceIndication {
	VehicleLengthConfidenceIndication_noTrailerPresent	= 0,
	VehicleLengthConfidenceIndication_trailerPresentWithKnownLength	= 1,
	VehicleLengthConfidenceIndication_trailerPresentWithUnknownLength	= 2,
	VehicleLengthConfidenceIndication_trailerPresenceIsUnknown	= 3,
	VehicleLengthConfidenceIndication_unavailable	= 4
} e_VehicleLengthConfidenceIndication;

/* VehicleLengthConfidenceIndication */
typedef long	 VehicleLengthConfidenceIndication_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VehicleLengthConfidenceIndication_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VehicleLengthConfidenceIndication;
extern const asn_INTEGER_specifics_t asn_SPC_VehicleLengthConfidenceIndication_specs_1;
asn_struct_free_f VehicleLengthConfidenceIndication_free;
asn_constr_check_f VehicleLengthConfidenceIndication_constraint;
ber_type_decoder_f VehicleLengthConfidenceIndication_decode_ber;
der_type_encoder_f VehicleLengthConfidenceIndication_encode_der;
per_type_decoder_f VehicleLengthConfidenceIndication_decode_uper;
per_type_encoder_f VehicleLengthConfidenceIndication_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleLengthConfidenceIndication_H_ */
#include <asn_internal.h>
