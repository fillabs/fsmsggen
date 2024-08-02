/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_VehicleRole_H_
#define	_VehicleRole_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VehicleRole {
	VehicleRole_default	= 0,
	VehicleRole_publicTransport	= 1,
	VehicleRole_specialTransport	= 2,
	VehicleRole_dangerousGoods	= 3,
	VehicleRole_roadWork	= 4,
	VehicleRole_rescue	= 5,
	VehicleRole_emergency	= 6,
	VehicleRole_safetyCar	= 7,
	VehicleRole_agriculture	= 8,
	VehicleRole_commercial	= 9,
	VehicleRole_military	= 10,
	VehicleRole_roadOperator	= 11,
	VehicleRole_taxi	= 12,
	VehicleRole_uvar	= 13,
	VehicleRole_rfu1	= 14,
	VehicleRole_rfu2	= 15
} e_VehicleRole;

/* VehicleRole */
typedef long	 VehicleRole_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VehicleRole_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VehicleRole;
extern const asn_INTEGER_specifics_t asn_SPC_VehicleRole_specs_1;
asn_struct_free_f VehicleRole_free;
asn_constr_check_f VehicleRole_constraint;
ber_type_decoder_f VehicleRole_decode_ber;
der_type_encoder_f VehicleRole_encode_der;
per_type_decoder_f VehicleRole_decode_uper;
per_type_encoder_f VehicleRole_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleRole_H_ */
#include <asn_internal.h>
