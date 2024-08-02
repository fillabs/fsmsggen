/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_VehicleMass_H_
#define	_VehicleMass_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VehicleMass {
	VehicleMass_outOfRange	= 1023,
	VehicleMass_unavailable	= 1024
} e_VehicleMass;

/* VehicleMass */
typedef long	 VehicleMass_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VehicleMass_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VehicleMass;
asn_struct_free_f VehicleMass_free;
asn_constr_check_f VehicleMass_constraint;
ber_type_decoder_f VehicleMass_decode_ber;
der_type_encoder_f VehicleMass_encode_der;
per_type_decoder_f VehicleMass_decode_uper;
per_type_encoder_f VehicleMass_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleMass_H_ */
#include <asn_internal.h>
