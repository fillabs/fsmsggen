/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_VehicleHeight2_H_
#define	_VehicleHeight2_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VehicleHeight2 {
	VehicleHeight2_outOfRange	= 61,
	VehicleHeight2_unavailable	= 62
} e_VehicleHeight2;

/* VehicleHeight2 */
typedef long	 VehicleHeight2_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_VehicleHeight2_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_VehicleHeight2;
asn_struct_free_f VehicleHeight2_free;
asn_constr_check_f VehicleHeight2_constraint;
ber_type_decoder_f VehicleHeight2_decode_ber;
der_type_encoder_f VehicleHeight2_encode_der;
per_type_decoder_f VehicleHeight2_decode_uper;
per_type_encoder_f VehicleHeight2_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleHeight2_H_ */
#include <asn_internal.h>
