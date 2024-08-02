/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_EuVehicleCategoryN_H_
#define	_EuVehicleCategoryN_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EuVehicleCategoryN {
	EuVehicleCategoryN_n1	= 0,
	EuVehicleCategoryN_n2	= 1,
	EuVehicleCategoryN_n3	= 2
} e_EuVehicleCategoryN;

/* EuVehicleCategoryN */
typedef long	 EuVehicleCategoryN_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_EuVehicleCategoryN_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_EuVehicleCategoryN;
extern const asn_INTEGER_specifics_t asn_SPC_EuVehicleCategoryN_specs_1;
asn_struct_free_f EuVehicleCategoryN_free;
asn_constr_check_f EuVehicleCategoryN_constraint;
ber_type_decoder_f EuVehicleCategoryN_decode_ber;
der_type_encoder_f EuVehicleCategoryN_encode_der;
per_type_decoder_f EuVehicleCategoryN_decode_uper;
per_type_encoder_f EuVehicleCategoryN_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _EuVehicleCategoryN_H_ */
#include <asn_internal.h>
