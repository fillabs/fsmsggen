/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_EuVehicleCategoryO_H_
#define	_EuVehicleCategoryO_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EuVehicleCategoryO {
	EuVehicleCategoryO_o1	= 0,
	EuVehicleCategoryO_o2	= 1,
	EuVehicleCategoryO_o3	= 2,
	EuVehicleCategoryO_o4	= 3
} e_EuVehicleCategoryO;

/* EuVehicleCategoryO */
typedef long	 EuVehicleCategoryO_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_EuVehicleCategoryO_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_EuVehicleCategoryO;
extern const asn_INTEGER_specifics_t asn_SPC_EuVehicleCategoryO_specs_1;
asn_struct_free_f EuVehicleCategoryO_free;
asn_constr_check_f EuVehicleCategoryO_constraint;
per_type_decoder_f EuVehicleCategoryO_decode_uper;
per_type_encoder_f EuVehicleCategoryO_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _EuVehicleCategoryO_H_ */
#include <asn_internal.h>
