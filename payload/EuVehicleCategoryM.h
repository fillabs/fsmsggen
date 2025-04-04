/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_EuVehicleCategoryM_H_
#define	_EuVehicleCategoryM_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum EuVehicleCategoryM {
	EuVehicleCategoryM_m1	= 0,
	EuVehicleCategoryM_m2	= 1,
	EuVehicleCategoryM_m3	= 2
} e_EuVehicleCategoryM;

/* EuVehicleCategoryM */
typedef long	 EuVehicleCategoryM_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_EuVehicleCategoryM_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_EuVehicleCategoryM;
extern const asn_INTEGER_specifics_t asn_SPC_EuVehicleCategoryM_specs_1;
asn_struct_free_f EuVehicleCategoryM_free;
asn_constr_check_f EuVehicleCategoryM_constraint;
per_type_decoder_f EuVehicleCategoryM_decode_uper;
per_type_encoder_f EuVehicleCategoryM_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _EuVehicleCategoryM_H_ */
#include <asn_internal.h>
