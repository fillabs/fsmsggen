/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_HardShoulderStatus_H_
#define	_HardShoulderStatus_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HardShoulderStatus {
	HardShoulderStatus_availableForStopping	= 0,
	HardShoulderStatus_closed	= 1,
	HardShoulderStatus_availableForDriving	= 2
} e_HardShoulderStatus;

/* HardShoulderStatus */
typedef long	 HardShoulderStatus_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_HardShoulderStatus_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_HardShoulderStatus;
extern const asn_INTEGER_specifics_t asn_SPC_HardShoulderStatus_specs_1;
asn_struct_free_f HardShoulderStatus_free;
asn_constr_check_f HardShoulderStatus_constraint;
per_type_decoder_f HardShoulderStatus_decode_uper;
per_type_encoder_f HardShoulderStatus_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _HardShoulderStatus_H_ */
#include <asn_internal.h>
