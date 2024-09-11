/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_InterferenceManagementZoneType_H_
#define	_InterferenceManagementZoneType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum InterferenceManagementZoneType {
	InterferenceManagementZoneType_permanentCenDsrcTolling	= 0,
	InterferenceManagementZoneType_temporaryCenDsrcTolling	= 1,
	InterferenceManagementZoneType_unavailable	= 2,
	InterferenceManagementZoneType_urbanRail	= 3,
	InterferenceManagementZoneType_satelliteStation	= 4,
	InterferenceManagementZoneType_fixedLinks	= 5
	/*
	 * Enumeration is extensible
	 */
} e_InterferenceManagementZoneType;

/* InterferenceManagementZoneType */
typedef long	 InterferenceManagementZoneType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_InterferenceManagementZoneType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_InterferenceManagementZoneType;
extern const asn_INTEGER_specifics_t asn_SPC_InterferenceManagementZoneType_specs_1;
asn_struct_free_f InterferenceManagementZoneType_free;
asn_constr_check_f InterferenceManagementZoneType_constraint;
per_type_decoder_f InterferenceManagementZoneType_decode_uper;
per_type_encoder_f InterferenceManagementZoneType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _InterferenceManagementZoneType_H_ */
#include <asn_internal.h>
