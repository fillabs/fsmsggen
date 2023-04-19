/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_ProtectedZoneType_H_
#define	_ProtectedZoneType_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ProtectedZoneType {
	ProtectedZoneType_permanentCenDsrcTolling	= 0,
	/*
	 * Enumeration is extensible
	 */
	ProtectedZoneType_temporaryCenDsrcTolling	= 1
} e_ProtectedZoneType;

/* ProtectedZoneType */
typedef long	 ProtectedZoneType_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ProtectedZoneType_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ProtectedZoneType;
extern const asn_INTEGER_specifics_t asn_SPC_ProtectedZoneType_specs_1;
asn_struct_free_f ProtectedZoneType_free;
asn_struct_print_f ProtectedZoneType_print;
asn_constr_check_f ProtectedZoneType_constraint;
ber_type_decoder_f ProtectedZoneType_decode_ber;
der_type_encoder_f ProtectedZoneType_encode_der;
jer_type_encoder_f ProtectedZoneType_encode_jer;
per_type_decoder_f ProtectedZoneType_decode_uper;
per_type_encoder_f ProtectedZoneType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ProtectedZoneType_H_ */
#include <asn_internal.h>
