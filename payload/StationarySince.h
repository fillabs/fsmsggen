/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include <NativeEnumerated.h>
#ifndef	_StationarySince_H_
#define	_StationarySince_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum StationarySince {
	StationarySince_lessThan1Minute	= 0,
	StationarySince_lessThan2Minutes	= 1,
	StationarySince_lessThan15Minutes	= 2,
	StationarySince_equalOrGreater15Minutes	= 3
} e_StationarySince;

/* StationarySince */
typedef long	 StationarySince_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_StationarySince_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_StationarySince;
extern const asn_INTEGER_specifics_t asn_SPC_StationarySince_specs_1;
asn_struct_free_f StationarySince_free;
asn_constr_check_f StationarySince_constraint;
per_type_decoder_f StationarySince_decode_uper;
per_type_encoder_f StationarySince_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _StationarySince_H_ */
#include <asn_internal.h>
