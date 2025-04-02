/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "VAM-PDU-Descriptions"
 * 	found in "asn1/VAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "ItsPduHeader.h"
#ifndef	_ItsPduHeaderVam_H_
#define	_ItsPduHeaderVam_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ItsPduHeaderVam */
typedef ItsPduHeader_t	 ItsPduHeaderVam_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_ItsPduHeaderVam_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_ItsPduHeaderVam;
asn_struct_free_f ItsPduHeaderVam_free;
asn_constr_check_f ItsPduHeaderVam_constraint;
per_type_decoder_f ItsPduHeaderVam_decode_uper;
per_type_encoder_f ItsPduHeaderVam_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _ItsPduHeaderVam_H_ */
#include <asn_internal.h>
