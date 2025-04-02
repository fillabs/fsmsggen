/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "PathPredictedList.h"
#ifndef	_PathPredictionContainer_H_
#define	_PathPredictionContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PathPredictionContainer */
typedef PathPredictedList_t	 PathPredictionContainer_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_PathPredictionContainer_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_PathPredictionContainer;
asn_struct_free_f PathPredictionContainer_free;
asn_constr_check_f PathPredictionContainer_constraint;
per_type_decoder_f PathPredictionContainer_decode_uper;
per_type_encoder_f PathPredictionContainer_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PathPredictionContainer_H_ */
#include <asn_internal.h>
