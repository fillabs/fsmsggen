/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "EmbarkationStatus.h"
#include <constr_SEQUENCE.h>
#ifndef	_PublicTransportContainer_H_
#define	_PublicTransportContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PtActivation;

/* PublicTransportContainer */
typedef struct PublicTransportContainer {
	EmbarkationStatus_t	 embarkationStatus;
	struct PtActivation	*ptActivation;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PublicTransportContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PublicTransportContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_PublicTransportContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_PublicTransportContainer_1[2];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PtActivation.h"

#endif	/* _PublicTransportContainer_H_ */
#include <asn_internal.h>
