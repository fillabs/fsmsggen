/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>
#ifndef	_InterferenceManagementZones_H_
#define	_InterferenceManagementZones_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct InterferenceManagementZone;

/* InterferenceManagementZones */
typedef struct InterferenceManagementZones {
	A_SEQUENCE_OF(struct InterferenceManagementZone) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterferenceManagementZones_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterferenceManagementZones;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "InterferenceManagementZone.h"

#endif	/* _InterferenceManagementZones_H_ */
#include <asn_internal.h>