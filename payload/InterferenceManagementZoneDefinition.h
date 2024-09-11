/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "Latitude.h"
#include "Longitude.h"
#include "ProtectedZoneId.h"
#include <constr_SEQUENCE.h>
#ifndef	_InterferenceManagementZoneDefinition_H_
#define	_InterferenceManagementZoneDefinition_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Shape;

/* InterferenceManagementZoneDefinition */
typedef struct InterferenceManagementZoneDefinition {
	Latitude_t	 interferenceManagementZoneLatitude;
	Longitude_t	 interferenceManagementZoneLongitude;
	ProtectedZoneId_t	*interferenceManagementZoneId;	/* OPTIONAL */
	struct Shape	*interferenceManagementZoneShape;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} InterferenceManagementZoneDefinition_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_InterferenceManagementZoneDefinition;
extern asn_SEQUENCE_specifics_t asn_SPC_InterferenceManagementZoneDefinition_specs_1;
extern asn_TYPE_member_t asn_MBR_InterferenceManagementZoneDefinition_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Shape.h"

#endif	/* _InterferenceManagementZoneDefinition_H_ */
#include <asn_internal.h>
