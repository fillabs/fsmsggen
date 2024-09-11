/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "VAM-PDU-Descriptions"
 * 	found in "asn1/VAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "VruProfileAndSubprofile.h"
#include "VruSizeClass.h"
#include <constr_SEQUENCE.h>
#ifndef	_VruLowFrequencyContainer_H_
#define	_VruLowFrequencyContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct VruExteriorLights;

/* VruLowFrequencyContainer */
typedef struct VruLowFrequencyContainer {
	VruProfileAndSubprofile_t	 profileAndSubprofile;
	VruSizeClass_t	*sizeClass;	/* OPTIONAL */
	struct VruExteriorLights	*exteriorLights;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VruLowFrequencyContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VruLowFrequencyContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_VruLowFrequencyContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_VruLowFrequencyContainer_1[3];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "VruExteriorLights.h"

#endif	/* _VruLowFrequencyContainer_H_ */
#include <asn_internal.h>
