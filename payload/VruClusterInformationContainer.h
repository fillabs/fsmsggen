/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "VAM-PDU-Descriptions"
 * 	found in "asn1/VAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "VruClusterInformation.h"
#include <constr_SEQUENCE.h>
#ifndef	_VruClusterInformationContainer_H_
#define	_VruClusterInformationContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* VruClusterInformationContainer */
typedef struct VruClusterInformationContainer {
	VruClusterInformation_t	 vruClusterInformation;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VruClusterInformationContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VruClusterInformationContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_VruClusterInformationContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_VruClusterInformationContainer_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _VruClusterInformationContainer_H_ */
#include <asn_internal.h>
