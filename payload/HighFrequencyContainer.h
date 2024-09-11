/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "BasicVehicleContainerHighFrequency.h"
#include "RSUContainerHighFrequency.h"
#include <constr_CHOICE.h>
#ifndef	_HighFrequencyContainer_H_
#define	_HighFrequencyContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum HighFrequencyContainer_PR {
	HighFrequencyContainer_PR_NOTHING,	/* No components present */
	HighFrequencyContainer_PR_basicVehicleContainerHighFrequency,
	HighFrequencyContainer_PR_rsuContainerHighFrequency
	/* Extensions may appear below */
	
} HighFrequencyContainer_PR;

/* HighFrequencyContainer */
typedef struct HighFrequencyContainer {
	HighFrequencyContainer_PR present;
	union HighFrequencyContainer_u {
		BasicVehicleContainerHighFrequency_t	 basicVehicleContainerHighFrequency;
		RSUContainerHighFrequency_t	 rsuContainerHighFrequency;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} HighFrequencyContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_HighFrequencyContainer;
extern asn_CHOICE_specifics_t asn_SPC_HighFrequencyContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_HighFrequencyContainer_1[2];
extern asn_per_constraints_t asn_PER_type_HighFrequencyContainer_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _HighFrequencyContainer_H_ */
#include <asn_internal.h>
