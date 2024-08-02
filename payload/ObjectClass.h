/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */


/* Including external dependencies */
#include "TrafficParticipantType.h"
#include "VruProfileAndSubprofile.h"
#include "VruClusterInformation.h"
#include "OtherSubClass.h"
#include <constr_CHOICE.h>
#ifndef	_ObjectClass_H_
#define	_ObjectClass_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ObjectClass_PR {
	ObjectClass_PR_NOTHING,	/* No components present */
	ObjectClass_PR_vehicleSubClass,
	ObjectClass_PR_vruSubClass,
	ObjectClass_PR_groupSubClass,
	ObjectClass_PR_otherSubClass
	/* Extensions may appear below */
	
} ObjectClass_PR;

/* ObjectClass */
typedef struct ObjectClass {
	ObjectClass_PR present;
	union ObjectClass_u {
		TrafficParticipantType_t	 vehicleSubClass;
		VruProfileAndSubprofile_t	 vruSubClass;
		VruClusterInformation_t	 groupSubClass;
		OtherSubClass_t	 otherSubClass;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ObjectClass_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ObjectClass;
extern asn_CHOICE_specifics_t asn_SPC_ObjectClass_specs_1;
extern asn_TYPE_member_t asn_MBR_ObjectClass_1[4];
extern asn_per_constraints_t asn_PER_type_ObjectClass_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _ObjectClass_H_ */
#include <asn_internal.h>
