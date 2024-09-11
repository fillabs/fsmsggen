/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "VruSubProfilePedestrian.h"
#include "VruSubProfileBicyclist.h"
#include "VruSubProfileMotorcyclist.h"
#include "VruSubProfileAnimal.h"
#include <constr_CHOICE.h>
#ifndef	_VruProfileAndSubprofile_H_
#define	_VruProfileAndSubprofile_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VruProfileAndSubprofile_PR {
	VruProfileAndSubprofile_PR_NOTHING,	/* No components present */
	VruProfileAndSubprofile_PR_pedestrian,
	VruProfileAndSubprofile_PR_bicyclistAndLightVruVehicle,
	VruProfileAndSubprofile_PR_motorcyclist,
	VruProfileAndSubprofile_PR_animal
	/* Extensions may appear below */
	
} VruProfileAndSubprofile_PR;

/* VruProfileAndSubprofile */
typedef struct VruProfileAndSubprofile {
	VruProfileAndSubprofile_PR present;
	union VruProfileAndSubprofile_u {
		VruSubProfilePedestrian_t	 pedestrian;
		VruSubProfileBicyclist_t	 bicyclistAndLightVruVehicle;
		VruSubProfileMotorcyclist_t	 motorcyclist;
		VruSubProfileAnimal_t	 animal;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} VruProfileAndSubprofile_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VruProfileAndSubprofile;
extern asn_CHOICE_specifics_t asn_SPC_VruProfileAndSubprofile_specs_1;
extern asn_TYPE_member_t asn_MBR_VruProfileAndSubprofile_1[4];
extern asn_per_constraints_t asn_PER_type_VruProfileAndSubprofile_constr_1;

#ifdef __cplusplus
}
#endif

#endif	/* _VruProfileAndSubprofile_H_ */
#include <asn_internal.h>
