/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CPM-PDU-Descriptions"
 * 	found in "asn1/CPM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */


/* Including external dependencies */
#include "CpmContainerId.h"
#include <ANY.h>
#include <asn_ioc.h>
#include "OriginatingVehicleContainer.h"
#include "OriginatingRsuContainer.h"
#include "SensorInformationContainer.h"
#include "PerceptionRegionContainer.h"
#include "PerceivedObjectContainer.h"
#include <OPEN_TYPE.h>
#include <constr_CHOICE.h>
#include <constr_SEQUENCE.h>
#ifndef	_WrappedCpmContainer_H_
#define	_WrappedCpmContainer_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum WrappedCpmContainer__containerData_PR {
	WrappedCpmContainer__containerData_PR_NOTHING,	/* No components present */
	WrappedCpmContainer__containerData_PR_OriginatingVehicleContainer,
	WrappedCpmContainer__containerData_PR_OriginatingRsuContainer,
	WrappedCpmContainer__containerData_PR_SensorInformationContainer,
	WrappedCpmContainer__containerData_PR_PerceptionRegionContainer,
	WrappedCpmContainer__containerData_PR_PerceivedObjectContainer
} WrappedCpmContainer__containerData_PR;

/* WrappedCpmContainer */
typedef struct WrappedCpmContainer {
	CpmContainerId_t	 containerId;
	struct WrappedCpmContainer__containerData {
		WrappedCpmContainer__containerData_PR present;
		union WrappedCpmContainer__containerData_u {
			OriginatingVehicleContainer_t	 OriginatingVehicleContainer;
			OriginatingRsuContainer_t	 OriginatingRsuContainer;
			SensorInformationContainer_t	 SensorInformationContainer;
			PerceptionRegionContainer_t	 PerceptionRegionContainer;
			PerceivedObjectContainer_t	 PerceivedObjectContainer;
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} containerData;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} WrappedCpmContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_WrappedCpmContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_WrappedCpmContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_WrappedCpmContainer_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _WrappedCpmContainer_H_ */
#include <asn_internal.h>
