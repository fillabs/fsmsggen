/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include "StationID.h"
#include "SequenceNumber.h"
#include <constr_SEQUENCE.h>
#ifndef	_ActionID_H_
#define	_ActionID_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ActionID */
typedef struct ActionID {
	StationID_t	 originatingStationID;
	SequenceNumber_t	 sequenceNumber;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ActionID_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ActionID;
extern asn_SEQUENCE_specifics_t asn_SPC_ActionID_specs_1;
extern asn_TYPE_member_t asn_MBR_ActionID_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _ActionID_H_ */
#include <asn_internal.h>
