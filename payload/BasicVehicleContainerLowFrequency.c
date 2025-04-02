/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "BasicVehicleContainerLowFrequency.h"

asn_TYPE_member_t asn_MBR_BasicVehicleContainerLowFrequency_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct BasicVehicleContainerLowFrequency, vehicleRole),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_VehicleRole,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"vehicleRole"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BasicVehicleContainerLowFrequency, exteriorLights),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ExteriorLights,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"exteriorLights"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct BasicVehicleContainerLowFrequency, pathHistory),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Path,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"pathHistory"
		},
};
static const ber_tlv_tag_t asn_DEF_BasicVehicleContainerLowFrequency_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_BasicVehicleContainerLowFrequency_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* vehicleRole */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* exteriorLights */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* pathHistory */
};
asn_SEQUENCE_specifics_t asn_SPC_BasicVehicleContainerLowFrequency_specs_1 = {
	sizeof(struct BasicVehicleContainerLowFrequency),
	offsetof(struct BasicVehicleContainerLowFrequency, _asn_ctx),
	asn_MAP_BasicVehicleContainerLowFrequency_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_BasicVehicleContainerLowFrequency = {
	"BasicVehicleContainerLowFrequency",
	"BasicVehicleContainerLowFrequency",
	&asn_OP_SEQUENCE,
	asn_DEF_BasicVehicleContainerLowFrequency_tags_1,
	sizeof(asn_DEF_BasicVehicleContainerLowFrequency_tags_1)
		/sizeof(asn_DEF_BasicVehicleContainerLowFrequency_tags_1[0]), /* 1 */
	asn_DEF_BasicVehicleContainerLowFrequency_tags_1,	/* Same as above */
	sizeof(asn_DEF_BasicVehicleContainerLowFrequency_tags_1)
		/sizeof(asn_DEF_BasicVehicleContainerLowFrequency_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_BasicVehicleContainerLowFrequency_1,
	3,	/* Elements count */
	&asn_SPC_BasicVehicleContainerLowFrequency_specs_1	/* Additional specs */
};

