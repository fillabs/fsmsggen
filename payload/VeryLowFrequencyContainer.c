/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "VeryLowFrequencyContainer.h"

asn_TYPE_member_t asn_MBR_VeryLowFrequencyContainer_1[] = {
	{ ATF_POINTER, 3, offsetof(struct VeryLowFrequencyContainer, vehicleHeight),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_VehicleHeight2,
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
		"vehicleHeight"
		},
	{ ATF_POINTER, 2, offsetof(struct VeryLowFrequencyContainer, wiperStatus),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_WiperStatus,
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
		"wiperStatus"
		},
	{ ATF_POINTER, 1, offsetof(struct VeryLowFrequencyContainer, brakeControl),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BrakeControl,
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
		"brakeControl"
		},
};
static const int asn_MAP_VeryLowFrequencyContainer_oms_1[] = { 0, 1, 2 };
static const ber_tlv_tag_t asn_DEF_VeryLowFrequencyContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_VeryLowFrequencyContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* vehicleHeight */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* wiperStatus */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* brakeControl */
};
asn_SEQUENCE_specifics_t asn_SPC_VeryLowFrequencyContainer_specs_1 = {
	sizeof(struct VeryLowFrequencyContainer),
	offsetof(struct VeryLowFrequencyContainer, _asn_ctx),
	asn_MAP_VeryLowFrequencyContainer_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_VeryLowFrequencyContainer_oms_1,	/* Optional members */
	3, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_VeryLowFrequencyContainer = {
	"VeryLowFrequencyContainer",
	"VeryLowFrequencyContainer",
	&asn_OP_SEQUENCE,
	asn_DEF_VeryLowFrequencyContainer_tags_1,
	sizeof(asn_DEF_VeryLowFrequencyContainer_tags_1)
		/sizeof(asn_DEF_VeryLowFrequencyContainer_tags_1[0]), /* 1 */
	asn_DEF_VeryLowFrequencyContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_VeryLowFrequencyContainer_tags_1)
		/sizeof(asn_DEF_VeryLowFrequencyContainer_tags_1[0]), /* 1 */
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
	asn_MBR_VeryLowFrequencyContainer_1,
	3,	/* Elements count */
	&asn_SPC_VeryLowFrequencyContainer_specs_1	/* Additional specs */
};

