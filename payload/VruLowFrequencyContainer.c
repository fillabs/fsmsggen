/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "VAM-PDU-Descriptions"
 * 	found in "asn1/VAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "VruLowFrequencyContainer.h"

asn_TYPE_member_t asn_MBR_VruLowFrequencyContainer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct VruLowFrequencyContainer, profileAndSubprofile),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_VruProfileAndSubprofile,
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
		"profileAndSubprofile"
		},
	{ ATF_POINTER, 2, offsetof(struct VruLowFrequencyContainer, sizeClass),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_VruSizeClass,
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
		"sizeClass"
		},
	{ ATF_POINTER, 1, offsetof(struct VruLowFrequencyContainer, exteriorLights),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_VruExteriorLights,
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
};
static const int asn_MAP_VruLowFrequencyContainer_oms_1[] = { 1, 2 };
static const ber_tlv_tag_t asn_DEF_VruLowFrequencyContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_VruLowFrequencyContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* profileAndSubprofile */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* sizeClass */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* exteriorLights */
};
asn_SEQUENCE_specifics_t asn_SPC_VruLowFrequencyContainer_specs_1 = {
	sizeof(struct VruLowFrequencyContainer),
	offsetof(struct VruLowFrequencyContainer, _asn_ctx),
	asn_MAP_VruLowFrequencyContainer_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_VruLowFrequencyContainer_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	3,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_VruLowFrequencyContainer = {
	"VruLowFrequencyContainer",
	"VruLowFrequencyContainer",
	&asn_OP_SEQUENCE,
	asn_DEF_VruLowFrequencyContainer_tags_1,
	sizeof(asn_DEF_VruLowFrequencyContainer_tags_1)
		/sizeof(asn_DEF_VruLowFrequencyContainer_tags_1[0]), /* 1 */
	asn_DEF_VruLowFrequencyContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_VruLowFrequencyContainer_tags_1)
		/sizeof(asn_DEF_VruLowFrequencyContainer_tags_1[0]), /* 1 */
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
	asn_MBR_VruLowFrequencyContainer_1,
	3,	/* Elements count */
	&asn_SPC_VruLowFrequencyContainer_specs_1	/* Additional specs */
};

