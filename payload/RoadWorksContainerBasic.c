/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "RoadWorksContainerBasic.h"

asn_TYPE_member_t asn_MBR_RoadWorksContainerBasic_1[] = {
	{ ATF_POINTER, 1, offsetof(struct RoadWorksContainerBasic, roadworksSubCauseCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RoadworksSubCauseCode,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"roadworksSubCauseCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct RoadWorksContainerBasic, lightBarSirenInUse),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LightBarSirenInUse,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"lightBarSirenInUse"
		},
	{ ATF_POINTER, 1, offsetof(struct RoadWorksContainerBasic, closedLanes),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ClosedLanes,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"closedLanes"
		},
};
static const int asn_MAP_RoadWorksContainerBasic_oms_1[] = { 0, 2 };
static const ber_tlv_tag_t asn_DEF_RoadWorksContainerBasic_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RoadWorksContainerBasic_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* roadworksSubCauseCode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* lightBarSirenInUse */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* closedLanes */
};
asn_SEQUENCE_specifics_t asn_SPC_RoadWorksContainerBasic_specs_1 = {
	sizeof(struct RoadWorksContainerBasic),
	offsetof(struct RoadWorksContainerBasic, _asn_ctx),
	asn_MAP_RoadWorksContainerBasic_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_RoadWorksContainerBasic_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RoadWorksContainerBasic = {
	"RoadWorksContainerBasic",
	"RoadWorksContainerBasic",
	&asn_OP_SEQUENCE,
	asn_DEF_RoadWorksContainerBasic_tags_1,
	sizeof(asn_DEF_RoadWorksContainerBasic_tags_1)
		/sizeof(asn_DEF_RoadWorksContainerBasic_tags_1[0]), /* 1 */
	asn_DEF_RoadWorksContainerBasic_tags_1,	/* Same as above */
	sizeof(asn_DEF_RoadWorksContainerBasic_tags_1)
		/sizeof(asn_DEF_RoadWorksContainerBasic_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_RoadWorksContainerBasic_1,
	3,	/* Elements count */
	&asn_SPC_RoadWorksContainerBasic_specs_1	/* Additional specs */
};

