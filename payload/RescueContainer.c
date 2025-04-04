/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "RescueContainer.h"

asn_TYPE_member_t asn_MBR_RescueContainer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RescueContainer, lightBarSirenInUse),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
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
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"lightBarSirenInUse"
		},
};
static const ber_tlv_tag_t asn_DEF_RescueContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RescueContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* lightBarSirenInUse */
};
asn_SEQUENCE_specifics_t asn_SPC_RescueContainer_specs_1 = {
	sizeof(struct RescueContainer),
	offsetof(struct RescueContainer, _asn_ctx),
	asn_MAP_RescueContainer_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_RescueContainer = {
	"RescueContainer",
	"RescueContainer",
	&asn_OP_SEQUENCE,
	asn_DEF_RescueContainer_tags_1,
	sizeof(asn_DEF_RescueContainer_tags_1)
		/sizeof(asn_DEF_RescueContainer_tags_1[0]), /* 1 */
	asn_DEF_RescueContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_RescueContainer_tags_1)
		/sizeof(asn_DEF_RescueContainer_tags_1[0]), /* 1 */
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
	asn_MBR_RescueContainer_1,
	1,	/* Elements count */
	&asn_SPC_RescueContainer_specs_1	/* Additional specs */
};

