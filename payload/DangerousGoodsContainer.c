/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/CAM-PDU-Descriptions.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */

#include "DangerousGoodsContainer.h"

asn_TYPE_member_t asn_MBR_DangerousGoodsContainer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct DangerousGoodsContainer, dangerousGoodsBasic),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_DangerousGoodsBasic,
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
		"dangerousGoodsBasic"
		},
};
static const ber_tlv_tag_t asn_DEF_DangerousGoodsContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_DangerousGoodsContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 } /* dangerousGoodsBasic */
};
asn_SEQUENCE_specifics_t asn_SPC_DangerousGoodsContainer_specs_1 = {
	sizeof(struct DangerousGoodsContainer),
	offsetof(struct DangerousGoodsContainer, _asn_ctx),
	asn_MAP_DangerousGoodsContainer_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_DangerousGoodsContainer = {
	"DangerousGoodsContainer",
	"DangerousGoodsContainer",
	&asn_OP_SEQUENCE,
	asn_DEF_DangerousGoodsContainer_tags_1,
	sizeof(asn_DEF_DangerousGoodsContainer_tags_1)
		/sizeof(asn_DEF_DangerousGoodsContainer_tags_1[0]), /* 1 */
	asn_DEF_DangerousGoodsContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_DangerousGoodsContainer_tags_1)
		/sizeof(asn_DEF_DangerousGoodsContainer_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_DangerousGoodsContainer_1,
	1,	/* Elements count */
	&asn_SPC_DangerousGoodsContainer_specs_1	/* Additional specs */
};

