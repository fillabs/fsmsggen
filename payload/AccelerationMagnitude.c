/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "AccelerationMagnitude.h"

asn_TYPE_member_t asn_MBR_AccelerationMagnitude_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct AccelerationMagnitude, accelerationMagnitudeValue),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AccelerationMagnitudeValue,
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
		"accelerationMagnitudeValue"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct AccelerationMagnitude, accelerationConfidence),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AccelerationConfidence,
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
		"accelerationConfidence"
		},
};
static const ber_tlv_tag_t asn_DEF_AccelerationMagnitude_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_AccelerationMagnitude_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* accelerationMagnitudeValue */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* accelerationConfidence */
};
asn_SEQUENCE_specifics_t asn_SPC_AccelerationMagnitude_specs_1 = {
	sizeof(struct AccelerationMagnitude),
	offsetof(struct AccelerationMagnitude, _asn_ctx),
	asn_MAP_AccelerationMagnitude_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_AccelerationMagnitude = {
	"AccelerationMagnitude",
	"AccelerationMagnitude",
	&asn_OP_SEQUENCE,
	asn_DEF_AccelerationMagnitude_tags_1,
	sizeof(asn_DEF_AccelerationMagnitude_tags_1)
		/sizeof(asn_DEF_AccelerationMagnitude_tags_1[0]), /* 1 */
	asn_DEF_AccelerationMagnitude_tags_1,	/* Same as above */
	sizeof(asn_DEF_AccelerationMagnitude_tags_1)
		/sizeof(asn_DEF_AccelerationMagnitude_tags_1[0]), /* 1 */
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
	asn_MBR_AccelerationMagnitude_1,
	2,	/* Elements count */
	&asn_SPC_AccelerationMagnitude_specs_1	/* Additional specs */
};

