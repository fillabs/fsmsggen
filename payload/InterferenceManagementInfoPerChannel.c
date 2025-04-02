/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "InterferenceManagementInfoPerChannel.h"

asn_TYPE_member_t asn_MBR_InterferenceManagementInfoPerChannel_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct InterferenceManagementInfoPerChannel, interferenceManagementChannel),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterferenceManagementChannel,
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
		"interferenceManagementChannel"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct InterferenceManagementInfoPerChannel, interferenceManagementZoneType),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_InterferenceManagementZoneType,
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
		"interferenceManagementZoneType"
		},
	{ ATF_POINTER, 2, offsetof(struct InterferenceManagementInfoPerChannel, interferenceManagementMitigationType),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_MitigationForTechnologies,
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
		"interferenceManagementMitigationType"
		},
	{ ATF_POINTER, 1, offsetof(struct InterferenceManagementInfoPerChannel, expiryTime),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_TimestampIts,
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
		"expiryTime"
		},
};
static const int asn_MAP_InterferenceManagementInfoPerChannel_oms_1[] = { 2, 3 };
static const ber_tlv_tag_t asn_DEF_InterferenceManagementInfoPerChannel_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_InterferenceManagementInfoPerChannel_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* interferenceManagementChannel */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* interferenceManagementZoneType */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* interferenceManagementMitigationType */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* expiryTime */
};
asn_SEQUENCE_specifics_t asn_SPC_InterferenceManagementInfoPerChannel_specs_1 = {
	sizeof(struct InterferenceManagementInfoPerChannel),
	offsetof(struct InterferenceManagementInfoPerChannel, _asn_ctx),
	asn_MAP_InterferenceManagementInfoPerChannel_tag2el_1,
	4,	/* Count of tags in the map */
	asn_MAP_InterferenceManagementInfoPerChannel_oms_1,	/* Optional members */
	2, 0,	/* Root/Additions */
	4,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_InterferenceManagementInfoPerChannel = {
	"InterferenceManagementInfoPerChannel",
	"InterferenceManagementInfoPerChannel",
	&asn_OP_SEQUENCE,
	asn_DEF_InterferenceManagementInfoPerChannel_tags_1,
	sizeof(asn_DEF_InterferenceManagementInfoPerChannel_tags_1)
		/sizeof(asn_DEF_InterferenceManagementInfoPerChannel_tags_1[0]), /* 1 */
	asn_DEF_InterferenceManagementInfoPerChannel_tags_1,	/* Same as above */
	sizeof(asn_DEF_InterferenceManagementInfoPerChannel_tags_1)
		/sizeof(asn_DEF_InterferenceManagementInfoPerChannel_tags_1[0]), /* 1 */
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
	asn_MBR_InterferenceManagementInfoPerChannel_1,
	4,	/* Elements count */
	&asn_SPC_InterferenceManagementInfoPerChannel_specs_1	/* Additional specs */
};

