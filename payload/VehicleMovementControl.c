/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "VehicleMovementControl.h"

asn_TYPE_member_t asn_MBR_VehicleMovementControl_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct VehicleMovementControl, accelerationPedalStatus),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PedalStatus,
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
		"accelerationPedalStatus"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct VehicleMovementControl, brakePedalStatus),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PedalStatus,
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
		"brakePedalStatus"
		},
	{ ATF_POINTER, 4, offsetof(struct VehicleMovementControl, saeAutomationLevel),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SaeAutomationLevel,
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
		"saeAutomationLevel"
		},
	{ ATF_POINTER, 3, offsetof(struct VehicleMovementControl, automationControl),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AutomationControl,
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
		"automationControl"
		},
	{ ATF_POINTER, 2, offsetof(struct VehicleMovementControl, accelerationControl),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AccelerationControl,
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
		"accelerationControl"
		},
	{ ATF_POINTER, 1, offsetof(struct VehicleMovementControl, accelerationControlExtension),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AccelerationControlExtension,
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
		"accelerationControlExtension"
		},
};
static const int asn_MAP_VehicleMovementControl_oms_1[] = { 2, 3, 4, 5 };
static const ber_tlv_tag_t asn_DEF_VehicleMovementControl_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_VehicleMovementControl_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* accelerationPedalStatus */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* brakePedalStatus */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* saeAutomationLevel */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* automationControl */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* accelerationControl */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* accelerationControlExtension */
};
asn_SEQUENCE_specifics_t asn_SPC_VehicleMovementControl_specs_1 = {
	sizeof(struct VehicleMovementControl),
	offsetof(struct VehicleMovementControl, _asn_ctx),
	asn_MAP_VehicleMovementControl_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_VehicleMovementControl_oms_1,	/* Optional members */
	4, 0,	/* Root/Additions */
	6,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_VehicleMovementControl = {
	"VehicleMovementControl",
	"VehicleMovementControl",
	&asn_OP_SEQUENCE,
	asn_DEF_VehicleMovementControl_tags_1,
	sizeof(asn_DEF_VehicleMovementControl_tags_1)
		/sizeof(asn_DEF_VehicleMovementControl_tags_1[0]), /* 1 */
	asn_DEF_VehicleMovementControl_tags_1,	/* Same as above */
	sizeof(asn_DEF_VehicleMovementControl_tags_1)
		/sizeof(asn_DEF_VehicleMovementControl_tags_1[0]), /* 1 */
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
	asn_MBR_VehicleMovementControl_1,
	6,	/* Elements count */
	&asn_SPC_VehicleMovementControl_specs_1	/* Additional specs */
};

