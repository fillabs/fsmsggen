/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ASN1C-DATE"
 * 	found in "../../../asn1c-fillabs/skeletons/standard-modules/date.asn1"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-BER -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM -pdu=CollectivePerceptionMessage`
 */

#include "YEAR-MONTH-ENCODING.h"

static int
memb_month_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 1 && value <= 12)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
static asn_per_constraints_t asn_PER_memb_month_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 4,  4,  1,  12 }	/* (1..12) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static asn_TYPE_member_t asn_MBR_YEAR_MONTH_ENCODING_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct YEAR_MONTH_ENCODING, year),
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_YEAR_ENCODING,
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
		"year"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct YEAR_MONTH_ENCODING, month),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_NativeInteger,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			&asn_PER_memb_month_constr_3,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
#if !defined(ASN_DISABLE_JER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_JER_SUPPORT) */
			memb_month_constraint_1
		},
		0, 0, /* No default value */
		"month"
		},
};
static const ber_tlv_tag_t asn_DEF_YEAR_MONTH_ENCODING_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_YEAR_MONTH_ENCODING_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 0 }, /* month */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* immediate */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 0, 0, 0 }, /* near-future */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 0, 0, 0 }, /* near-past */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 0, 0, 0 } /* remainder */
};
static asn_SEQUENCE_specifics_t asn_SPC_YEAR_MONTH_ENCODING_specs_1 = {
	sizeof(struct YEAR_MONTH_ENCODING),
	offsetof(struct YEAR_MONTH_ENCODING, _asn_ctx),
	asn_MAP_YEAR_MONTH_ENCODING_tag2el_1,
	5,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_YEAR_MONTH_ENCODING = {
	"YEAR-MONTH-ENCODING",
	"YEAR-MONTH-ENCODING",
	&asn_OP_SEQUENCE,
	asn_DEF_YEAR_MONTH_ENCODING_tags_1,
	sizeof(asn_DEF_YEAR_MONTH_ENCODING_tags_1)
		/sizeof(asn_DEF_YEAR_MONTH_ENCODING_tags_1[0]), /* 1 */
	asn_DEF_YEAR_MONTH_ENCODING_tags_1,	/* Same as above */
	sizeof(asn_DEF_YEAR_MONTH_ENCODING_tags_1)
		/sizeof(asn_DEF_YEAR_MONTH_ENCODING_tags_1[0]), /* 1 */
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
	asn_MBR_YEAR_MONTH_ENCODING_1,
	2,	/* Elements count */
	&asn_SPC_YEAR_MONTH_ENCODING_specs_1	/* Additional specs */
};

