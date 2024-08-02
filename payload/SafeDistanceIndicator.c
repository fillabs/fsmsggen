/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "SafeDistanceIndicator.h"

/*
 * This type is implemented using BOOLEAN,
 * so here we adjust the DEF accordingly.
 */
static const ber_tlv_tag_t asn_DEF_SafeDistanceIndicator_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (1 << 2))
};
asn_TYPE_descriptor_t asn_DEF_SafeDistanceIndicator = {
	"SafeDistanceIndicator",
	"SafeDistanceIndicator",
	&asn_OP_BOOLEAN,
	asn_DEF_SafeDistanceIndicator_tags_1,
	sizeof(asn_DEF_SafeDistanceIndicator_tags_1)
		/sizeof(asn_DEF_SafeDistanceIndicator_tags_1[0]), /* 1 */
	asn_DEF_SafeDistanceIndicator_tags_1,	/* Same as above */
	sizeof(asn_DEF_SafeDistanceIndicator_tags_1)
		/sizeof(asn_DEF_SafeDistanceIndicator_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		BOOLEAN_constraint
	},
	0, 0,	/* No members */
	0	/* No specifics */
};

