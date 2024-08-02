/*
 * Generated by asn1c-0.9.29-DF (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/ETSI-ITS-CDD.asn"
 * 	`asn1c -S ../../../asn1c-fillabs/skeletons -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -no-gen-JER -no-gen-random-fill -no-gen-print -fcompound-names -pdu=CAM -pdu=DENM -pdu=VAM`
 */

#include "LowerTriangularPositiveSemidefiniteMatrixColumns.h"

#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_LowerTriangularPositiveSemidefiniteMatrixColumns_constr_1 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  4,  4,  1,  13 }	/* (SIZE(1..13,...)) */,
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
asn_TYPE_member_t asn_MBR_LowerTriangularPositiveSemidefiniteMatrixColumns_1[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_CorrelationColumn,
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
		""
		},
};
static const ber_tlv_tag_t asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
asn_SET_OF_specifics_t asn_SPC_LowerTriangularPositiveSemidefiniteMatrixColumns_specs_1 = {
	sizeof(struct LowerTriangularPositiveSemidefiniteMatrixColumns),
	offsetof(struct LowerTriangularPositiveSemidefiniteMatrixColumns, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
asn_TYPE_descriptor_t asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns = {
	"LowerTriangularPositiveSemidefiniteMatrixColumns",
	"LowerTriangularPositiveSemidefiniteMatrixColumns",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1,
	sizeof(asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1)
		/sizeof(asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1[0]), /* 1 */
	asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1,	/* Same as above */
	sizeof(asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1)
		/sizeof(asn_DEF_LowerTriangularPositiveSemidefiniteMatrixColumns_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_LowerTriangularPositiveSemidefiniteMatrixColumns_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_OF_constraint
	},
	asn_MBR_LowerTriangularPositiveSemidefiniteMatrixColumns_1,
	1,	/* Single element */
	&asn_SPC_LowerTriangularPositiveSemidefiniteMatrixColumns_specs_1	/* Additional specs */
};

