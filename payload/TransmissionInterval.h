/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "asn1/ITS-Container.asn"
 * 	`asn1c -no-gen-example -no-gen-APER -no-gen-OER -no-gen-XER -pdu=CAM -pdu=DENM`
 */


/* Including external dependencies */
#include <NativeInteger.h>
#ifndef	_TransmissionInterval_H_
#define	_TransmissionInterval_H_


#include <asn_application.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum TransmissionInterval {
	TransmissionInterval_oneMilliSecond	= 1,
	TransmissionInterval_tenSeconds	= 10000
} e_TransmissionInterval;

/* TransmissionInterval */
typedef long	 TransmissionInterval_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_TransmissionInterval_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_TransmissionInterval;
asn_struct_free_f TransmissionInterval_free;
asn_struct_print_f TransmissionInterval_print;
asn_constr_check_f TransmissionInterval_constraint;
ber_type_decoder_f TransmissionInterval_decode_ber;
der_type_encoder_f TransmissionInterval_encode_der;
per_type_decoder_f TransmissionInterval_decode_uper;
per_type_encoder_f TransmissionInterval_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _TransmissionInterval_H_ */
#include <asn_internal.h>
