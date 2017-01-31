#!/bin/bash

#
# GUARDTIME CONFIDENTIAL
#
# Copyright (C) [2016] Guardtime, Inc
# All Rights Reserved
#
# NOTICE:  All information contained herein is, and remains, the
# property of Guardtime Inc and its suppliers, if any.
# The intellectual and technical concepts contained herein are
# proprietary to Guardtime Inc and its suppliers and may be
# covered by U.S. and Foreign Patents and patents in process,
# and are protected by trade secret or copyright law.
# Dissemination of this information or reproduction of this
# material is strictly forbidden unless prior written permission
# is obtained from Guardtime Inc.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime Inc.
#


source ./converter.sh

PATH_V1="resource/tlv/v1"
PATH_V2="resource/tlv/v2"

# Convert aggregation request (PDUv1->PDUv2)
convert_aggr_req_pdu $PATH_V1/aggr_request.tlv $PATH_V2/aggr_request.tlv


# Convert aggregation response (PDUv1->PDUv2)
AGGR_RESPONSE=(
		aggr_error_pdu.tlv
		aggr-response-no-cal-auth-and-invalid-cal.tlv
		aggr_response.tlv
		nok_aggr_response-1.tlv
		nok_aggr_response_bad_tag.tlv
		nok_aggr_response-invalid-aggr-chain.tlv
		nok_aggr_response_missing_header.tlv
		ok_aggr_err_response-1.tlv
		ok-aggr-resp-1460631424.tlv
		ok-local_aggr_lvl4_resp.tlv
		ok-sig-2014-07-01.1-aggr_response_ordered.tlv
		ok-sig-2014-07-01.1-aggr_response.tlv
		ok-sig-2014-07-01.1-aggr_response-wrong-id.tlv
		ok-sig-2016-03-08-aggr_response.tlv
		ok-sig-2016-04-13-preaggr_response.tlv
		test_create_aggregated_response.tlv
		test_meta_data_masking.tlv
		test_meta_data_response.tlv
		tlv_missing_tag.tlv
		tlv_unknown_tag.tlv
		test_meta_data_response.tlv
	)
for i in ${AGGR_RESPONSE[@]}; do
	convert_aggr_resp_pdu $PATH_V1/$i $PATH_V2/$i
done


# Convert extention request (PDUv1->PDUv2)
convert_ext_req_pdu $PATH_V1/extend_request.tlv $PATH_V2/extend_request.tlv


# Convert extention response (PDUv1->PDUv2)
EXT_RESPONSE=(
		all-wrong-hash-chains-in-signature-extend_response.tlv
		cal_algo_switch-extend_resposne.tlv
		ext_error_pdu.tlv
		extend_response.tlv
		extender-response-no-cal-auth-and-invalid-cal.tlv
		nok-sig-2015-09-13_21-34-00-extend_responce.tlv
		nok-sig-wrong-aggre-time-extend_response.tlv
		ok_extend_err_response-1.tlv
		ok_extender_error_response_101.tlv
		ok_extender_error_response_102.tlv
		ok_extender_error_response_103.tlv
		ok_extender_error_response_104.tlv
		ok_extender_error_response_105.tlv
		ok_extender_error_response_106.tlv
		ok_extender_error_response_107.tlv
		ok_extender_error_response_200.tlv
		ok_extender_error_response_201.tlv
		ok_extender_error_response_202.tlv
		ok_extender_error_response_300.tlv
		ok_extender_error_response_301.tlv
		ok-sig-2014-04-30.1-extend_response.tlv
		ok-sig-2014-04-30.1-extend_response-wrong-id.tlv
		ok-sig-2014-04-30.1-head-extend_response.tlv
		ok-sig-2014-04-30.1-nok-extend_response-1.tlv
		ok-sig-2014-04-30.1-nok-extend_response-3.tlv
		test_meta_data_response.tlv
	)
for i in ${EXT_RESPONSE[@]}; do
	convert_ext_resp_pdu $PATH_V1/$i $PATH_V2/$i
done
