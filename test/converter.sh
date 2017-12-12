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

# Method for converting aggregation request (PDUv1->PDUv2)
# $1 - source file
# $2 - destination file
function convert_aggr_req_pdu {
	gttlvdump $1 |
		sed -e "s/\(^TLV\[\)0200/\10220/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[\)0201/\102/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[1f\]\:\)[[:space:]][[:xdigit:]]*$/\1\$HMAC(v2|sha256|anon)/g" |
		gttlvundump > $2
}


# Method for converting aggregation response (PDUv1->PDUv2)
# $1 - source file
# $2 - destination file
function convert_aggr_resp_pdu {
	gttlvdump $1 |
		sed -e "s/\(^TLV\[\)0200/\10221/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[\)0202/\102/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[\)0203/\103/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[1f\]\:\)[[:space:]][[:xdigit:]]*$/\1\$HMAC(v2|sha256|anon)/g" |
		gttlvundump > $2
}


# Method for converting extention request (PDUv1->PDUv2)
# $1 - source file
# $2 - destination file
function convert_ext_req_pdu {
	gttlvdump $1 |
		sed -e "s/\(^TLV\[\)0300/\10320/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[\)0301/\102/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[1f\]\:\)[[:space:]][[:xdigit:]]*$/\1\$HMAC(v2|sha256|anon)/g" |
		gttlvundump > $2
}


# Method for converting extention response (PDUv1->PDUv2)
# $1 - source file
# $2 - destination file
function convert_ext_resp_pdu {
	gttlvdump $1 |
		sed -e "s/\(^TLV\[\)0300/\10321/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[\)0302/\102/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[\)0303/\103/g" \
			-e "s/\(^[[:space:]]\{4\}TLV\[\)10/\112/g" \
			-e "s/\(^[[:space:]]\{2\}TLV\[1f\]\:\)[[:space:]][[:xdigit:]]*$/\1\$HMAC(v2|sha256|anon)/g" |
		gttlvundump > $2
}
