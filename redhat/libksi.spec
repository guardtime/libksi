#
# Copyright 2013-2015 Guardtime, Inc.
#
# This file is part of the Guardtime client SDK.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# "Guardtime" and "KSI" are trademarks or registered trademarks of
# Guardtime, Inc., and no license to trademarks is granted; Guardtime
# reserves and retains all trademark rights.
#

Summary: Guardtime KSI Client API for C
Name: libksi
Version: %(cat VERSION)
Release: STABLE 
License: ASL 2.0
Group: Development/Libraries
Source: http://download.guardtime.com/%{name}-%{version}.tar.gz
URL: http://www.guardtime.com/
Vendor: Guardtime AS
Packager: Guardtime AS <info@guardtime.com>
Requires: openssl
Requires: curl
Requires: ca-certificates
BuildRequires: openssl-devel
BuildRequires: curl-devel

%description
Client-side runtime libraries for accessing
Guardtime's Keyless Signature Service.

%package devel
Summary: Guardtime KSI Client API for C
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}
Requires: openssl-devel
Requires: curl-devel

%description devel
Client-side development libraries and headers for accessing
Guardtime's Keyless Signature Service.

%prep
%setup

%build
%configure
make

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
 
%files
%defattr(644,root,root,755)
%{_libdir}/libksi.so
%{_libdir}/libksi.so.0
%{_libdir}/libksi.so.0.0.0
%{_docdir}/%{name}/changelog
%{_docdir}/%{name}/license.txt

%files devel
%defattr(644,root,root,755)
%{_includedir}/ksi/base32.h
%{_includedir}/ksi/crc32.h
%{_includedir}/ksi/common.h
%{_includedir}/ksi/err.h
%{_includedie}/ksi/fast_tlv.h
%{_includedir}/ksi/hash.h
%{_includedir}/ksi/hashchain.h
%{_includedir}/ksi/hmac.h
%{_includedir}/ksi/io.h
%{_includedir}/ksi/ksi.h
%{_includedir}/ksi/list.h
%{_includedir}/ksi/log.h
%{_includedir}/ksi/net.h
%{_includedir}/ksi/net_http.h
%{_includedir}/ksi/net_tcp.h
%{_includedir}/ksi/net_uri.h
%{_includedir}/ksi/pkitruststore.h
%{_includedir}/ksi/publicationsfile.h
%{_includedir}/ksi/signature.h
%{_includedir}/ksi/tlv.h
%{_includedir}/ksi/tlv_template.h
%{_includedir}/ksi/types.h
%{_includedir}/ksi/types_base.h
%{_includedir}/ksi/verification.h
%{_includedir}/ksi/compatibility.h
%{_libdir}/libksi.a
%{_libdir}/libksi.la
%{_libdir}/pkgconfig/libksi.pc
