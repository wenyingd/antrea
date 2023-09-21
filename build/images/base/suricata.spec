Summary: Intrusion Detection System
Name: suricata
Version: %{suricata_version}
Release: 1%{?dist}
Epoch: 1
License: GPLv2
URL: https://suricata-ids.org/
Source0: https://www.openinfosecfoundation.org/download/%{name}-%{version}.tar.gz

BuildRequires: autoconf automake
BuildRequires: pkg-config coreutils
BuildRequires: rust
BuildRequires: libyaml-devel
BuildRequires: zlib-devel pcre-devel libcap-ng-devel
BuildRequires: libnetfilter_queue-devel
BuildRequires: lz4-devel libpcap-devel
BuildRequires: file-devel
BuildRequires: jansson-devel
BuildRequires: clang-devel elfutils-libelf-devel
BuildRequires: systemd-devel doxygen

Requires(pre): /usr/sbin/useradd
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
The Suricata Engine is an Open Source Next Generation Intrusion
Detection and Prevention Engine. This engine is not intended to
just replace or emulate the existing tools in the industry, but
will bring new ideas and technologies to the field. This new Engine
supports Multi-threading, Automatic Protocol Detection (IP, TCP,
UDP, ICMP, HTTP, TLS, FTP and SMB! ), Gzip Decompression, Fast IP
Matching, and GeoIP identification.

%prep
%setup -q -n suricata-%{version}

find python/ -type f -exec sed -i '1s=^#!/usr/bin/\(python\|env python\)[23]\?=#!%{__python3}=' {} +
sed -i 's/(datadir)/(sysconfdir)/' etc/Makefile.am
sed -i 's/^dist_doc_DATA =.*/dist_doc_DATA =/' doc/Makefile.am

autoreconf -fv --install

%build
%configure --enable-af-packet --enable-nfqueue \
	--enable-gccprotect --disable-gccmarch-native \
	--disable-coccinelle \
	--disable-suricata-update

%make_build

%install
make DESTDIR="%{buildroot}" "bindir=%{_sbindir}" install

# Move utilities back to bindir.
mv %{buildroot}%{_sbindir}/suricatasc %{buildroot}%{_bindir}/
mv %{buildroot}%{_sbindir}/suricatactl %{buildroot}%{_bindir}/

# Setup etc directory
mkdir -p %{buildroot}%{_sysconfdir}/%{name}/rules
install -m 640 rules/*.rules %{buildroot}%{_sysconfdir}/%{name}/rules
install -m 600 etc/*.config %{buildroot}%{_sysconfdir}/%{name}
install -m 600 threshold.config %{buildroot}%{_sysconfdir}/%{name}
install -m 600 suricata.yaml %{buildroot}%{_sysconfdir}/%{name}
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 etc/%{name}.service %{buildroot}%{_unitdir}/

# Set up logging
mkdir -p %{buildroot}/%{_var}/log/%{name}
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
install -m 644 etc/%{name}.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/%{name}

# Remove a couple things so they don't get picked up
rm -rf %{buildroot}%{_includedir}
rm -f %{buildroot}%{_libdir}/libhtp.la
rm -f %{buildroot}%{_libdir}/libhtp.a
rm -f %{buildroot}%{_libdir}/libhtp.so
rm -rf %{buildroot}%{_libdir}/pkgconfig

mkdir -p %{buildroot}/%{_var}/lib/%{name}

%check
make check

%pre
getent group suricata > /dev/null || groupadd -r suricata
getent passwd suricata >/dev/null || useradd -r -M -g suricata -s /sbin/nologin suricata

%post
%systemd_post suricata.service

%preun
%systemd_preun suricata.service

%postun
%systemd_postun_with_restart suricata.service

%files
%doc doc/Setting_up_IPSinline_for_Linux.txt
%{!?_licensedir:%global license %%doc}
%license COPYING
%attr(644,root,root) %{_mandir}/man1/*
%{_sbindir}/suricata
%{_bindir}/suricatasc
%{_bindir}/suricatactl
%{_libdir}/libhtp*
%{_prefix}/lib/suricata/python/*
%config(noreplace) %attr(0640,suricata,suricata) %{_sysconfdir}/%{name}/suricata.yaml
%config(noreplace) %attr(0640,suricata,suricata) %{_sysconfdir}/%{name}/*.config
%config(noreplace) %attr(0640,suricata,suricata) %{_sysconfdir}/%{name}/rules/*.rules
%attr(644,root,root) %{_unitdir}/suricata.service
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/logrotate.d/%{name}
%attr(750,suricata,suricata) %dir %{_var}/log/%{name}
%attr(750,suricata,suricata) %dir %{_sysconfdir}/%{name}/rules
%attr(2770,suricata,suricata) %dir %{_var}/lib/%{name}
%{_datadir}/%{name}/rules

%changelog
* Tue Sep 5 2023 Xu Liu <xliu2@vmware.com> - 1:6.0.13-1
- Support build on Photon 3.0.
- Change the shebangs in the python scripts to use Python 3 explicitly.

* Fri Apr 14 2023 Jason Ish <jason.ish@oisf.net> - 1:6.0.11-1
- Update to 6.0.11.

* Tue Jan 31 2023 Jason Ish <jason.ish@oisf.net> - 1:6.0.10-1
- Update to 6.0.10.

* Tue Nov 29 2022 Jason Ish <jason.ish@oisf.net> - 1:6.0.9-1
- Update to 6.0.9.

* Tue Sep 27 2022 Jason Ish <jason.ish@oisf.net> - 1:6.0.8-1
- Update to 6.0.8.
- Update handling for Python files as Suricata 6.0.8 moved away from
  using distuils.

* Tue Jul 12 2022 Jason Ish <jason.ish@oisf.net> - 1:6.0.6-1
- Update to 6.0.6.

* Tue May 10 2022 Jason Ish <jason.ish@oisf.net> - 1:6.0.5-2
- Don't fail if group already exists.

* Thu Apr 21 2022 Jason Ish <jason.ish@oisf.net> - 1:6.0.5-1
- Update to 6.0.5.

* Thu Nov 18 2021 Jason Ish <jason.ish@oisf.net> - 1:6.0.4-1
- Update to 6.0.4
- Remove libprelude as a dependency as support for prelude is broken in
  Suricata 6.0.x.

* Wed Jun 30 2021 Jason Ish <jason.ish@oisf.net> - 1:6.0.3-1
- Update to 6.0.3

* Tue Mar  2 2021 Jason Ish <jason.ish@oisf.net> - 1:6.0.2-1
- Update to 6.0.2

* Fri Dec  4 2020 Jason Ish <jason.ish@oisf.net> - 1:6.0.1-1
- Update to 6.0.1

* Thu Oct 08 2020 Jason Ish <jason.ish@oisf.net> - 1:6.0.0-1
- Update to Suricata 6.0.0 release.

* Mon Sep 14 2020 Jason Ish <jason.ish@oisf.net> - 1:6.0.0-0.1rc1
- Set epoch to 1 so this package will take precedence over anything in EPEL, etc.

* Fri Sep 11 2020 Jason <jason.ish@oisf.net> - 6.0.0-0.2rc1
- Update to Suricata 6.0.0-rc1

* Tue Apr 28 2020 Jason <jason.ish@oisf.net> - 5.0.3-1
- Update to 5.0.3

* Tue Apr 28 2020 Jason Ish <jason.ish@oisf.net> - 5.0.2-4
- Sync up with Fedora master

* Tue Apr 28 2020 Jason Taylor <jtfas90@gmail.com> 5.0.3-1
- Upstream security/bugfix release
- Updated reference, classification, threshold config file installs

* Fri Apr 03 2020 Jason Taylor <jtfas90@gmail.com> 5.0.2-2
- Add python3-pyyaml to resolve (#1818935)

* Mon Mar 30 2020 Jason Ish <jason.ish@oisf.net> - 5.0.2-3
- Add PyYAML as a runtime requirement for suricata-update

* Mon Mar 30 2020 Jason Ish <jason.ish@oisf.net> - 5.0.2-2
- Use Python 2 on CentOS

* Thu Feb 13 2020 Steve Grubb <sgrubb@redhat.com> 5.0.2-1
- New bugfix release

* Fri Jan 31 2020 Fedora Release Engineering <releng@fedoraproject.org> - 5.0.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Fri Dec 13 2019 Steve Grubb <sgrubb@redhat.com> 5.0.1-1
- New bugfix release

* Fri Oct 18 2019 Steve Grubb <sgrubb@redhat.com> 5.0.0-2
- New feature release (which also fixes a security issue)
- Enable ebpf on x86_64 only
- Disable building on ppc64le due to rust problems

* Thu Aug 01 2019 Steve Grubb <sgrubb@redhat.com> 4.1.4-4
- Fix FTBFS bz 1736727

* Sat Jul 27 2019 Fedora Release Engineering <releng@fedoraproject.org> - 4.1.4-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Mon Jul 22 2019 Steve Grubb <sgrubb@redhat.com> 4.1.4-2
- Rebuild for libprelude so bump

* Tue Apr 30 2019 Jason Taylor <jtfas90@gmail.com> 4.1.4-1
- Upstream bugfix release

* Thu Mar 07 2019 Steve Grubb <sgrubb@redhat.com> 4.1.3-1
- Upstream bugfix release

* Sun Feb 03 2019 Fedora Release Engineering <releng@fedoraproject.org> - 4.1.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Fri Dec 21 2018 Jason Taylor <jtfas90@gmail.com> 4.1.2-1
- Upstream bugfix release
- Updated source to use official download site

* Thu Dec 20 2018 Steve Grubb <sgrubb@redhat.com> 4.1.1-4
- Adjust permissions on /run/suricata and /var/lib/suricata to group writable

* Mon Dec 17 2018 Steve Grubb <sgrubb@redhat.com> 4.1.1-2
- Remove ragel requirement

* Mon Dec 17 2018 Steve Grubb <sgrubb@redhat.com> 4.1.1-1
- Make log directory group readable
- Allow users of the suricata group to run suricata-update
- Add lz4-devel BuildRequires to support pcap compression
- Update service file for systemd security protections
- Upstream bugfix update

* Tue Nov 20 2018 Steve Grubb <sgrubb@redhat.com> 4.1.0-3
- Use the upstream service and logrote files (#1330331)
- Make the log directory readable by members of the suricata group (#1651394)

* Wed Nov 07 2018 Steve Grubb <sgrubb@redhat.com> 4.1.0-2
- Add cargo BuildRequires

* Tue Nov 06 2018 Steve Grubb <sgrubb@redhat.com> 4.1.0-1
- Latest upstream major release
- Fixes CVE-2018-18956 Segmentation fault in the ProcessMimeEntity function

* Mon Aug 13 2018 Steve Grubb <sgrubb@redhat.com> - 4.0.5-3
- Consolidate branches so that everything is in sync (#1614935)

* Fri Aug 10 2018 Jason Taylor <jtfas90@gmail.com> 4.0.5-2
- fixes bz#1614935

* Wed Jul 18 2018 Jason Taylor <jtfas90@gmail.com> - 4.0.5-1
- upstream security fix release
- addresses CVE-2018-10242, CVE-2018-10243, CVE-2018-10244

* Sat Jul 14 2018 Fedora Release Engineering <releng@fedoraproject.org> - 4.0.4-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Mon Jul 09 2018 Jason Taylor <jtfas90@gmail.com> - 4.0.4-2
- bumped release for build against hyperscan 5.0.0

* Mon Jul 09 2018 Jason Taylor <jtfas90@gmail.com> - 4.0.4-1
- added gcc-c++ buildrequires

* Thu Feb 15 2018 Jason Taylor <jtfas90@gmail.com> - 4.0.4-1
- fixes bz#1543250 and bz#1543251
- multiple upstream bugfixes

* Fri Feb 09 2018 Fedora Release Engineering <releng@fedoraproject.org> - 4.0.3-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Mon Dec 11 2017 Jason Taylor <jtfas90@gmail.com> 4.0.3-2
- Added prelude support

* Fri Dec 08 2017 Jason Taylor <jtfas90@gmail.com> 4.0.3-1
- Upstream bugfix release

* Wed Oct 18 2017 Steve Grubb <sgrubb@redhat.com> 4.0.1-1
- Upstream bugfix update

* Tue Sep 26 2017 Steve Grubb <sgrubb@redhat.com> 4.0.0-2
- Make suricata user own /run/suricata (#1396150)

* Mon Jul 31 2017 Jason Taylor <jtfas90@gmail.com> 4.0.0-1
- Latest upstream major release
- Build now has hyperscan and redis support

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.2.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Thu Jul 13 2017 Jason Taylor <jtfas90@gmail.com> 3.2.3-1
- Upstream bugfix update

* Wed Jun 07 2017 Steve Grubb <sgrubb@redhat.com> 3.2.2-1
- Upstream bugfix update

* Wed Feb 15 2017 Steve Grubb <sgrubb@redhat.com> 3.2.1-1
- Upstream security update

* Mon Feb 13 2017 Steve Grubb <sgrubb@redhat.com> 3.2-1
- New upstream feature release
- Rotate /var/log/suricata/eve.json (#1396151)
- Fix ownership of /run/suricata (#1396150)

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.1.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Tue Nov 01 2016 Steve Grubb <sgrubb@redhat.com> 3.1.3-1
- New upstream bug fix release

* Wed Sep 07 2016 Steve Grubb <sgrubb@redhat.com> 3.1.2-1
- New upstream bug fix release

* Tue Jul 19 2016 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.1.1-2
- https://fedoraproject.org/wiki/Changes/Automatic_Provides_for_Python_RPM_Packages

* Wed Jul 13 2016 Steve Grubb <sgrubb@redhat.com> 3.1.1-1
- New upstream bug fix release

* Wed Jun 22 2016 Steve Grubb <sgrubb@redhat.com> 3.1-1
- New upstream bug fix release

* Mon Apr 04 2016 Steve Grubb <sgrubb@redhat.com> 3.0.1-1
- New upstream bug fix release

* Wed Mar 16 2016 Steve Grubb <sgrubb@redhat.com> 3.0-2
- Fixed Bug 1227085 - Have Suricata start after the network is online

* Mon Mar 07 2016 Steve Grubb <sgrubb@redhat.com> 3.0-1
- New upstream bug fix release

* Wed Feb 10 2016 Peter Schiffer <pschiffe@redhat.com> 2.0.11-3
- Run suricata under suricata user

* Fri Feb 05 2016 Fedora Release Engineering <releng@fedoraproject.org> - 2.0.11-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Mon Dec 28 2015 Steve Grubb <sgrubb@redhat.com> 2.0.11-1
- New upstream bug fix release

* Wed Nov 25 2015 Steve Grubb <sgrubb@redhat.com> 2.0.10-1
- New upstream bug fix release

* Sat Oct 03 2015 Steve Grubb <sgrubb@redhat.com> 2.0.9-1
- New upstream bug fix release

* Fri Jun 19 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Wed May 06 2015 Steve Grubb <sgrubb@redhat.com> 2.0.8-1
- New upstream security bug fix release

* Thu Feb 26 2015 Steve Grubb <sgrubb@redhat.com> 2.0.7-1
- New upstream security bug fix release for CVE-2015-0928

* Thu Jan 15 2015 Steve Grubb <sgrubb@redhat.com> 2.0.6-1
- New upstream bug fix release
- Don't use the system libhtp library

* Fri Dec 12 2014 Steve Grubb <sgrubb@redhat.com> 2.0.5-1
- New upstream bug fix release
- Use the system libhtp library

* Wed Sep 24 2014 Steve Grubb <sgrubb@redhat.com> 2.0.4-1
- New upstream bug fix release
- Fixes CVE-2014-6603 out-of-bounds access in SSH parser

* Mon Aug 18 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.3-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Fri Aug 08 2014 Steve Grubb <sgrubb@redhat.com> 2.0.3-1
- New upstream bug fix release

* Sat Jun 28 2014 Steve Grubb <sgrubb@redhat.com> 2.0.2-2
- Specfile cleanups (#1113413)

* Wed Jun 25 2014 Steve Grubb <sgrubb@redhat.com> 2.0.2-1
- New upstream bug fix release
- Enable liblua support

* Sun Jun 08 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.0.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Wed May 21 2014 Steve Grubb <sgrubb@redhat.com> 2.0.1-1
- New upstream bug fix release

* Wed Mar 26 2014 Steve Grubb <sgrubb@redhat.com> 2.0-1
- Major new upstream release with new features

* Tue Jan 21 2014 Dan Horák <dan[at]danny.cz> 1.4.7-3
- luajit available only on selected arches

* Sat Jan 11 2014 Steve Grubb <sgrubb@redhat.com> 1.4.7-2
- Enable luajit support

* Wed Dec 18 2013 Steve Grubb <sgrubb@redhat.com> 1.4.7-1
- New upstream bug fix release

* Fri Oct 04 2013 Steve Grubb <sgrubb@redhat.com> 1.4.6-1
- New upstream bug fix release

* Sun Aug 04 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.3-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Fri Jun 21 2013 Steve Grubb <sgrubb@redhat.com> 1.4.3-2
- Drop prelude support

* Fri Jun 21 2013 Steve Grubb <sgrubb@redhat.com> 1.4.3-1
- New upstream bug fix release

* Mon Jun 03 2013 Steve Grubb <sgrubb@redhat.com> 1.4.2-1
- New upstream bug fix release

* Sun Mar 10 2013 Steve Grubb <sgrubb@redhat.com> 1.4.1-1
- New upstream bugfix release
- Enable libgeoip support
- Switch to stack-protector-all

* Fri Feb 15 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Thu Dec 20 2012 Steve Grubb <sgrubb@redhat.com> 1.4-1
- New upstream feature enhancement release

* Thu Dec 06 2012 Steve Grubb <sgrubb@redhat.com> 1.3.5-1
- New upstream bugfix release

* Tue Nov 27 2012 Steve Grubb <sgrubb@redhat.com> 1.3.4-1
- New upstream release

* Mon Nov 05 2012 Steve Grubb <sgrubb@redhat.com> 1.3.3-1
- New upstream release

* Tue Oct 09 2012 Steve Grubb <sgrubb@redhat.com> 1.3.2-2
- Add nss-devel build require and systemd macros

* Mon Oct 08 2012 Steve Grubb <sgrubb@redhat.com> 1.3.2-1
- New upstream release

* Sat Aug 25 2012 Steve Grubb <sgrubb@redhat.com> 1.3.1-1
- New upstream release
- Switch startup to use systemd

* Fri Jul 06 2012 Steve Grubb <sgrubb@redhat.com> 1.3-1
- New upstream release

* Fri Mar 30 2012 Jon Ciesla <limburgher@gmail.com> - 1.2.1-3
- Rebuild for updated libnet.

* Fri Feb 10 2012 Petr Pisar <ppisar@redhat.com> - 1.2.1-2
- Rebuild against PCRE 8.30

* Thu Feb 02 2012 Steve Grubb <sgrubb@redhat.com> 1.2.1-1
- New upstream release

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.1.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Dec 22 2011 Steve Grubb <sgrubb@redhat.com> 1.1.1-2
- Enable AF_PACKET support

* Wed Dec 07 2011 Steve Grubb <sgrubb@redhat.com> 1.1.1-1
- New upstream release

* Mon Jul 25 2011 Steve Grubb <sgrubb@redhat.com> 1.0.5-1
- New upstream release

* Fri Jun 24 2011 Steve Grubb <sgrubb@redhat.com> 1.0.4-1
- New upstream release

* Thu Apr 28 2011 Dan Horák <dan[at]danny.cz> 1.0.3-2
- don't override -march set by the buildsystem (fixes build on non-x86)

* Sat Apr 23 2011 Steve Grubb <sgrubb@redhat.com> 1.0.3-1
- New upstream release

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.0.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Nov 10 2010 Steve Grubb <sgrubb@redhat.com> 1.0.2-1
- New upstream release (#651978)

* Thu Jul 01 2010 Steve Grubb <sgrubb@redhat.com> 1.0.0-1
- New upstream release

* Fri May 07 2010 Steve Grubb <sgrubb@redhat.com> 0.9.0-1
- New upstream release

* Tue Apr 20 2010 Steve Grubb <sgrubb@redhat.com> 0.8.2-1
- New upstream release

* Sat Feb 27 2010 Steve Grubb <sgrubb@redhat.com> 0.8.1-1
- Initial packaging
