Summary: Allows restricted root access for specified users
Name: sudo
Version: 1.8.6p3
Release: 28%{?dist}
License: ISC
Group: Applications/System
URL: http://www.courtesan.com/sudo/
Source0: http://www.courtesan.com/sudo/dist/sudo-%{version}.tar.gz
Source1: sudo-1.8.6p3-sudoers
Source2: sudo-1.7.4p5-sudo-ldap.conf
Source3: sudo-1.8.6p3-sudo.conf
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: /etc/pam.d/system-auth, vim-minimal

BuildRequires: pam-devel
BuildRequires: groff
BuildRequires: openldap-devel
BuildRequires: flex
BuildRequires: bison
BuildRequires: automake autoconf libtool
BuildRequires: audit-libs-devel libcap-devel
BuildRequires: libselinux-devel
BuildRequires: sendmail
BuildRequires: zlib-devel
BuildRequires: tzdata

# don't strip
Patch1: sudo-1.6.7p5-strip.patch
# configure.in fix
Patch2: sudo-1.7.2p1-envdebug.patch
# show the editor being executed by `sudo -e' in audit messages
Patch3: sudo-1.8.6p3-auditeditor.patch
# fix manpage typo (#726634)
Patch4: sudo-1.8.6p3-mantypo.patch
# correct SELinux handling in sudoedit mode (#697775)
Patch5: sudo-1.8.6p3-sudoedit-selinux.patch
# [RFE] Fix visudo -s to be backwards compatible (#604297)
Patch6: sudo-1.8.6p3-aliaswarnonly.patch
# log failed user role changes (#665131)
Patch7: sudo-1.8.6p3-auditrolechange.patch
# 840980 - sudo creates a new parent process
# Adds cmnd_no_wait Defaults option
Patch8: sudo-1.8.6p3-nowaitopt.patch
# Do not inform the user that the command was not permitted by the
# policy if they do not successfully authenticate.
Patch9: sudo-1.8.6p3-noauthwarn-regression.patch
# 876578 - erealloc3 error on sssd sudoHost netgroup mismatch
Patch10: sudo-1.8.6p3-emallocfail.patch
# 876208 - sudoRunAsUser #uid specification doesn't work
Patch11: sudo-1.8.6p3-ldap-sssd-usermatch.patch
# 879675 - sudo parse ldap.conf incorrectly
Patch12: sudo-1.8.6p3-ldapconfparse.patch
# 879633 - sudo + sssd + local user sends e-mail to administrator
Patch13: sudo-1.8.6p3-sssd-noise.patch
# 903020 - sudoers containing specially crafted aliases causes segfault of visudo
Patch14: sudo-1.8.6p3-cyclesegv.patch
# 856901 - Defauts:!<user> syntax in sudoers doesn't seem to work as expected
Patch15: sudo-1.8.6p3-ALL-with-negation-manupdate.patch
# 947276 - Cannot set RLIMIT_NPROC to unlimited via pam_limits when running sudo
Patch16: sudo-1.8.6p3-nprocfix.patch
# 886648 - Access granted with invalid sudoRunAsUser/sudoRunAsGroup
Patch17: sudo-1.8.6p3-strictuidgid.patch
# 994563 - Warning in visudo: cycle in Host_Alias even without cycle
Patch18: sudo-1.8.6p3-cycledetect.patch
# 848111 - Improve error message
Patch19: sudo-1.8.6p3-netgrmatchtrace.patch
# 994626 - sudo -u <user> sudo -l show error: *** glibc detected *** sudo: realloc(): invalid next size
Patch20: sudo-1.8.6p3-lbufexpandcode.patch
# 973228 - RHEL6 sudo logs username "root" instead of realuser in /var/log/secure
Patch21: sudo-1.8.6p3-logsudouser.patch
# 880150 - sssd +netgroup sudoUser is always matched
Patch22: sudo-1.8.6p3-sssdfixes.patch
# 853542 - sudo should use ipa_hostname in IPA backend when defined
Patch23: sudo-1.8.6p3-ipahostname.patch
# 1015355 - CVE-2013-1775 CVE-2013-2777 CVE-2013-2776 sudo: various flaws
#  upstream ref: 2f3225a2a4a4 049a12a5cc14 ebd6cc75020f
Patch24: sudo-1.8.6p3-CVE-2013-2777_2776_1775.patch
# 1065415 - -sesh replaces /path/to/myshell with /path/to-myshell instead of -myshell
Patch25: sudo-1.8.6p3-sesharg0fix.patch
# 1078338 - sudo does not handle the "(none)" string, when no domainname is set, which breaks when nscd is enabled
Patch26: sudo-1.8.6p3-nonehostname.patch
# 1052940 - Regression in sudo 1.8.6p3-7 package, double quotes are not accepted in sudoers
Patch27: sudo-1.8.6p3-doublequotefix.patch
# 1083064 - With sudo-1.8.6p3-12.el6.x86_64 version, If a sudo rules contains +netgroup in sudoUser attribute it result in access denied
# 1006463 - sudo -U <user> listing shows incorrect list when sssd is used.
Patch28: sudo-1.8.6p3-netgrfilterfix.patch
# 1006447 - sudo -ll does not list the rule names when sssd is used.
Patch29: sudo-1.8.6p3-sssdrulenames.patch
# 1070952 - pam_faillock causes sudo to lock user when user aborts password prompt
Patch30: sudo-1.8.6p3-authinterrupt.patch
# Fix compiler warnings about discarting const qualifiers
Patch31: sudo-1.8.6p3-constwarnfix.patch
# 1138267 - sudoers.ldap man page has typos in description
Patch32: sudo-1.8.6p3-mantypos-ldap.patch
# 1147498 - duplicate sss module in nsswitch breaks sudo
Patch33: sudo-1.8.6p3-nssdupfix.patch
# 1138581 - sudo with sssd doesn't work correctly with sudoOrder option
Patch34: sudo-1.8.6p3-sudoorderfix.patch
# 1142122 - sudo option mail_no_user doesn't work
Patch35: sudo-1.8.6p3-ldapusermatchfix.patch
# 1094548 - sudo - cmnd_no_wait can cause child processes to ignore SIGPIPE
Patch36: sudo-1.8.6p3-sigpipefix.patch
# 1144448 - sudo with ldap doesn't work correctly with 'listpw=all' and 'verifypw=all' in sudoOption entry
Patch37: sudo-1.8.6p3-authlogicfix.patch
# 1200253 - CVE-2014-9680 sudo: unsafe handling of TZ environment variable [rhel-6.7]
Patch38: sudo-1.8.6p3-CVE-2014-9680.patch
# 1075836 - Sudo taking a long time when user information is stored externally.
Patch39: sudo-1.8.6p3-legacy-group-processing.patch
# 1241896 - [RFE] Implement sudoers option to change netgroup processing semantics
Patch40: sudo-1.8.6p3-netgroup_tuple.patch
# 1248695 - sudo segfault segfault at 8 i error 4 in sudoers.so
Patch41: sudo-1.8.6p3-seqfault-null-group-list.patch
# 1197885 - visudo ignores -q flag
Patch42: sudo-1.8.6p3-visudo-quiet-flag.patch
# 1247231 - [RFE] Backport pam_service and pam_login_service sudoers options from sudo 1.8.8
Patch43: sudo-1.8.6p3-pam_servicebackport.patch
# 1144422 - sudo with ldap/sssd doesn't respect env_keep,env_check and env_delete variables in sudoOption
Patch44: sudo-1.8.6p3-strunquote.patch
# 1279447 -  sudo command throwing error when defaults records are added in ldap based on sudoers2ldif generated ldif
Patch45: sudo-1.8.6p3-ldap_sssd_parse_whitespaces.patch
# 1135531 - sudo with ldap doesn't work with 'user id' in sudoUser option
Patch46: sudo-1.8.6p3-ldapsearchuidfix.patch
# 1220480 - sudo option mail_no_user doesn't work with sssd provider
Patch47: sudo-1.8.6p3-sssd-mailfix.patch
# 1284886 - getcwd failed, resulting in Null pointer exception
Patch48: sudo-1.8.6p3-null_exception.patch
# 1309976 - closefrom_override sudo option not working
Patch49: sudo-1.8.6p7-closefrom-override-fix.patch
# 1312481 - non-root user can list privileges of other users
Patch50: sudo-1.8.6p3-unprivileged-list-fix.patch
# 1330001 - Fix sudo log file wrong group ownership
Patch51: sudo-1.8.6p3-loggingperms.patch
# 1374410 - Fix "sudo -l command" in the LDAP and SSS backends when the command is not allowed.
Patch52: sudo-1.8.6p3-ldap-sssd-notallowedcmnd.patch
# 1318374 - Fix sudo parsing sudoers with user's locale
Patch53: sudo-1.8.6p3-sudoerslocale.patch
# 1365156 - Fix race condition when creating /var/log/sudo-io direcotry
Patch54: sudo-1.8.6p3-iologracecondition.patch
# 1391938 - CVE-2016-7032 CVE-2016-7076 sudo: various flaws [rhel-6.9]
Patch55: sudo-1.8.6p3-noexec-update.patch
# 1455399 - CVE-2017-1000367 sudo: Privilege escalation in via improper get_process_ttyname() parsing [rhel-6.9.z]
Patch56: sudo-1.8.6p3-tty-parsing.patch


%description
Sudo (superuser do) allows a system administrator to give certain
users (or groups of users) the ability to run some (or all) commands
as root while logging all commands and arguments. Sudo operates on a
per-command basis.  It is not a replacement for the shell.  Features
include: the ability to restrict what commands a user may run on a
per-host basis, copious logging of each command (providing a clear
audit trail of who did what), a configurable timeout of the sudo
command, and the ability to use the same configuration file (sudoers)
on many different machines.

%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description    devel
The %{name}-devel package contains header files developing sudo
plugins that use %{name}.

%prep
%setup -q

%patch1 -p1 -b .strip
%patch2 -p1 -b .envdebug
%patch3 -p1 -b .auditeditor
%patch4 -p1 -b .mantypo
%patch5 -p1 -b .sudoedit-selinux
%patch6 -p1 -b .aliaswarnonly
%patch7 -p1 -b .auditrolechange
%patch8 -p1 -b .nowaitopt
%patch9 -p1 -b .noauthwarn
%patch10 -p1 -b .emallocfail
%patch11 -p1 -b .ldap-sssd-usermatch
%patch12 -p1 -b .ldapconfparse
%patch13 -p1 -b .sssd-noise
%patch14 -p1 -b .cyclesegv
%patch15 -p1 -b .ALL-with-negation-manupdate
%patch16 -p1 -b .nprocfix
%patch17 -p1 -b .strictuidgid
%patch18 -p1 -b .cycledetect
%patch19 -p1 -b .netgrmatchtrace
%patch20 -p1 -b .lbufexpandcode
%patch21 -p1 -b .logsudouser
%patch22 -p1 -b .sssdfixes
%patch23 -p1 -b .ipahostname
%patch24 -p1 -b .CVE-2013-2777_2776_1775
%patch25 -p1 -b .sesharg0fix
%patch26 -p1 -b .nonehostname
%patch27 -p1 -b .doublequotefix
%patch28 -p1 -b .netgrfilterfix
%patch29 -p1 -b .sssdrulenames
%patch30 -p1 -b .authinterrupt
%patch31 -p1 -b .constwarnfix
%patch32 -p1 -b .mantypos-ldap
%patch33 -p1 -b .nssdupfix
%patch34 -p1 -b .sudoorderfix
%patch35 -p1 -b .ldapusermatchfix
%patch36 -p1 -b .sigpipefix
%patch37 -p1 -b .authlogicfix
%patch38 -p1 -b .CVE-2014-9680
%patch39 -p1 -b .legacy-group-processing
%patch40 -p1 -b .netgroup_tuple
%patch41 -p1 -b .segfault-null-group-list
%patch42 -p1 -b .visudo-quiet-flag
%patch43 -p1 -b .pam_servicebackport
%patch44 -p1 -b .strunquote
%patch45 -p1 -b .rmwhitespaces
%patch46 -p1 -b .ldapsearchuidfix
%patch47 -p1 -b .mailfix
%patch48 -p1 -b .nullexception
%patch49 -p1 -b .closefrom-override-fix
%patch50 -p1 -b .unprivileged-list-fix
%patch51 -p1 -b .loggingperms
%patch52 -p1 -b .ldap-sssd-notallowedcmnd
%patch53 -p1 -b .sudoerslocale
%patch54 -p1 -b .iologracecondition
%patch55 -p1 -b .noexec-update
%patch56 -p1 -b .tty-parsing

%build
autoreconf -I m4 -fv --install

%ifarch s390 s390x sparc64
F_PIE=-fPIE
%else
F_PIE=-fpie
%endif

export CFLAGS="$RPM_OPT_FLAGS $F_PIE" LDFLAGS="-pie -Wl,-z,relro -Wl,-z,now" SHLIB_MODE=755

%configure \
        --prefix=%{_prefix} \
        --sbindir=%{_sbindir} \
        --libdir=%{_libdir} \
	--docdir=%{_datadir}/doc/%{name}-%{version} \
        --with-logging=syslog \
        --with-logfac=authpriv \
        --with-pam \
	--with-pam-login \
        --with-editor=/bin/vi \
        --with-env-editor \
        --with-ignore-dot \
        --with-tty-tickets \
        --with-ldap \
	--with-ldap-conf-file="%{_sysconfdir}/sudo-ldap.conf" \
	--with-selinux \
	--with-passprompt="[sudo] password for %p: " \
	--with-linux-audit \
	--with-sssd
#	--without-kerb5 \
#	--without-kerb4
make

%install
rm -rf $RPM_BUILD_ROOT

# Update README.LDAP (#736653)
sed -i 's|/etc/ldap\.conf|%{_sysconfdir}/sudo-ldap.conf|g' README.LDAP

make install DESTDIR="$RPM_BUILD_ROOT" install_uid=`id -u` install_gid=`id -g` sudoers_uid=`id -u` sudoers_gid=`id -g`
chmod 755 $RPM_BUILD_ROOT%{_bindir}/* $RPM_BUILD_ROOT%{_sbindir}/* 
install -p -d -m 700 $RPM_BUILD_ROOT/var/db/sudo
install -p -d -m 750 $RPM_BUILD_ROOT/etc/sudoers.d
install -p -c -m 0440 %{SOURCE1} $RPM_BUILD_ROOT/etc/sudoers
install -p -c -m 0640 %{SOURCE3} $RPM_BUILD_ROOT/etc/sudo.conf
install -p -c -m 0640 %{SOURCE2} $RPM_BUILD_ROOT/%{_sysconfdir}/sudo-ldap.conf

# Remove execute permission on this script so we don't pull in perl deps
chmod -x $RPM_BUILD_ROOT%{_docdir}/sudo-*/sudoers2ldif

%find_lang sudo
%find_lang sudoers

cat sudo.lang sudoers.lang > sudo_all.lang
rm sudo.lang sudoers.lang

mkdir -p $RPM_BUILD_ROOT/etc/pam.d
cat > $RPM_BUILD_ROOT/etc/pam.d/sudo << EOF
#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
EOF

cat > $RPM_BUILD_ROOT/etc/pam.d/sudo-i << EOF
#%PAM-1.0
auth       include      sudo
account    include      sudo
password   include      sudo
session    optional     pam_keyinit.so force revoke
session    required     pam_limits.so
EOF

%clean
rm -rf $RPM_BUILD_ROOT

%files -f sudo_all.lang
%defattr(-,root,root)
%attr(0440,root,root) %config(noreplace) /etc/sudoers
%attr(0640,root,root) %config(noreplace) /etc/sudo.conf
%attr(0640,root,root) %config(noreplace) %{_sysconfdir}/sudo-ldap.conf
%attr(0750,root,root) %dir /etc/sudoers.d/
%config(noreplace) /etc/pam.d/sudo
%config(noreplace) /etc/pam.d/sudo-i
%dir /var/db/sudo
%attr(4111,root,root) %{_bindir}/sudo
%attr(4111,root,root) %{_bindir}/sudoedit
%attr(0111,root,root) %{_bindir}/sudoreplay
%attr(0755,root,root) %{_sbindir}/visudo
%attr(0755,root,root) %{_libexecdir}/sesh
%{_libexecdir}/sudoers.*
%{_libexecdir}/sudo_noexec.*
%{_mandir}/man5/sudoers.5*
%{_mandir}/man5/sudoers.ldap.5*
%{_mandir}/man8/sudo.8*
%{_mandir}/man8/sudoedit.8*
%{_mandir}/man8/sudoreplay.8*
%{_mandir}/man8/visudo.8*
%{_docdir}/sudo-%{version}/*


# Make sure permissions are ok even if we're updating
%post
/bin/chmod 0440 /etc/sudoers || :

%files devel
%defattr(-,root,root,-)
%doc plugins/sample/sample_plugin.c
%{_includedir}/sudo_plugin.h
%{_mandir}/man8/sudo_plugin.8*

%changelog
* Mon May 29 2017 Radovan Sroka <rsroka@redhat.com> - 1.8.6p3-28
- Fixes CVE-2017-1000367
  Resolves: rhbz#1455399

* Thu Nov 24 2016 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-27
- Update noexec syscall blacklist
- Fixes CVE-2016-7032 and CVE-2016-7076
  Resolves: rhbz#1391938

* Tue Oct 18 2016 Tomas Sykora <tosykora@redhat.com> - 1.8.6p3-26
- RHEL-6.9 erratum
  - Fix race condition when creating /var/log/sudo-io direcotry
  Resolves: rhbz#1365156

* Thu Oct 06 2016 Tomas Sykora <tosykora@redhat.com> - 1.8.6p3-25
- RHEL-6.9 erratum
  - Fix "sudo -l command" in the LDAP and SSS backends when the command
    is not allowed.
  Resolves: rhbz#1374410
  - Fix sudo log file wrong group ownership
  Resolves: rhbz#1330001
  - Fix sudo parsing sudoers with user's locale
  Resolves: rhbz#1318374

* Tue Mar 01 2016 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-24
- RHEL-6.8 erratum
  - fixed a bug causing that non-root users can list privileges of
    other users
  Resolves: rhbz#1312481

* Thu Feb 25 2016 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-23
- RHEL-6.8 erratum
  - fixed handling of closefrom_override defaults option
  Resolves: rhbz#1309976

* Wed Jan 20 2016 Radovan Sroka <rsroka@redhat.com> - 1.8.6p3-22
- RHEL-6.8 erratum
  - fixed potential getcwd failure, resulting in Null pointer exception 
  Resolves: rhbz#1284886

* Tue Dec 15 2015 Radovan Sroka <rsroka@redhat.com> - 1.8.6p3-21
- RHEL-6.8 erratum
  - fixed sssd's detection of user with zero rules
  Resolves: rhbz#1220480

* Mon Dec 14 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-21
- RHEL-6.8 erratum
  - search also by user id when fetching rules from LDAP
  Resolves: rhbz#1135531

* Tue Dec 8 2015 Radovan Sroka <rsroka@redhat.com> - 1.8.6p3-21
- RHEL-6.8 erratum
  - fixed ldap's and sssd's sudoOption value and remove quotes
  - fixed ldap's and sssd's sudoOption whitespaces parse problem
  Resolves: rhbz#1144422
  Resolves: rhbz#1279447

* Tue Dec 8 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-21
- RHEL-6.8 erratum
  - removed defaults option requiretty from /etc/sudoers
  - backported pam_service and pam_login_service defaults options
  - implemented a new defaults option for changing netgroup processing
    semantics
  - fixed visudo's quiet cli option
  Resolves: rhbz#1248695
  Resolves: rhbz#1247231
  Resolves: rhbz#1241896
  Resolves: rhbz#1197885
  Resolves: rhbz#1233205

* Wed Jul 29 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-20
- added patch to re-introduce old group processing behaviour
  Resolves: rhbz#1075836

* Tue May 05 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-19
- RHEL-6.7 erratum
  - modified the authlogicfix patch to fix #1144448
  - fixed a bug in the ldapusermatchfix patch
  Resolves: rhbz#1144448
  Resolves: rhbz#1142122

* Thu Apr 16 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-18
- RHEL-6.7 erratum
  - fixed the mantypos-ldap.patch
  Resolves: rhbz#1138267

* Tue Mar 31 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-17
- RHEL-6.7 erratum
  - added patch for CVE-2014-9680
  - added BuildRequires for tzdata
  Resolves: rhbz#1200253

* Wed Mar  4 2015 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-16
- RHEL-6.7 erratum
  - added zlib-devel build required to enable zlib compression support
  - fixed two typos in the sudoers.ldap man page
  - fixed a hang when duplicate nss entries are specified in nsswitch.conf
  - SSSD: implemented sorting of the result entries according to the
          sudoOrder attribute
  - LDAP: fixed logic handling the computation of the "user matched" flag
  - fixed restoring of the SIGPIPE signal in the tgetpass function
  - fixed listpw, verifypw + authenticate option logic in LDAP/SSSD
  Resolves: rhbz#1106433
  Resolves: rhbz#1138267
  Resolves: rhbz#1147498
  Resolves: rhbz#1138581
  Resolves: rhbz#1142122
  Resolves: rhbz#1094548
  Resolves: rhbz#1144448

* Thu Jul 31 2014 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-15
- RHEL-6.6 erratum
  - SSSD: dropped the ipahostnameshort patch, as it is not
    needed. rhbz#1033703 is a configuration issue.
  Related: rhbz#1033703

* Wed Jul 30 2014 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-14
- RHEL-6.6 erratum
  - SSSD: fixed netgroup filter patch
  - SSSD: dropped serparate patch for #1006463, the fix is now part
    of the netgroup filter patch
  Resolves: rhbz#1006463
  Resolves: rhbz#1083064

* Mon May 19 2014 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-13
- RHEL-6.6 erratum
  - don't retry authentication when ctrl-c pressed
  - fix double-quote processing in Defaults options
  - fix sesh login shell argv[0]
  - handle the "(none)" hostname correctly
  - SSSD: fix ipa_hostname handling
  - SSSD: fix sudoUser netgroup specification filtering
  - SSSD: list correct user when -U <user> -l specified
  - SSSD: show rule names on long listing (-ll)
  Resolves: rhbz#1065415
  Resolves: rhbz#1078338
  Resolves: rhbz#1052940
  Resolves: rhbz#1083064
  Resolves: rhbz#1033703
  Resolves: rhbz#1006447
  Resolves: rhbz#1006463
  Resolves: rhbz#1070952

* Mon Oct  7 2013 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-12
- added patches for CVE-2013-1775 CVE-2013-2777 CVE-2013-2776
  Resolves: rhbz#1015355

* Thu Sep  5 2013 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-11
- sssd: fixed a bug in ipa_hostname processing
  Resolves: rhbz#853542

* Thu Aug 15 2013 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-10
- sssd: fixed buffer size for the ipa_hostname value
  Resolves: rhbz#853542

* Wed Aug 14 2013 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-9
- sssd: match against ipa_hostname from sssd.conf too when
  checking sudoHost
  Resolves: rhbz#853542

* Wed Aug 14 2013 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-8
- updated man-page
- fixed handling of RLIMIT_NPROC resource limit
- fixed alias cycle detection code
- added debug messages for tracing of netgroup matching
- fixed aborting on realloc when displaying allowed commands
- show the SUDO_USER in logs, if running commands as root
- sssd: filter netgroups in the sudoUser attribute
  Resolves: rhbz#856901
  Resolves: rhbz#947276
  Resolves: rhbz#886648
  Resolves: rhbz#994563
  Resolves: rhbz#848111
  Resolves: rhbz#994626
  Resolves: rhbz#973228
  Resolves: rhbz#880150

* Wed Jan 23 2013 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-7
- fixed potential stack overflow in visudo
  Resolves: rhbz#903020

* Thu Nov 29 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-6
- added patches to address a number of issues in ldap & sssd plugins
- fixed README.LDAP updating in the spec file
  Resolves: rhbz#860397
  Resolves: rhbz#876208
  Resolves: rhbz#876578
  Resolves: rhbz#879675
  Resolves: rhbz#879633

* Wed Nov 07 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-5
- Include just one sample plugin in the documentation for the -devel
  subpackage. Don't include architecture specific files.
- patch: Do not inform the user that the command was not permitted by
  the policy if they do not successfully authenticate.
  Resolves: rhbz#759480
  Resolves: rhbz#871303
  Resolves: rhbz#872740

* Wed Sep 26 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-4
- removed %doc since sudo installs the files anyway
  Resolves: rhbz#759480

* Wed Sep 26 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-3
- added SHLIB_MODE=755 to get striping to work again
  Resolves: rhbz#759480

* Wed Sep 26 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-2
- extended the default sudo-ldap.conf file
- corrected default file permissions on sudo.conf, sudo-ldap.conf
- added patch that introduces the cmnd_no_wait Defaults option
  Resolves: rhbz#840980 - sudo creates a new parent process
  Resolves: rhbz#860397 - new /etc/sudo-ldap.conf configuration file problems

* Mon Sep 24 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.8.6p3-1
- rebase to 1.8.6p3
- new -devel subpackage
- new configuration file: /etc/sudo.conf
  Resolves: rhbz#852045 - ulimit -c got Operation not permitted
  Resolves: rhbz#804123 - sudo does not call pam_close_session() or pam_end()
  Resolves: rhbz#828707 - sudo fails to report error correctly when execv(3) fails
  Resolves: rhbz#844691 - Cannot set RLIMIT_NPROC to unlimited via pam_limits when running sudo
  Resolves: rhbz#759480 - Rebase sudo to 1.8 in RHEL 6.4
  Resolves: rhbz#846117 - Sudo interpretation of wildcard command arguments is more lenient providing a security risk
  Resolves: rhbz#789937 - [RFE] Add ability to treat files authoritatively in sudoers.ldap
  Resolves: rhbz#836242 - sudo -s -u USERNAME can't change ulimit -c

* Tue Jul 17 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-13
- fixed job control
  Resolves: rhbz#823993

* Fri Jun 29 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-12
- added patch for CVE-2012-2337
  Resolves: rhbz#829757

* Wed May 16 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-11
- use SIG_SETMASK when resetting signal mask instead of SIG_UNBLOCK (#821976)
  Resolves: rhbz#821976

* Fri May 04 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-10.1
- backported ldap code modifications that fix an issue with tls_checkpeer (#810372)
  Resolves: rhbz#810372

* Mon Apr 16 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-10
- fixed bug in Runas_Spec group matching (#810147)
- disable `sudo -l' output word wrapping if the output
  is piped (#810326)
- fixed `sudo -i' command escaping (#806095)
  Resolves: rhbz#806095
  Resolves: rhbz#810147
  Resolves: rhbz#810326

* Mon Apr 16 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-9
- fixed uninitialized value warning introduced with the sudoedit-selinux patch
  Resolves: rhbz#806386

* Thu Mar 01 2012 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-8
- created a separate ldap configuration file, sudo-ldap.conf
- visudo: mark unused aliases as warnings, not errors
- backported signal handling from 1.7.5
- don't disable coredumping from the code, rely on /proc/sys/fs/suid_dumpable
- use correct SELinux context when editing files with sudoedit
- fixed visudo syntax checks
- fixed typos and inconsistencies in documentation
- switched to an updated -getgrouplist patch to fix sudo -l -U <user> behavior 
  Resolves: rhbz#760843
  Resolves: rhbz#736030
  Resolves: rhbz#697775
  Resolves: rhbz#726634
  Resolves: rhbz#708515
  Resolves: rhbz#736653
  Resolves: rhbz#667120
  Resolves: rhbz#769701
  Resolves: rhbz#751680
  Resolves: rhbz#604297
  Resolves: rhbz#797511

* Thu Jul 21 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-7
- set ldap configuration file to nslcd.conf
  Resolves: rhbz#709235

* Thu Jul 14 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-6
- removed the --with-ldap-*conf options
- added RELRO flags
  Resolves: rhbz#709235
  Resolves: rhbz#709859

* Tue Apr 19 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-5
- patch: log failed user role changes
  Resolves: rhbz#665131

* Wed Mar 23 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-4
- added #includedir /etc/sudoers.d to sudoers
  Resolves: rhbz#615087

* Tue Mar 22 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-3
- added !visiblepw option to sudoers
  Resolves: rhbz#688640

* Fri Feb  4 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-2
- added patch for rhbz#665131
  Resolves: rhbz#665131

* Thu Jan 13 2011 Daniel Kopecek <dkopecek@redhat.com> - 1.7.4p5-1
- rebase to latest stable version
- sudo now uses /var/db/sudo for timestamps
- new command available: sudoreplay
- use native audit support
- sync configuration paths with the nss_ldap package
  Resolves: rhbz#615087
  Resolves: rhbz#652726
  Resolves: rhbz#634159
  Resolves: rhbz#603823

* Wed Sep  1 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-9
- added patch for CVE-2010-2956 (#628628)
  Resolves: rhbz#629054

* Tue Aug 03 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-8
- sudoers change: always set $HOME to the target user home directory 
  Resolves: rhbz#619293

* Thu Jul 15 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-7
- move the sudo_end* calls before closefrom()
- close audit_fd before exec
- fixed typo in Makefile.in
  Resolves: rhbz#569313

* Tue Jun  8 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-6
- fixed segfault when #include directive is used in cycles
  Resolves: rhbz#598363

* Tue Jun  1 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-5
- added patch that fixes insufficient environment sanitization issue (#598154)
  Resolves: rhbz#598383

* Tue Apr 13 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-4
- added second patch for CVE-2010-0426 (#580441)
  Resolves: rhbz#580527

* Wed Feb 24 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-3
- added patch for CVE-2010-0426 (#567337)
  Resolves: rhbz#567675

* Wed Jan 27 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-2
- changed the License: value to ISC
  Related: rhbz#543948

* Wed Jan 13 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.2p2-1
- new upstream version
  Resolves: rhbz#554321
- drop *.pod man page duplicates from docs
- commented out unused aliases in sudoers to make visudo happy (#550239)

* Tue Jan 12 2010 Daniel Kopecek <dkopecek@redhat.com> - 1.7.1-8
- Rebuild for new libaudit
  Related: rhbz#543948

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 1.7.1-7
- rebuilt with new audit

* Thu Aug 20 2009 Daniel Kopecek <dkopecek@redhat.com> 1.7.1-6
- moved secure_path from compile-time option to sudoers file (#517428)

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.7.1-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Jul 09 2009 Daniel Kopecek <dkopecek@redhat.com> 1.7.1-4
- moved the closefrom() call before audit_help_open() (sudo-1.7.1-auditfix.patch)
- epoch number sync

* Mon Jun 22 2009 Daniel Kopecek <dkopecek@redhat.com> 1.7.1-1
- updated sudo to version 1.7.1
- fixed small bug in configure.in (sudo-1.7.1-conffix.patch)

* Tue Feb 24 2009 Daniel Kopecek <dkopecek@redhat.com> 1.6.9p17-6
- fixed building with new libtool
- fix for incorrect handling of groups in Runas_User
- added /usr/local/sbin to secure-path

* Tue Jan 13 2009 Daniel Kopecek <dkopecek@redhat.com> 1.6.9p17-3
- build with sendmail installed
- Added /usr/local/bin to secure-path

* Tue Sep 02 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p17-2
- adjust audit patch, do not scream when kernel is
  compiled without audit netlink support (#401201)

* Fri Jul 04 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p17-1
- upgrade

* Wed Jun 18 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-7
- build with newer autoconf-2.62 (#449614)

* Tue May 13 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-6
- compiled with secure path (#80215)

* Mon May 05 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-5
- fix path to updatedb in /etc/sudoers (#445103)

* Mon Mar 31 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-4
- include ldap files in rpm package (#439506)

* Thu Mar 13 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-3
- include [sudo] in password prompt (#437092)

* Tue Mar 04 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-2
- audit support improvement

* Thu Feb 21 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p13-1
- upgrade to the latest upstream release

* Wed Feb 06 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p12-1
- upgrade to the latest upstream release
- add selinux support

* Mon Feb 02 2008 Dennis Gilmore <dennis@ausil.us> 1.6.9p4-6
- sparc64 needs to be in the -fPIE list with s390

* Mon Jan 07 2008 Peter Vrabec <pvrabec@redhat.com> 1.6.9p4-5
- fix complains about audit_log_user_command(): Connection 
  refused (#401201)

* Wed Dec 05 2007 Release Engineering <rel-eng at fedoraproject dot org> - 1.6.9p4-4
- Rebuild for deps

* Wed Dec 05 2007 Release Engineering <rel-eng at fedoraproject dot org> - 1.6.9p4-3
- Rebuild for openssl bump

* Thu Aug 30 2007 Peter Vrabec <pvrabec@redhat.com> 1.6.9p4-2
- fix autotools stuff and add audit support

* Mon Aug 20 2007 Peter Vrabec <pvrabec@redhat.com> 1.6.9p4-1
- upgrade to upstream release

* Thu Apr 12 2007 Peter Vrabec <pvrabec@redhat.com> 1.6.8p12-14
- also use getgrouplist() to determine group membership (#235915)

* Mon Feb 26 2007 Peter Vrabec <pvrabec@redhat.com> 1.6.8p12-13
- fix some spec file issues

* Thu Dec 14 2006 Peter Vrabec <pvrabec@redhat.com> 1.6.8p12-12
- fix rpmlint issue

* Thu Oct 26 2006 Peter Vrabec <pvrabec@redhat.com> 1.6.8p12-11
- fix typo in sudoers file (#212308)

* Sun Oct 01 2006 Jesse Keating <jkeating@redhat.com> - 1.6.8p12-10
- rebuilt for unwind info generation, broken in gcc-4.1.1-21

* Thu Sep 21 2006 Peter Vrabec <pvrabec@redhat.com> 1.6.8p12-9
- fix sudoers file, X apps didn't work (#206320)

* Tue Aug 08 2006 Peter Vrabec <pvrabec@redhat.com> 1.6.8p12-8
- use Red Hat specific default sudoers file

* Sun Jul 16 2006 Karel Zak <kzak@redhat.com> 1.6.8p12-7
- fix #198755 - make login processes (sudo -i) initialise session keyring
  (thanks for PAM config files to David Howells)
- add IPv6 support (patch by Milan Zazrivec)

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 1.6.8p12-6.1
- rebuild

* Mon May 29 2006 Karel Zak <kzak@redhat.com> 1.6.8p12-6
- fix #190062 - "ssh localhost sudo su" will show the password in clear

* Tue May 23 2006 Karel Zak <kzak@redhat.com> 1.6.8p12-5
- add LDAP support (#170848)

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 1.6.8p12-4.1
- bump again for double-long bug on ppc(64)

* Wed Feb  8 2006 Karel Zak <kzak@redhat.com> 1.6.8p12-4
- reset env. by default

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 1.6.8p12-3.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Mon Jan 23 2006 Dan Walsh <dwalsh@redhat.com> 1.6.8p12-3
- Remove selinux patch.  It has been decided that the SELinux patch for sudo is
- no longer necessary.  In tageted policy it had no effect.  In strict/MLS policy
- We require the person using sudo to execute newrole before using sudo.

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Fri Nov 25 2005 Karel Zak <kzak@redhat.com> 1.6.8p12-1
- new upstream version 1.6.8p12

* Tue Nov  8 2005 Karel Zak <kzak@redhat.com> 1.6.8p11-1
- new upstream version 1.6.8p11

* Thu Oct 13 2005 Tomas Mraz <tmraz@redhat.com> 1.6.8p9-6
- use include instead of pam_stack in pam config

* Tue Oct 11 2005 Karel Zak <kzak@redhat.com> 1.6.8p9-5
- enable interfaces in selinux patch
- merge sudo-1.6.8p8-sesh-stopsig.patch to selinux patch

* Mon Sep 19 2005 Karel Zak <kzak@redhat.com> 1.6.8p9-4
- fix debuginfo

* Mon Sep 19 2005 Karel Zak <kzak@redhat.com> 1.6.8p9-3
- fix #162623 - sesh hangs when child suspends

* Mon Aug 1 2005 Dan Walsh <dwalsh@redhat.com> 1.6.8p9-2
- Add back in interfaces call, SELinux has been fixed to work around

* Tue Jun 21 2005 Karel Zak <kzak@redhat.com> 1.6.8p9-1
- new version 1.6.8p9 (resolve #161116 - CAN-2005-1993 sudo trusted user arbitrary command execution)

* Tue May 24 2005 Karel Zak <kzak@redhat.com> 1.6.8p8-2
- fix #154511 - sudo does not use limits.conf

* Mon Apr  4 2005 Thomas Woerner <twoerner@redhat.com> 1.6.8p8-1
- new version 1.6.8p8: new sudoedit and sudo_noexec

* Wed Feb  9 2005 Thomas Woerner <twoerner@redhat.com> 1.6.7p5-31
- rebuild

* Mon Oct  4 2004 Thomas Woerner <twoerner@redhat.com> 1.6.7p5-30.1
- added missing BuildRequires for libselinux-devel (#132883) 

* Wed Sep 29 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-30
- Fix missing param error in sesh

* Mon Sep 27 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-29
- Remove full patch check from sesh

* Thu Jul 8 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-28
- Fix selinux patch to switch to root user

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Tue Apr 13 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-26
- Eliminate tty handling from selinux

* Thu Apr  1 2004 Thomas Woerner <twoerner@redhat.com> 1.6.7p5-25
- fixed spec file: sesh in file section with selinux flag (#119682)

* Thu Mar 30 2004 Colin Walters <walters@redhat.com> 1.6.7p5-24
- Enhance sesh.c to fork/exec children itself, to avoid
  having sudo reap all domains.
- Only reinstall default signal handlers immediately before
  exec of child with SELinux patch

* Thu Mar 18 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-23
- change to default to sysadm_r 
- Fix tty handling

* Thu Mar 18 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-22
- Add /bin/sesh to run selinux code.
- replace /bin/bash -c with /bin/sesh

* Tue Mar 16 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-21
- Hard code to use "/bin/bash -c" for selinux 

* Tue Mar 16 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-20
- Eliminate closing and reopening of terminals, to match su.

* Mon Mar 15 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-19
- SELinux fixes to make transitions work properly

* Fri Mar  5 2004 Thomas Woerner <twoerner@redhat.com> 1.6.7p5-18
- pied sudo

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Tue Jan 27 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-16
- Eliminate interfaces call, since this requires big SELinux privs
- and it seems to be useless.

* Tue Jan 27 2004 Karsten Hopp <karsten@redhat.de> 1.6.7p5-15
- visudo requires vim-minimal or setting EDITOR to something useful (#68605)

* Mon Jan 26 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-14
- Fix is_selinux_enabled call

* Tue Jan 13 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-13
- Clean up patch on failure 

* Tue Jan 6 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-12
- Remove sudo.te for now.

* Fri Jan 2 2004 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-11
- Fix usage message

* Mon Dec 22 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-10
- Clean up sudo.te to not blow up if pam.te not present

* Thu Dec 18 2003 Thomas Woerner <twoerner@redhat.com>
- added missing BuildRequires for groff

* Tue Dec 16 2003 Jeremy Katz <katzj@redhat.com> 1.6.7p5-9
- remove left-over debugging code

* Tue Dec 16 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-8
- Fix terminal handling that caused Sudo to exit on non selinux machines.

* Mon Dec 15 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-7
- Remove sudo_var_run_t which is now pam_var_run_t

* Fri Dec 12 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-6
- Fix terminal handling and policy

* Thu Dec 11 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-5
- Fix policy

* Thu Nov 13 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-4.sel
- Turn on SELinux support

* Tue Jul 29 2003 Dan Walsh <dwalsh@redhat.com> 1.6.7p5-3
- Add support for SELinux

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon May 19 2003 Thomas Woerner <twoerner@redhat.com> 1.6.7p5-1

* Wed Jan 22 2003 Tim Powers <timp@redhat.com>
- rebuilt

* Tue Nov 12 2002 Nalin Dahyabhai <nalin@redhat.com> 1.6.6-2
- remove absolute path names from the PAM configuration, ensuring that the
  right modules get used for whichever arch we're built for
- don't try to install the FAQ, which isn't there any more

* Thu Jun 27 2002 Bill Nottingham <notting@redhat.com> 1.6.6-1
- update to 1.6.6

* Fri Jun 21 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Thu May 23 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Thu Apr 18 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.5p2-2
- Fix bug #63768

* Thu Mar 14 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.5p2-1
- 1.6.5p2

* Fri Jan 18 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.5p1-1
- 1.6.5p1
- Hope this "a new release per day" madness stops ;)

* Thu Jan 17 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.5-1
- 1.6.5

* Tue Jan 15 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.4p1-1
- 1.6.4p1

* Mon Jan 14 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.4-1
- Update to 1.6.4

* Mon Jul 23 2001 Bernhard Rosenkraenzer <bero@redhat.com> 1.6.3p7-2
- Add build requirements (#49706)
- s/Copyright/License/
- bzip2 source

* Sat Jun 16 2001 Than Ngo <than@redhat.com>
- update to 1.6.3p7
- use %%{_tmppath}

* Fri Feb 23 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- 1.6.3p6, fixes buffer overrun

* Tue Oct 10 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- 1.6.3p5

* Wed Jul 12 2000 Prospector <bugzilla@redhat.com>
- automatic rebuild

* Tue Jun 06 2000 Karsten Hopp <karsten@redhat.de>
- fixed owner of sudo and visudo

* Thu Jun  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- modify PAM setup to use system-auth
- clean up buildrooting by using the makeinstall macro

* Tue Apr 11 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- initial build in main distrib
- update to 1.6.3
- deal with compressed man pages

* Tue Dec 14 1999 Preston Brown <pbrown@redhat.com>
- updated to 1.6.1 for Powertools 6.2
- config files are now noreplace.

* Thu Jul 22 1999 Tim Powers <timp@redhat.com>
- updated to 1.5.9p2 for Powertools 6.1

* Wed May 12 1999 Bill Nottingham <notting@redhat.com>
- sudo is configured with pam. There's no pam.d file. Oops.

* Mon Apr 26 1999 Preston Brown <pbrown@redhat.com>
- upgraded to 1.59p1 for powertools 6.0

* Tue Oct 27 1998 Preston Brown <pbrown@redhat.com>
- fixed so it doesn't find /usr/bin/vi first, but instead /bin/vi (always installed)

* Fri Oct 08 1998 Michael Maher <mike@redhat.com>
- built package for 5.2 

* Mon May 18 1998 Michael Maher <mike@redhat.com>
- updated SPEC file

* Thu Jan 29 1998 Otto Hammersmith <otto@redhat.com>
- updated to 1.5.4

* Tue Nov 18 1997 Otto Hammersmith <otto@redhat.com>
- built for glibc, no problems

* Fri Apr 25 1997 Michael Fulbright <msf@redhat.com>
- Fixed for 4.2 PowerTools 
- Still need to be pamified
- Still need to move stmp file to /var/log

* Mon Feb 17 1997 Michael Fulbright <msf@redhat.com>
- First version for PowerCD.

