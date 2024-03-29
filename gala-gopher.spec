%define __os_install_post %{nil}

%define vmlinux_ver 5.10.0-126.0.0.66.oe2203.%{_arch}

%define without_flamegraph 0
%define without_cadvisor   0
%define without_jvm        0

%define extend_tailor_probes \\\
  %[0%{?without_flamegraph}?"stackprobe|":""] \\\
  %[0%{?without_cadvisor}?"cadvisor.probe|":""] \\\
  %[0%{?without_jvm}?"jvm.probe|":""]

Summary:       Intelligent ops toolkit for openEuler
Name:          gala-gopher
Version:       1.0.2
Release:       2
License:       Mulan PSL v2
URL:           https://gitee.com/openeuler/gala-gopher
Source:        %{name}-%{version}.tar.gz
BuildRoot:     %{_builddir}/%{name}-%{version}
BuildRequires: systemd cmake gcc-c++ elfutils-devel clang >= 10.0.1 llvm
BuildRequires: libconfig-devel librdkafka-devel libmicrohttpd-devel
BuildRequires: libbpf-devel >= 2:0.3 uthash-devel log4cplus-devel cjson-devel
%if 0%{?without_flamegraph}?0:1
BuildRequires: libcurl-devel
%endif
%if 0%{?without_jvm}?0:1
BuildRequires: java-1.8.0-openjdk-devel
%endif

Requires:      bash glibc elfutils bpftool dmidecode iproute cjson
Requires:      libbpf >= 2:0.3 kmod net-tools ethtool
%if 0%{?without_flamegraph}?0:1
Requires:      flamegraph libcurl
%endif
%if 0%{?without_opengauss_sli}?0:1
Requires:      python3-psycopg2 python3-yaml
%endif
%if 0%{?without_cadvisor}?0:1
Requires:      cadvisor python3-libconf python3-requests
%endif

%description
gala-gopher is a low-overhead eBPF-based probes framework

%prep
%autosetup -n %{name}-%{version} -p1


%build
cat << EOF > tailor.conf
EXTEND_PROBES="%{extend_tailor_probes}"
EOF

pushd build
sh build.sh --release %{vmlinux_ver}
popd

%check

%install
install -d %{buildroot}/etc/gala-gopher
install -d %{buildroot}/opt/gala-gopher
install -d %{buildroot}%{_bindir}
mkdir -p  %{buildroot}/usr/lib/systemd/system
install -m 0600 service/gala-gopher.service %{buildroot}/usr/lib/systemd/system/gala-gopher.service
pushd build
sh install.sh %{buildroot}%{_bindir} %{buildroot}/opt/gala-gopher %{buildroot}/etc/gala-gopher
popd

%post
%systemd_post gala-gopher.service

%preun
%systemd_preun gala-gopher.service

%postun
if [ $1 -eq 0 ]; then
  rm -rf /sys/fs/bpf/gala-gopher > /dev/null
fi
%systemd_postun_with_restart gala-gopher.service

%files
%defattr(-,root,root)
%dir /opt/gala-gopher
%dir /opt/gala-gopher/extend_probes
%dir /opt/gala-gopher/meta
%dir /opt/gala-gopher/lib
%{_bindir}/*
/opt/gala-gopher/extend_probes/*
/opt/gala-gopher/meta/*
/opt/gala-gopher/lib/*
/etc/gala-gopher/res/event_multy_language.rc
%config(noreplace) /etc/gala-gopher/*.conf
%config(noreplace) /etc/gala-gopher/extend_probes/*.conf
%exclude /opt/gala-gopher/extend_probes/*.pyc
%exclude /opt/gala-gopher/extend_probes/*.pyo
/usr/lib/systemd/system/gala-gopher.service

%changelog

