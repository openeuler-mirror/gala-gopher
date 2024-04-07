%define __os_install_post %{nil}

%define without_flamegraph    0
%define without_cadvisor      0
%define without_jvm           0
%define without_tcp           0
%define without_systeminfo    0
%define without_virt          0
%define without_opengauss_sli 0
%define without_l7            0
%define without_postgre_sli   0
%define without_redis_sli     0
%define without_proc          0
%define without_tprofiling    0

%define disable_kafka_channel 0
%define disable_flamegraph_svg 0

# example for tailoring probes
%global extend_tailor_probes %{nil}
%if 0%{?without_flamegraph}
%global extend_tailor_probes %{extend_tailor_probes}stackprobe|
%endif
%if 0%{?without_jvm}
%global extend_tailor_probes %{extend_tailor_probes}jvm.probe
%endif

Summary:       Intelligent ops toolkit for openEuler
Name:          gala-gopher
Version:       2.0.0
Release:       1
License:       Mulan PSL v2
URL:           https://gitee.com/openeuler/gala-gopher
Source:        %{name}-%{version}.tar.gz
BuildRoot:     %{_builddir}/%{name}-%{version}
BuildRequires: systemd cmake gcc-c++ elfutils-devel (clang >= 10.0.1 or clang12) llvm bpftool >= 6.8
BuildRequires: libconfig-devel libevent-devel openssl-devel libbpf-devel >= 2:0.8 uthash-devel
BuildRequires: jsoncpp-devel git libstdc++-devel
# for DT
#BuildRequires: CUnit-devel

%if !0%{?disable_kafka_channel}
BuildRequires: librdkafka-devel
%endif
%if !0%{?without_flamegraph}
BuildRequires: libcurl-devel
%endif
%if !0%{?without_jvm}
BuildRequires: java-1.8.0-openjdk-devel
%endif
%if !0%{?without_l7}
BuildRequires: jsoncpp-devel java-1.8.0-openjdk-devel
%endif

Requires:      bash gawk procps-ng glibc elfutils bpftool libbpf >= 2:0.8
Requires:      libconfig libevent iproute jsoncpp libstdc++

%if !0%{?disable_kafka_channel}
Requires:      librdkafka
%endif

%if !0%{?without_systeminfo}
Requires:      ethtool systemd iproute
%endif
%if !0%{?without_virt}
Requires:      systemd
%endif
%if !0%{?without_tcp}
Requires:      iproute conntrack-tools
%endif
%if !0%{?without_proc}
Requires:      kmod
%endif
%if !0%{?without_flamegraph}
%if !0%{?disable_flamegraph_svg}
Requires:      flamegraph
%endif
Requires:      libcurl
%endif
%if !0%{?without_opengauss_sli}
Requires:      python3-psycopg2 python3-yaml net-tools
%endif
%if !0%{?without_cadvisor}
Requires:      cadvisor python3-libconf python3-requests net-tools util-linux
%endif
%if !0%{?without_postgre_sli}
Requires:      iproute
%endif
%if !0%{?without_redis_sli}
Requires:      iproute
%endif
%if !0%{?without_l7}
Requires:      jsoncpp conntrack-tools
%endif
%if !0%{?without_tprofiling}
Requires:      lsof
%endif


%description
gala-gopher is a low-overhead eBPF-based probes framework

%prep
%autosetup -n %{name}-%{version} -p1


%build
cat << EOF > tailor.conf
EXTEND_PROBES="%{extend_tailor_probes}"
EOF

BUILD_OPTS=(
%if !0%{?disable_kafka_channel}
    -DKAFKA_CHANNEL=1
%else
    -DKAFKA_CHANNEL=0
%endif

%if !0%{?disable_flamegraph_svg}
    -DFLAMEGRAPH_SVG=1
%endif
)

pushd build
export PATH=$PATH:/usr/lib64/llvm12/bin
sh build.sh --debug "${BUILD_OPTS[@]}"
popd

%check
# pushd test
# sh test_modules.sh "${BUILD_OPTS[@]}"
# popd

%install
install -d %{buildroot}/etc/gala-gopher
install -d %{buildroot}/opt/gala-gopher
install -d %{buildroot}%{_bindir}
install -d %{buildroot}/usr/libexec/gala-gopher/
mkdir -p  %{buildroot}/usr/lib/systemd/system
install -m 0600 service/gala-gopher.service %{buildroot}/usr/lib/systemd/system/gala-gopher.service
pushd build
sh install.sh %{buildroot}%{_bindir} %{buildroot}/opt/gala-gopher %{buildroot}/etc/gala-gopher %{buildroot}/usr/libexec/gala-gopher/ %{buildroot}/opt/gala-gopher
popd

%post
%systemd_post gala-gopher.service
if [ -d /var/log/gala-gopher ]; then
  othermode=$(expr $(stat -L -c "%a" /var/log/gala-gopher) % 10)
  if [ $othermode -ne 0 ]; then
    chmod 750 /var/log/gala-gopher
    chmod 750 /var/log/gala-gopher/debug
    chmod 640 /var/log/gala-gopher/debug/gopher.log
  fi
fi

%preun
%systemd_preun gala-gopher.service

%postun
if [ $1 -eq 0 ]; then
  rm -rf /sys/fs/bpf/gala-gopher > /dev/null
fi
%systemd_postun_with_restart gala-gopher.service

%files
%attr(0750,root,root) %dir /opt/gala-gopher
%attr(0550,root,root) %dir /opt/gala-gopher/extend_probes
%attr(0750,root,root) %dir /opt/gala-gopher/meta
%attr(0750,root,root) %dir /opt/gala-gopher/btf
%attr(0550,root,root) %dir /opt/gala-gopher/lib
%attr(0550,root,root) %{_bindir}/*
%attr(0550,root,root) /opt/gala-gopher/extend_probes/*
%attr(0640,root,root) /opt/gala-gopher/meta/*
#%attr(0640,root,root) /opt/gala-gopher/btf/*
%attr(0550,root,root) /opt/gala-gopher/lib/*
%attr(0640,root,root) /etc/gala-gopher/res/event_multy_language.rc
%attr(0640,root,root) %config(noreplace) /etc/gala-gopher/probes.init
%attr(0640,root,root) %config(noreplace) /etc/gala-gopher/*.conf
%attr(0640,root,root) %config(noreplace) /etc/gala-gopher/extend_probes/*.conf
%attr(0600,root,root) /usr/lib/systemd/system/gala-gopher.service
%attr(0550,root,root) /usr/libexec/gala-gopher/init_probes.sh

%changelog

