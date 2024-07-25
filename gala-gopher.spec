%define __os_install_post %{nil}
%define gopher_state_dir %{_rundir}/gala_gopher

%define without_baseinfo      1
%define without_virt          1
%define without_flamegraph    1
%define without_l7            1
%define without_tcp           1
%define without_socket        1
%define without_io            1
%define without_proc          1
%define without_jvm           1
%define without_postgre_sli   1
%define without_opengauss_sli 1
%define without_nginx         1
%define without_tprofiling    1
%define without_kafka         1
%define without_hw            1
%define without_ksli          1
%define without_container     1
%define without_sermant       1
%define without_sli           0

%define disable_report_event   0
%define disable_kafka_channel  0
%define disable_flamegraph_svg 1


Summary:       Intelligent ops toolkit for openEuler
Name:          gala-gopher
Version:       2.0.2
Release:       1
License:       Mulan PSL v2
URL:           https://gitee.com/openeuler/gala-gopher
Source:        %{name}-%{version}.tar.gz
BuildRoot:     %{_builddir}/%{name}-%{version}
BuildRequires: systemd cmake gcc-c++ elfutils-devel clang llvm bpftool
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

Requires:      bash gawk procps-ng glibc elfutils libbpf >= 2:0.8
Requires:      libconfig libevent iproute jsoncpp libstdc++

%if !0%{?disable_kafka_channel}
Requires:      librdkafka
%endif

%if !0%{?without_baseinfo}
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
%if !0%{?without_container}
Requires:      cadvisor python3-requests net-tools util-linux
%endif
%if !0%{?without_postgre_sli}
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
BUILD_OPTS=(
  -DENABLE_BASEINFO=%[0%{?without_baseinfo}?0:1]
  -DENABLE_VIRT=%[0%{?without_virt}?0:1]

  -DENABLE_FLAMEGRAPH=%[0%{?without_flamegraph}?0:1]
  -DENABLE_L7=%[0%{?without_l7}?0:1]
  -DENABLE_TCP=%[0%{?without_tcp}?0:1]
  -DENABLE_SOCKET=%[0%{?without_socket}?0:1]
  -DENABLE_IO=%[0%{?without_io}?0:1]
  -DENABLE_PROC=%[0%{?without_proc}?0:1]
  -DENABLE_JVM=%[0%{?without_jvm}?0:1]
  -DENABLE_POSTGRE_SLI=%[0%{?without_postgre_sli}?0:1]
  -DENABLE_OPENGAUSS_SLI=%[0%{?without_opengauss_sli}?0:1]
  -DENABLE_NGINX=%[0%{?without_nginx}?0:1]
  -DENABLE_TPROFILING=%[0%{?without_tprofiling}?0:1]
  -DENABLE_KAFKA=%[0%{?without_kafka}?0:1]
  -DENABLE_HW=%[0%{?without_hw}?0:1]
  -DENABLE_KSLI=%[0%{?without_ksli}?0:1]
  -DENABLE_CONTAINER=%[0%{?without_cadvisor}?0:1]
  -DENABLE_SERMANT=%[0%{?without_sermant}?0:1]
  -DENABLE_SLI=%[0%{?without_sli}?0:1]

  -DENABLE_REPORT_EVENT=%[0%{?disable_report_event}?0:1]
  -DKAFKA_CHANNEL=%[0%{?disable_kafka_channel}?0:1]
  -DFLAMEGRAPH_SVG=%[0%{?disable_flamegraph_svg}?0:1]
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
install -d %{buildroot}/%{gopher_state_dir}
install -d %{buildroot}/var/log/gala-gopher
pushd build
sh install.sh %{buildroot}%{_bindir} %{buildroot}/opt/gala-gopher %{buildroot}/etc/gala-gopher %{buildroot}/usr/libexec/gala-gopher/ %{buildroot}/opt/gala-gopher
popd

%pre

%post
%systemd_post gala-gopher.service

%preun
%systemd_preun gala-gopher.service

%postun
if [ $1 -eq 0 ]; then
  rm -rf /sys/fs/bpf/gala-gopher > /dev/null
  rm -rf /opt/gala-gopher > /dev/null
fi
%systemd_postun_with_restart gala-gopher.service

%files
%attr(0750,root,root) %dir /var/log/gala-gopher
%attr(0750,root,root) %dir %{gopher_state_dir}
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
%attr(0640,root,root) %config(noreplace) /etc/gala-gopher/probes.init
%attr(0640,root,root) %config(noreplace) /etc/gala-gopher/*.conf
%attr(0640,root,root) %config(noreplace) /etc/gala-gopher/extend_probes/*.conf
%attr(0600,root,root) /usr/lib/systemd/system/gala-gopher.service
%attr(0550,root,root) /usr/libexec/gala-gopher/init_probes.sh
%attr(0550,root,root) /usr/libexec/gala-gopher/start_pre.sh

%changelog

