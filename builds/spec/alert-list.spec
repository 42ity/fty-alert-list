#
#    alert-list - Provides information about active and resolved alerts
#
#    Copyright (c) the Authors
#

Name:           alert-list
Version:        0.1.0
Release:        1
Summary:        provides information about active and resolved alerts
License:        GPL-2.0+
URL:            https://eaton.com/
Source0:        %{name}-%{version}.tar.gz
Group:          System/Libraries
BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  pkg-config
BuildRequires:  zeromq-devel
BuildRequires:  czmq-devel
BuildRequires:  malamute-devel
BuildRequires:  biosproto-devel
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
alert-list provides information about active and resolved alerts.

%package -n libalert_list0
Group:          System/Libraries
Summary:        provides information about active and resolved alerts

%description -n libalert_list0
alert-list provides information about active and resolved alerts.
This package contains shared library.

%post -n libalert_list0 -p /sbin/ldconfig
%postun -n libalert_list0 -p /sbin/ldconfig

%files -n libalert_list0
%defattr(-,root,root)
%doc COPYING
%{_libdir}/libalert_list.so.*

%package devel
Summary:        provides information about active and resolved alerts
Group:          System/Libraries
Requires:       libalert_list0 = %{version}
Requires:       zeromq-devel
Requires:       czmq-devel
Requires:       malamute-devel
Requires:       biosproto-devel

%description devel
alert-list provides information about active and resolved alerts.
This package contains development files.

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libalert_list.so
%{_libdir}/pkgconfig/alert-list.pc

%prep
%setup -q

%build
sh autogen.sh
%{configure}
make %{_smp_mflags}

%install
make install DESTDIR=%{buildroot} %{?_smp_mflags}

# remove static libraries
find %{buildroot} -name '*.a' | xargs rm -f
find %{buildroot} -name '*.la' | xargs rm -f


%changelog
