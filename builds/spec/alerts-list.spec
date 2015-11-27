#
#    alerts-list - Provides information about active alerts.
#
#    Copyright (C) 2014 - 2015 Eaton                                        
#                                                                           
#    This program is free software; you can redistribute it and/or modify   
#    it under the terms of the GNU General Public License as published by   
#    the Free Software Foundation; either version 2 of the License, or      
#    (at your option) any later version.                                    
#                                                                           
#    This program is distributed in the hope that it will be useful,        
#    but WITHOUT ANY WARRANTY; without even the implied warranty of         
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
#    GNU General Public License for more details.                           
#                                                                           
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.            
#

Name:           alerts-list
Version:        0.1.0
Release:        1
Summary:        provides information about active alerts.
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
alerts-list provides information about active alerts..

%package -n libalerts_list0
Group:          System/Libraries
Summary:        provides information about active alerts.

%description -n libalerts_list0
alerts-list provides information about active alerts..
This package contains shared library.

%post -n libalerts_list0 -p /sbin/ldconfig
%postun -n libalerts_list0 -p /sbin/ldconfig

%files -n libalerts_list0
%defattr(-,root,root)
%doc COPYING
%{_libdir}/libalerts_list.so.*

%package devel
Summary:        provides information about active alerts.
Group:          System/Libraries
Requires:       libalerts_list0 = %{version}
Requires:       zeromq-devel
Requires:       czmq-devel
Requires:       malamute-devel
Requires:       biosproto-devel

%description devel
alerts-list provides information about active alerts..
This package contains development files.

%files devel
%defattr(-,root,root)
%{_includedir}/*
%{_libdir}/libalerts_list.so
%{_libdir}/pkgconfig/alerts-list.pc

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
