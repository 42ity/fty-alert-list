Format:         1.0
Source:         alerts_list
Version:        0.1.0-1
Binary:         alerts_list, libalerts_list0
Architecture:   any all
Maintainer:     John Doe <John.Doe@example.com>
Standards-Version: 3.9.5
Build-Depends: bison, debhelper (>= 8),
    pkg-config,
    automake,
    autoconf,
    libtool,
    libzmq4-dev,
    libczmq-dev,
    libmlm-dev,
    libbiosproto-dev,
    dh-autoreconf

Package-List:
 alerts_list dev net optional arch-any
 libalerts_list0 dev net optional arch-any

