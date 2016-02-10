Format:         1.0
Source:         alerts-list
Version:        0.7.0-1
Binary:         libalerts-list0, alerts-list-dev
Architecture:   any all
Maintainer:     John Doe <John.Doe@example.com>
Standards-Version: 3.9.5
Build-Depends: bison, debhelper (>= 8),
    pkg-config,
    automake,
    autoconf,
    libtool,
    libsodium-dev,
    libzmq4-dev,
    libuuid-dev,
    libczmq-dev,
    libmlm-dev,
    libbiosproto-dev,
    dh-autoreconf

Package-List:
 libalerts-list0 deb net optional arch=any
 alerts-list-dev deb libdevel optional arch=any

