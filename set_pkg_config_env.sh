#! /bin/bash

echo "prefix=/usr/local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=/usr/local/include/bm

Name: BMv2
Description: Behavioral Model
Version: 1.15.0
Libs: -L\${libdir} -lbmall
Cflags: -I\${includedir}" >/usr/local/lib/pkgconfig/bm.pc

echo "prefix=/usr/local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=/usr/local/include/bm

Name: BMv2
Description: Behavioral Model
Version: 1.15.0
Libs: -L\${libdir} -lbmruntime
Cflags: -I\${includedir}" >/usr/local/lib/pkgconfig/bmruntime.pc

echo "prefix=/usr/lib/
exec_prefix=\${prefix}
libdir=\${exec_prefix}
includedir=/usr/include/boost

Name: boost_system
Description: Boost System
Version: 1.83.0
Libs: -L\${libdir} -lboost_system
Cflags: -I\${includedir}" >/usr/local/lib/pkgconfig/boost_system.pc

echo "prefix=/usr/local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=/usr/local/include/bm

Name: simple switch
Description: Behavioral Model Target Simple Switch
Version: 1.15.0
Libs: -L\${libdir} -lsimpleswitch_thrift
Cflags: -I\${includedir}" >/usr/local/lib/pkgconfig/simple_switch.pc

echo "prefix=/usr/local
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=/usr/local/include/bm

Name: psa switch
Description: Behavioral Model Target PSA Switch
Version: 1.15.0
Libs: -L\${libdir} -lpsaswitch_thrift
Cflags: -I\${includedir}" >/usr/local/lib/pkgconfig/psa_switch.pc