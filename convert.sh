#!/bin/bash
/home/zane/Code/research/checkedC/build/bin/3c \
-dump-stats \
-itypes-for-extern \
-alltypes \
-addcr \
-p \
$BASEDIR/compile_commands.json \
-extra-arg=-w \
-base-dir=$BASEDIR \
-output-dir=$BASEDIR/out.checked \
$BASEDIR/src/event.c \
$BASEDIR/src/client.c \
$BASEDIR/src/xslt.c \
$BASEDIR/src/avl/avl.c \
$BASEDIR/src/log/log.c \
$BASEDIR/src/slave.c \
$BASEDIR/src/sighandler.c \
$BASEDIR/src/format_skeleton.c \
$BASEDIR/src/fserve.c \
$BASEDIR/src/admin.c \
$BASEDIR/src/format.c \
$BASEDIR/src/stats.c \
$BASEDIR/src/format_ogg.c \
$BASEDIR/src/auth_htpasswd.c \
$BASEDIR/src/format_kate.c \
$BASEDIR/src/format_flac.c \
$BASEDIR/src/format_opus.c \
$BASEDIR/src/connection.c \
$BASEDIR/src/format_midi.c \
$BASEDIR/src/format_ebml.c \
$BASEDIR/src/util.c \
$BASEDIR/src/format_mp3.c \
$BASEDIR/src/cfgfile.c \
$BASEDIR/src/format_vorbis.c \
$BASEDIR/src/md5.c \
$BASEDIR/src/net/resolver.c \
$BASEDIR/src/main.c \
$BASEDIR/src/auth.c \
$BASEDIR/src/source.c \
$BASEDIR/src/refbuf.c \
$BASEDIR/src/logging.c \
$BASEDIR/src/net/sock.c \
$BASEDIR/src/httpp/httpp.c \
$BASEDIR/src/thread/thread.c \
$BASEDIR/src/global.c \
$BASEDIR/src/timing/timing.c
