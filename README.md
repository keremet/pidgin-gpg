pidgin-gpg
==========

This is an OpenPGP/GPG (XEP-0027) plugin for Pidgin.
This fork is compatible to the Message Carbons (XEP-0280) extension.

Download
--------
Windows users can download a precompiled version of the latest release here:
https://github.com/Draghtnod/Pidgin-GPG/releases

Building
--------
    apt install libpurple-dev libgpgme11-dev libtool
    autoreconf -i
    ./configure
    make
	mkdir -p ~/.purple/plugins
    cp src/.libs/pidgin_gpg.so ~/.purple/plugins/

Usage
-----
Select Tools > Plugins, and enable the OpenPGP/GPG plugin. Select
configure and choose your GPG key.

Your OpenPGP/GPG agent needs to be enabled for this plugin to work properly.
You may need to restart pidgin to be prompted for the key passphrase after
enabling this plugin.

About
-----
This is not the official branch. I'm maintianing this fork simply for
maintenence. I'm *am not* actively developing pidgin-gpg, maintly making
sure it keeps working and building. Releases > 0.9 should not be confused
with those of the original author (though the original author seems to
have stopped all development).
