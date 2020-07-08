#
# Creates Pidgin win32 installer and pidgin_gpg plugin
#
# The Pidgin version is based on the latest version tag in the official repo including:
#	"XEP-0280 (Message Carbons)" patch from http://developer.pidgin.im/ticket/15508
#
# The pidgin-gpg plugin is based on https://github.com/Draghtnod/Pidgin-GPG
#   (This fork has been updated widh XEP-0280 support and countless fixes)
#
# Note:
# Bonjour is disabled because Apple doesn't like that someone downloads their Bonjour SDK
# automatically. Do this manually if you want Bonjour, place the SDK into /root/win32-dev/BonjourSDK
# and remove the patch at the bottom of this Document.
#

FROM	debian:wheezy

# Get all packages and sources neccessary to compile pidgin
RUN	echo	"deb ftp://ftp.debian.org/debian wheezy main\n" \
			"deb ftp://ftp.debian.org/debian wheezy-updates main\n" \
			"deb http://security.debian.org wheezy/updates main\n" \
		> /etc/apt/sources.list && \
	apt-get update && \
	apt-get install -y curl unzip mercurial mingw32-runtime gcc-mingw32 build-essential gettext intltool wget zip nsis && \
	apt-get clean

WORKDIR	/root

# Download and install NSIS nsisunz plugin
RUN	curl -sSO http://nsis.sourceforge.net/mediawiki/images/1/1c/Nsisunz.zip && \
	unzip -q Nsisunz.zip && \
	cp nsisunz/Release/nsisunz.dll /usr/share/nsis/Plugins/

# Time to download the dependencies
RUN	mkdir win32-dev
WORKDIR	/root/win32-dev

# Download GTK+
RUN	curl -sSO http://ftp.gnome.org/pub/gnome/binaries/win32/gtk+/2.14/gtk+-bundle_2.14.7-20090119_win32.zip && \
	unzip -q gtk+-bundle_2.14.7-20090119_win32.zip -d gtk_2_0-2.14

# Download gettext
RUN	curl -sSO http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-tools-0.17.zip && \
	unzip -q gettext-tools-0.17.zip -d gettext-0.17 && \
	curl -sSO http://ftp.gnome.org/pub/gnome/binaries/win32/dependencies/gettext-runtime-0.17-1.zip && \
	unzip -q gettext-runtime-0.17-1.zip -d gettext-0.17

# Download Libxml2
RUN	curl -sSO http://ftp.gnome.org/pub/GNOME/binaries/win32/dependencies/libxml2-dev_2.9.0-1_win32.zip && \
	unzip -q libxml2-dev_2.9.0-1_win32.zip -d libxml2-2.9.0 && \
	curl -sSO http://ftp.gnome.org/pub/GNOME/binaries/win32/dependencies/libxml2_2.9.0-1_win32.zip && \
	unzip -q libxml2_2.9.0-1_win32.zip -d libxml2-2.9.0

# Download Perl 5.10
RUN	curl -sSO https://developer.pidgin.im/static/win32/perl_5-10-0.tar.gz && \
	tar xfz perl_5-10-0.tar.gz

# Download Tcl 8.4.5
RUN	curl -sSO https://developer.pidgin.im/static/win32/tcl-8.4.5.tar.gz && \
	tar xfz tcl-8.4.5.tar.gz

# Download GtkSpell
RUN	curl -sSO https://developer.pidgin.im/static/win32/gtkspell-2.0.16.tar.bz2 && \
	tar xfj gtkspell-2.0.16.tar.bz2

# Downlaod Enchant
RUN	curl -sSO https://developer.pidgin.im/static/win32/enchant_1.6.0_win32.zip && \
	unzip -q enchant_1.6.0_win32.zip

# Download Mozills NSS
RUN	curl -sSO https://developer.pidgin.im/static/win32/nss-3.17.1-nspr-4.10.7.tar.gz && \
	tar xfz nss-3.17.1-nspr-4.10.7.tar.gz

# Download SILC Toolkit
RUN	curl -sSO https://developer.pidgin.im/static/win32/silc-toolkit-1.1.10.tar.gz && \
	tar xfz silc-toolkit-1.1.10.tar.gz

# Download Meanwhile
RUN	curl -sSO https://developer.pidgin.im/static/win32/meanwhile-1.0.2_daa3-win32.zip && \
	unzip -q meanwhile-1.0.2_daa3-win32.zip

# Download Cyrus SASL
RUN	curl -sSO https://developer.pidgin.im/static/win32/cyrus-sasl-2.1.25.tar.gz && \
	tar xfz cyrus-sasl-2.1.25.tar.gz

# Download Intltool
RUN	curl -sSO http://ftp.acc.umu.se/pub/GNOME/binaries/win32/intltool/0.40/intltool_0.40.4-1_win32.zip && \
	unzip -q intltool_0.40.4-1_win32.zip -d intltool_0.40.4-1_win32

# Download Crash Report Library and install NSIS SHA1Plugin
RUN	curl -sSO https://developer.pidgin.im/static/win32/pidgin-inst-deps-20130214.tar.gz && \
	tar xfz pidgin-inst-deps-20130214.tar.gz && \
	cp pidgin-inst-deps-20130214/SHA1Plugin.dll /usr/share/nsis/Plugins/

# Clone the Pidgin repo and update to latest version tag
RUN	cd /root && \
	echo "Cloning Pidgin repository, time to get a coffee..." && \
	hg clone https://hg.pidgin.im/pidgin/main pidgin-main
WORKDIR	/root/pidgin-main
RUN	hg up $(hg tags | sed -n '2p' | sed 's/ \w*:\w*//') && \
	echo	"SHELL := /bin/bash\n" \
		"CC := /usr/bin/i586-mingw32msvc-cc\n" \
		"GMSGFMT := /usr/bin/msgfmt\n" \
		"MAKENSIS := /usr/bin/makensis\n" \
		"WINDRES := /usr/bin/i586-mingw32msvc-windres\n" \
		"STRIP := /usr/bin/i586-mingw32msvc-strip\n" \
		"INTLTOOL_MERGE := /usr/bin/intltool-merge\n" \
		"GTK_BIN := /usr/bin\n" \
		"MONO_SIGNCODE := echo ***Bypassing signcode***\n" \
		"GPG_SIGN := echo ***Bypassing gpg***\n" \
		> local.mak

# Disable Bonjour Protocol, as the Bonjour SDK can not be automatically downloaded. If you want Bonjour, download the SDK manually and remove this patch!
RUN	cd libpurple/protocols && \
	echo	"11c11\n< SUBDIRS = gg irc jabber msn mxit novell null oscar sametime silc simple yahoo bonjour myspace\n---\n> SUBDIRS = gg irc jabber msn mxit novell null oscar sametime silc simple yahoo myspace" > noBonjour.patch && \
	patch Makefile.mingw < noBonjour.patch

# Download and apply the carbons patch
RUN	curl -sSO https://developer.pidgin.im/raw-attachment/ticket/15508/carbons.5.patch && \
	patch -p1 < carbons.5.patch

# Compile the patched pidgin
RUN	ln -s /usr/lib/gcc/i686-w64-mingw32/4.6/libssp-0.dll /usr/bin/libssp-0.dll && \
	make -f Makefile.mingw installers

WORKDIR	/root

# Clone and compile Pidgin-GPG with XEP-0280 support
RUN	apt-get install -y libpurple-dev libgpgme11-dev libtool gcc-multilib && \
	apt-get clean
RUN	git clone https://github.com/Draghtnod/Pidgin-GPG.git
RUN	cd Pidgin-GPG && \
	mv /usr/lib/x86_64-linux-gnu/libglib-2.0.a /usr/lib/x86_64-linux-gnu/libglib-2.0.a.hide && \
	autoreconf -i && \
	./win32.sh

# Copy the binaries back to the host
ENTRYPOINT echo "****** Use these Files to install Pidgin *****" && \
	cp -v \
	pidgin-main/pidgin-2.*.exe \
	pidgin-main/pidgin-2.*.zip \
	/output/ && \
	echo "***** Put these files in the pidgin main folder *****" && \
	cp -v Pidgin-GPG/win32libs/libgpgme.dll /output/libgpgme-11.dll && \
	cp -v Pidgin-GPG/win32libs/libgpg-error.dll /output/libgpg-error-0.dll && \
	echo "***** This file has to go into the plugin folder *****" && \
	cp -v Pidgin-GPG/src/.libs/pidgin_gpg.dll /output/

# Mission accomplished!
RUN	echo	"**************\n" \
		"Your pidgin files are ready! Time to get them with:\n" \
		"docker run -v [your output folder]:/output [this image]\n" \
		"Enjoy!\n" \
		"**************"

