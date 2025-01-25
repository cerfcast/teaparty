# SPDX-License-Identifier: GPL-3.0-only
#
# Copyright (C) 2025 Cerfcast, Will Hawkins

include $(TOPDIR)/rules.mk

PKG_NAME:=teaparty
PKG_VERSION:=0.0.1
# This should be incremented when there is a change to the installation
# artifacts without a commensurate increase in the application's version.
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/cerfcast/teaparty.git
# The git commit that will be downloaded and built. (Yes,
# it can be a tag: 
# https://openwrt.org/docs/guide-developer/packages#use_source_repository)
PKG_SOURCE_VERSION:=3e32555f09ecc70d84a6705912dfef2470d36e03
# Eventually this will be a feature that we want to use:
# See https://openwrt.org/docs/guide-developer/packages.
PKG_MIRROR_HASH:=skip
PKG_MAINTAINER:=Will Hawkins <hawkinsw@obs.cr>
PKG_LICENSE:=GPL-3.0-only
#PKG_CPE_ID:=cpe:/a:ripgrep_project:ripgrep

# Require that Rust be available for (cross) compilation betwee
# the host and the OpenWRT platform.
PKG_BUILD_DEPENDS:=rust/host
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk
# Note: You must be very careful about the location of this `Makefile`
# with respect to this `.mk` file.
include ../../../feeds/packages/lang/rust/rust-package.mk

define Package/teaparty
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Teaparty STAMP Sender/Reflector
  DEPENDS:=$(RUST_ARCH_DEPENDS)
  URL:=https://github.com/cerfcast/teaparty
endef

define Package/teaparty/description
  Teaparty is an implementation of a STAMP Sender/Reflector
	(RFC 8762 and 8972).
endef

$(eval $(call RustBinPackage,teaparty))
$(eval $(call BuildPackage,teaparty))
