# Copyright 2015 
# Matthew

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-pcap_dnsproxy-app
PKG_VERSION:= 0.1
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define Package/luci-pcap_dnsproxy-app
	SECTION:=luci
	CATEGORY:=Luci
	SUBMENU:=3. Applications
	TITLE:=
	DEPENDS:=
endef

define Package/luci-pcap_dnsproxy-app/description

endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-pcap_dnsproxy-app/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller

	$(INSTALL_CONF) ./files/etc/config/pcap_dnsproxy $(1)/etc/config/pcap_dnsproxy
	$(INSTALL_CONF) ./files/init.d/pcap_dnsproxy.sh $(1)/etc/init.d/pcap_dnsproxy.sh
	$(INSTALL_CONF) ./files/pcap_dnsproxy $(1)/etc/pcap_dnsproxy
	$(INSTALL_DATA) ./files/usr/controller/pcap_dnsproxy.lua $(1)/usr/lib/lua/luci/controller/pcap_dnsproxy.lua
	$(INSTALL_DATA) ./files/usr/model/pcap_dnsproxy.lua $(1)/usr/lib/lua/luci/model/cbi/pcap_dnsproxy.lua
	endef


$(eval $(call BuildPackage,luci-pcap_dnsproxy-app))
