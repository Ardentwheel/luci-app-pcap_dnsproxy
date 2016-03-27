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
	$(INSTALL_DATA) ./files/etc/config/pcap_dnsproxy $(1)/etc/config/pcap_dnsproxy
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/init.d/pcap_dnsproxy.sh $(1)/etc/init.d/pcap_dnsproxy.sh
	
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/pcap_dnsproxy/config $(1)/etc/pcap_dnsproxy/config
	$(INSTALL_DATA) ./files/pcap_dnsproxy/Hosts.conf $(1)/etc/pcap_dnsproxy/Hosts.conf
	$(INSTALL_DATA) ./files/pcap_dnsproxy/IPFilter.conf $(1)/etc/pcap_dnsproxy/IPFilter.conf
	$(INSTALL_DATA) ./files/pcap_dnsproxy/Routing.txt $(1)/etc/pcap_dnsproxy/Routing.txt
	$(INSTALL_DATA) ./files/pcap_dnsproxy/WhiteList.txt $(1)/etc/pcap_dnsproxy/WhiteList.txt
	$(INSTALL_DATA) ./files/pcap_dnsproxy/WhiteList_User.txt $(1)/etc/pcap_dnsproxy/WhiteList_User.txt
	$(INSTALL_DATA) ./files/pcap_dnsproxy/user/Config.conf $(1)/etc/pcap_dnsproxy/user/Config.conf
	$(INSTALL_DATA) ./files/pcap_dnsproxy/user/Hosts.conf $(1)/etc/pcap_dnsproxy/user/Hosts.conf
	$(INSTALL_DATA) ./files/pcap_dnsproxy/user/IPFilter.conf $(1)/etc/pcap_dnsproxy/user/IPFilter.conf
	$(INSTALL_DATA) ./files/pcap_dnsproxy/user/Routing.txt $(1)/etc/pcap_dnsproxy/user/Routing.txt
	$(INSTALL_DATA) ./files/pcap_dnsproxy/user/WhiteList.txt $(1)/etc/pcap_dnsproxy/user/WhiteList.txt
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/controller/pcap_dnsproxy.lua $(1)/usr/lib/lua/luci/controller/pcap_dnsproxy.lua
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./files/usr/model/pcap_dnsproxy.lua $(1)/usr/lib/lua/luci/model/cbi/pcap_dnsproxy.lua

	endef


$(eval $(call BuildPackage,luci-pcap_dnsproxy-app))
