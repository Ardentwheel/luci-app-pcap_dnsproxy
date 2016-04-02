# Copyright 2015 
# Matthew

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-pcap_dnsproxy
PKG_VERSION:= 1.2
PKG_RELEASE:= 1.2

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-pcap_dnsproxy
	SECTION:=luci
	CATEGORY:=LuCI
	SUBMENU:=3. Applications
	TITLE:=LuCI for pcap-dnsproxy
	PKGARCH:=all
	DEPENDS:=+libpthread +libsodium
endef

define Package/luci-app-pcap_dnsproxy/description
	LuCI for pcap-dnsproxy. 
endef

define Build/Prepare
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-pcap_dnsproxy/conffiles
/etc/config/pcap_dnsproxy
endef

define Package/luci-app-pcap_dnsproxy/preinst
endef

define Package/luci-app-pcap_dnsproxy/postinst
#!/bin/sh
	/etc/init.d/pcap_dnsproxy.sh enable
	/etc/init.d/pcap-dnsproxy disable
	[ -e /etc/init.d/pcap-dnsproxy ] && /etc/init.d/pcap-dnsproxy disable
exit 0
endef

define Package/luci-app-pcap_dnsproxy/prerm
#!/bin/sh
	/etc/init.d/pcap_dnsproxy stop
	[ -e /etc/init.d/pcap-dnsproxy ] && /etc/init.d/pcap-dnsproxy enable
exit 0
endef

define Package/luci-app-pcap_dnsproxy/install
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/etc/config/pcap_dnsproxy $(1)/etc/config/pcap_dnsproxy
	
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/pcap_dnsproxy.sh $(1)/etc/init.d/pcap_dnsproxy.sh
	
	$(INSTALL_DIR) $(1)/etc/pcap_dnsproxy
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/config $(1)/etc/pcap_dnsproxy/config
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/Hosts.conf $(1)/etc/pcap_dnsproxy/Hosts.conf
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/IPFilter.conf $(1)/etc/pcap_dnsproxy/IPFilter.conf
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/Routing.txt $(1)/etc/pcap_dnsproxy/Routing.txt
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/WhiteList.txt $(1)/etc/pcap_dnsproxy/WhiteList.txt
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/WhiteList_User.txt $(1)/etc/pcap_dnsproxy/WhiteList_User.txt

	$(INSTALL_DIR) $(1)/etc/pcap_dnsproxy/user
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/user/Config.conf $(1)/etc/pcap_dnsproxy/user/Config.conf
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/user/Hosts.conf $(1)/etc/pcap_dnsproxy/user/Hosts.conf
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/user/IPFilter.conf $(1)/etc/pcap_dnsproxy/user/IPFilter.conf
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/user/Routing.txt $(1)/etc/pcap_dnsproxy/user/Routing.txt
	$(INSTALL_DATA) ./files/etc/pcap_dnsproxy/user/WhiteList.txt $(1)/etc/pcap_dnsproxy/user/WhiteList.txt
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DATA) ./files/usr/controller/pcap_dnsproxy.lua $(1)/usr/lib/lua/luci/controller/pcap_dnsproxy.lua
	
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DATA) ./files/usr/model/pcap_dnsproxy.lua $(1)/usr/lib/lua/luci/model/cbi/pcap_dnsproxy.lua
endef


$(eval $(call BuildPackage,luci-app-pcap_dnsproxy))
