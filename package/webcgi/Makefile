
include $(TOPDIR)/rules.mk

PKG_NAME:=webcgi
PKG_VERSION:=1.0

PKG_BUILD_DIR:= $(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/webcgi
	SECTION  := net
 	CATEGORY := Network
	TITLE    := web management cgi for httpd server 
	DEPENDS  := +libadapter 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/webcgi/install
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(CP) $(PKG_BUILD_DIR)/*.cgi $(1)/www/cgi-bin
	$(INSTALL_BIN) ./files/port_status.cgi $(1)/www/cgi-bin/
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/web-cgi $(1)/usr/sbin/
	$(CP) $(PKG_BUILD_DIR)/*.cli $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/cgi_reload.sh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/ct_default.sh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/ct_ntwk.sh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/ct_ipsec.sh $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/ct_wan_event.sh $(1)/usr/sbin/
	$(INSTALL_DIR) $(1)/etc/scripts/firewall
	$(INSTALL_BIN) ./files/002-ct_ntwk.rule $(1)/etc/scripts/firewall
	$(INSTALL_BIN) ./files/004-ct_ipsec.rule $(1)/etc/scripts/firewall
	$(INSTALL_BIN) ./files/005-ct_fw.rule $(1)/etc/scripts/firewall
endef

$(eval $(call BuildPackage,webcgi))
