-- Copyright 2015
-- Matthew
-- Licensed to the public under the Apache License 2.0.

module("luci.controller.pcap_dnsproxy", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/pcap_dnsproxy") then
		return
	end

	local page

	page = entry({"admin", "services", "pcap_dnsproxy"}, cbi("pcap_dnsproxy"), _("Pcap_DNSProxy"))
	page.dependent = true
end
