-- Copyright 2015
-- Matthew
-- Licensed to the public under the Apache License 2.0.

local fs = require "nixio.fs"

local state_msg = ""
local ss_redir_on = (luci.sys.call("pidof Pcap_DNSProxy > /dev/null") == 0)
if ss_redir_on then	
	state_msg = "<b><font color=\"green\">" .. translate("Running") .. "</font></b>"
else
	state_msg = "<b><font color=\"red\">" .. translate("Not running") .. "</font></b>"
end

m = Map("pcap_dnsproxy", translate("Pcap_DnsProxy"),
	translate("A fast secure tunnel proxy that help you get through firewalls on your router") .. " - " .. state_msg)

s = m:section(TypedSection, "base", "")
s.anonymous = true


s:tab("general",  translate("General Settings"))
s:tab("gen_dns",  translate("General DNS Request"))
s:tab("local_req",  translate("Local DNS Request"))
s:tab("adv_switches",  translate("Advanced Switches"))
s:tab("proxy_set",  translate("Proxy Settings"))
s:tab("advanced",  translate("Advanced Settings"))
s:tab("users_host_file",  translate("Users Host File"))
s:tab("config_file",  translate("Config File"))

---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- General Settings
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


switch = s:taboption("general", Flag, "enabled", translate("Enable"), translate("<a href=\"https://github.com/chengr28/Pcap_DNSProxy/tree/Release/Documents\">Documents</a>"))
switch.rmempty = false

opera_mode = s:taboption("general", ListValue, "opera_mode", translate("Operation Mode"))
opera_mode:value("Server")
opera_mode:value("Private")
opera_mode:value("Proxy")
opera_mode:value("Custom")

server_port = s:taboption("general", Value, "server_port", translate("Server Port"))
server_port.default = "1053"
server_port.datatype = "port"

listen_protocol = s:taboption("general", ListValue, "listen_protocol", translate("Listen Protocol"))
listen_protocol:value("IPv4 + IPv6 + TCP + UDP")
listen_protocol:value("IPv4 + IPv6 + UDP")
listen_protocol:value("IPv4 + IPv6 + TCP")
listen_protocol:value("IPv4 + TCP + UDP")
listen_protocol:value("IPv6 + TCP + UDP")
listen_protocol:value("IPv4 + UDP")
listen_protocol:value("IPv4 + TCP")
listen_protocol:value("IPv6 + UDP")
listen_protocol:value("IPv6 + TCP")

read_timeout = s:taboption("general", Value, "read_timeout", translate("Pcap Reading Timeout"))
read_timeout.default = "200"

gen_ipv4_req = s:taboption("general", Value, "gen_ipv4_req", translate("IPv4 DNS Address"))
gen_ipv4_req:value("8.8.8.8:53")
gen_ipv4_req:value("8.8.4.4:53")
gen_ipv4_req.default = "8.8.4.4:53"

alt_ipv4_req = s:taboption("general", Value, "alt_ipv4_req", translate("IPv4 DNS Address Alternate"))
alt_ipv4_req:value("8.8.8.8:53|208.67.220.220:443|208.67.222.222:5353")
alt_ipv4_req.default = "8.8.8.8:53|208.67.220.220:443|208.67.222.222:5353"

gen_ipv4_lo_req = s:taboption("general", Value, "gen_ipv4_lo_req", translate("IPv4 DNS Address"))
gen_ipv4_lo_req:value("114.114.114.114:53")
gen_ipv4_lo_req:value("114.114.115.115:53")
gen_ipv4_lo_req:value("223.5.5.5:53")
gen_ipv4_lo_req:value("223.6.6.6:53")
gen_ipv4_lo_req.default = "114.114.115.115:53"

alt_ipv4_lo_req = s:taboption("general", Value, "alt_ipv4_lo_req", translate("IPv4 DNS Address Alternate"))
alt_ipv4_lo_req:value("114.114.114.114:53|223.5.5.5:53|202.96.128.86:53")
alt_ipv4_lo_req.default = "114.114.114.114:53|223.5.5.5:53|202.96.128.86:53"

gen_ipv6_req = s:taboption("general", Value, "gen_ipv6_req", translate("IPv6 DNS Address"))
gen_ipv6_req:value("[2001:4860:4860::8844]:53")
gen_ipv6_req.default = "[2001:4860:4860::8844]:53"

alt_ipv6_req = s:taboption("general", Value, "alt_ipv6_req", translate("IPv6 DNS Address Alternate"))
alt_ipv6_req:value("[2001:4860:4860::8888]:53|[2620:0:CCD::2]:443|[2620:0:CCC::2]:5353")
alt_ipv6_req.default = "[2001:4860:4860::8888]:53|[2620:0:CCD::2]:443|[2620:0:CCC::2]:5353"

gen_req_set = s:taboption("general", Flag, "gen_req_set", translate("Open General DNS Request Settings"))
gen_req_set.default = "0"
gen_req_set.rmempty = false

local_req_set = s:taboption("general", Flag, "local_req_set", translate("Open Local DNS Request Settings"))
local_req_set.default = "0"
local_req_set.rmempty = false

swi_set = s:taboption("general", Flag, "swi_set", translate("Open adv_switches Settings"))
swi_set.default = "0"
swi_set.rmempty = false

proxy_set = s:taboption("general", Flag, "proxy_set", translate("Open Proxy Settings"))
proxy_set.default = "0"
proxy_set.rmempty = false

adv_set = s:taboption("general", Flag, "adv_set", translate("Open Advanced Settings"))
adv_set.default = "0"
adv_set.rmempty = false

conf_fil = s:taboption("general", Flag, "conf_fil", translate("Using Config File")
	, translate("Disable All CGI Settings"))
conf_fil.default = "0"
conf_fil.rmempty = false


---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- General DNS Request
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    




dns_protocol = s:taboption("gen_dns", ListValue, "dns_protocol", translate("DNS Protocol"))
dns_protocol:value("IPv4 + UDP")
dns_protocol:value("IPv4 + TCP")
dns_protocol:value("IPv6 + UDP")
dns_protocol:value("IPv6 + TCP")
dns_protocol:value("IPv4 + IPv6 + UDP")
dns_protocol:value("IPv4 + IPv6 + TCP")
dns_protocol:depends("gen_req_set", "1")

dir_req = s:taboption("gen_dns", ListValue, "dir_req", translate("Direct Request"))
dir_req:value("")
dir_req:value("IPv4")
dir_req:value("IPv6")
dir_req:value("IPv4 + IPv6")
dir_req:depends("gen_req_set", "1")

cache_type = s:taboption("gen_dns", ListValue, "cache_type", translate("Cache Type"))
cache_type:value("queue", translate"Queue")
cache_type:value("timer", translate"Timer")
cache_type:depends("gen_req_set", "1")

cache_par = s:taboption("gen_dns", Value, "cache_par", translate("Cache Parameter")
	, translate("Default Set is 128."))
cache_par.default = "128"
cache_par:depends("gen_req_set", "1")

def_ttl = s:taboption("gen_dns", Value, "def_ttl", translate("Default TTL")
	, translate("Default Set is 900s."))
def_ttl.default = "900"
def_ttl.datatype = "ufloat"
def_ttl:depends("gen_req_set", "1")




---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- Local DNS Request
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


local_protocol = s:taboption("local_req", ListValue, "local_protocol", translate("Local DNS Protocol"))
local_protocol:value("IPv4 + UDP")
local_protocol:value("IPv4 + TCP")
local_protocol:value("IPv6 + UDP")
local_protocol:value("IPv6 + TCP")
local_protocol:value("IPv4 + IPv6 + UDP")
local_protocol:value("IPv4 + IPv6 + TCP")
local_protocol:depends("local_req_set", "1")

req_partition = s:taboption("local_req", Flag, "req_partition", translate("Request Partition(Local Prefer)"),
	translate(""))
req_partition.default = "0"
req_partition:depends("local_req_set", "1")


part_mod = s:taboption("local_req", ListValue, "part_mod", translate("Partition Mod"))
part_mod:value("H", translate("Local Hosts"))
part_mod:value("M", translate("Local Main"))
part_mod:depends ("req_partition", "1")

hosts_fil = s:taboption("local_req", Value, "hosts_fil", translate("Hosts File Name"),
	translate(""))
hosts_fil:value("Hosts.ini|Hosts.conf|Hosts|Hosts.txt|Hosts.csv|WhiteList.txt|WhiteList_User.txt|White_List.txt")
hosts_fil.default = "Hosts.ini|Hosts.conf|Hosts|Hosts.txt|Hosts.csv|WhiteList.txt|WhiteList_User.txt|White_List.txt"
hosts_fil:depends ("part_mod", "H")

local_routing = s:taboption("local_req", Flag, "local_routing", translate("Local Routing"))
local_routing.default = "0"
local_routing:depends ("part_mod", "M")


---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- Advanced Switches
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------   

TCP_fast = s:taboption("adv_switches", Flag, "TCP_fast", translate("TCP Fast Open"),
	translate("IPv4 support needs Liunx version newer than 3.7. IPv6 TFO support needs Liunx version newer than 3.16."))
TCP_fast:depends("swi_set", "1")

alt_mul_req = s:taboption("adv_switches", Flag, "alt_mul_req", translate("Alternate Multi Request"),
	translate(""))
alt_mul_req.default = "0"
alt_mul_req:depends("swi_set", "1")

mul_req = s:taboption("adv_switches", ListValue, "mul_req", translate("Multi Request Times"))
mul_req:value("0")
mul_req:value("1")
mul_req:value("2")
mul_req:value("3")
mul_req:value("4")
mul_req:value("5")
mul_req:value("6")
mul_req:value("7")
mul_req:value("8")
mul_req:value("9")
mul_req:value("10")
mul_req.default = "1"
mul_req:depends("swi_set", "1")


compress = s:taboption("adv_switches", ListValue, "compress", translate("Compression Pointer Mutation"))
compress:value("1")
compress:value("1 + 2")
compress:value("1 + 2 + 3")
compress:depends("swi_set", "1")



---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- Proxy Settings
---------    ---------    ---------    ---------    ---------    ---------   

proxy = s:taboption("proxy_set", Flag, "proxy", translate("Proxy"),
	translate(""))
proxy.default = "0"
proxy:depends ("proxy_set", "1")

socks_proxy = s:taboption("proxy_set", Flag, "socks_proxy", translate("SOCKS Proxy"),
	translate(""))
socks_proxy.default = "0"
socks_proxy:depends ("proxy_set", "1")


socks_proxy_ol = s:taboption("proxy_set", Flag, "socks_proxy_ol", translate("SOCKS Proxy Only"),
	translate(""))
socks_proxy_ol:depends ("socks_proxy", "1")

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
socks_permisson = s:taboption("proxy_set", Flag, "socks_permisson", translate("SOCKS Permisson"),
	translate(""))
socks_permisson:depends ("socks_proxy", "1")

socks_user = s:taboption("proxy_set", Value, "socks_user", translate("User"))
socks_user:depends ("socks_permisson","1")

socks_pwd = s:taboption("proxy_set", Value, "socks_pwd", translate("Password"))
socks_pwd:depends ("socks_permisson","1")

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 

socks_ipv4 = s:taboption("proxy_set", Value, "socks_ipv4", translate("<abbr title=\"Internet protocol Version 4\">IPv4</abbr>-Address")
	, translate("127.0.0.1:1080"))
socks_ipv4:value("127.0.0.1:1080")
socks_ipv4.default = "127.0.0.1:1080"
socks_ipv4:depends ("socks_proxy","1")

socks_ipv6 = s:taboption("proxy_set", Value, "socks_ipv6", translate("<abbr title=\"Internet protocol Version 6\">IPv6</abbr>-Address")
	, translate("[::1]:1080"))
socks_ipv6:value("[::1]:1080")
socks_ipv6.default = "[::1]:1080"
socks_ipv6:depends ("socks_version", "5")

socks_ip = s:taboption("proxy_set", Value, "socks_ip", translate("Target Server")
	, translate("8.8.8.8:53 or [::1]:53"))
socks_ip:value("8.8.8.8:53")
socks_ip.default = "8.8.8.8:53"
socks_ip:depends ("socks_proxy", "1")

soscks_tcp_tiout = s:taboption("proxy_set", Value, "soscks_tcp_tiout", translate("SOCKS Reliable Socket Timeout (TCP)")
	, translate("6000"))
soscks_tcp_tiout:value("6000")
soscks_tcp_tiout.default = "6000"
soscks_tcp_tiout:depends ("socks_proxy", "1")

soscks_udp_tiout = s:taboption("proxy_set", Value, "soscks_udp_tiout", translate("SOCKS Unreliable Socket Timeout (TCP)")
	, translate("3000"))
soscks_udp_tiout:value("3000")
soscks_udp_tiout.default = "3000"
soscks_udp_tiout:depends ("socks_proxy", "1")

socks_version = s:taboption("proxy_set", ListValue, "socks_version", translate("Socks Version"))
socks_version:value("5")
socks_version:value("4a")
socks_version:value("4")
socks_version:depends ("socks_proxy", "1")

socks_protocol = s:taboption("proxy_set", ListValue, "socks_protocol", translate("Proxy protocol"))
socks_protocol:value("IPv4 + UDP")
socks_protocol:value("IPv4 + TCP")
socks_protocol:value("IPv6 + UDP")
socks_protocol:value("IPv6 + TCP")
socks_protocol:value("IPv4 + IPv6 + UDP")
socks_protocol:value("IPv4 + IPv6 + TCP")
socks_protocol:depends ("socks_proxy", "1")

------------   ------------   ------------   ------------   ------------   ------------   ------------   ------------   ------------   ------------   

http_proxy = s:taboption("proxy_set", Flag, "http_proxy", translate("HTTP Proxy"),
	translate(""))
http_proxy.default = "0"
http_proxy:depends ("proxy_set", "1")

http_proxy_ol = s:taboption("proxy_set", Flag, "http_proxy_ol", translate("HTTP Proxy Only"),
	translate(""))
http_proxy_ol:depends ("http_proxy", "1")

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 
http_permisson = s:taboption("proxy_set", Flag, "http_permisson", translate("http Permisson"),
	translate(""))
http_permisson:depends ("http_proxy", "1")

http_user = s:taboption("proxy_set", Value, "http_user", translate("User"))
http_user:depends ("http_permisson","1")

http_pwd = s:taboption("proxy_set", Value, "http_pwd", translate("Password"))
http_pwd:depends ("http_permisson","1")

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- 

http_ipv4 = s:taboption("proxy_set", Value, "http_ipv4", translate("<abbr title=\"Internet protocol Version 4\">IPv4</abbr>-Address")
	, translate("127.0.0.1:1080"))
http_ipv4:value("127.0.0.1:1080")
http_ipv4.default = "127.0.0.1:1080"
http_ipv4:depends ("http_proxy","1")

http_ipv6 = s:taboption("proxy_set", Value, "http_ipv6", translate("<abbr title=\"Internet protocol Version 6\">IPv6</abbr>-Address")
	, translate("[::1]:1080"))
http_ipv6:value("[::1]:1080")
http_ipv6.default = "[::1]:1080"
http_ipv6:depends ("http_proxy", "1")

http_ip = s:taboption("proxy_set", Value, "http_ip", translate("Target Server")
	, translate("8.8.8.8:53 or [::1]:53"))
http_ip:value("8.8.8.8:53")
http_ip.default = "8.8.8.8:53"
http_ip:depends ("http_proxy", "1")

http_protocol = s:taboption("proxy_set", ListValue, "http_protocol", translate("proxy protocol"))
http_protocol:value("IPv4")
http_protocol:value("IPv6")
http_protocol:value("IPv4 + IPv6")
http_protocol:depends ("http_proxy", "1")



---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- Advanced Settings
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    

pcap_cap = s:taboption("advanced", Flag, "pcap_cap", translate("Disable cap Capture"))
pcap_cap.default = "0"
pcap_cap:depends ("adv_set", "1")

server_name = s:taboption("advanced", Value, "server_name", translate("Localhost Server Name"))
server_name.default = "pcap-dnsproxy.localhost.server"
server_name:depends ("adv_set", "1")

addit_path = s:taboption("advanced", Value, "addit_path", translate("Additional Path"),
	translate(""))
addit_path:depends ("adv_set", "1")
--[[
ipfil_type = s:taboption("advanced", ListValue, "ipfil_type", translate("IPFilter Type"),
	translate(""))
ipfil_type:value("Deny")
ipfil_type:value("Permit")
ipfil_type.default = "Deny"
ipfil_type:depends ("opera_mode", "Custom")

ipfil_lv = s:taboption("advanced", Value, "ipfil_lv", translate("IPFilter Level"),
	translate(""))
ipfil_lv:value("0")
ipfil_lv:value("1")
ipfil_lv:value("2")
ipfil_lv:value("3")
ipfil_lv:value("4")
ipfil_lv:value("5")
ipfil_lv:value("6")
ipfil_lv:value("7")
ipfil_lv.default = ""
ipfil_lv:depends ("opera_mode", "Custom")
]]--
ipfil = s:taboption("advanced", Value, "ipfil", translate("IPFilter File Name"),
	translate(""))
ipfil:value("IPFilter.ini|IPFilter.conf|IPFilter.dat|IPFilter.csv|IPFilter|Guarding.p2p|Guarding|Routing.txt|chnrouting.txt|chnroute.txt")
ipfil.default = "IPFilter.ini|IPFilter.conf|IPFilter.dat|IPFilter.csv|IPFilter|Guarding.p2p|Guarding|Routing.txt|chnrouting.txt|chnroute.txt"
ipfil:depends ("adv_set", "1")

dev_black = s:taboption("advanced", Value, "dev_black", translate("Devices Blacklist"))
dev_black:value("Pseudo|Virtual|Tunnel|VPN|PPTP|L2TP|IKE|ISATAP|Teredo|AnyConnect|Hyper|Oracle|Host|Only|VMware|VMNet|lo|any")
dev_black.default = "Pseudo|Virtual|Tunnel|VPN|PPTP|L2TP|IKE|ISATAP|Teredo|AnyConnect|Hyper|Oracle|Host|Only|VMware|VMNet|lo|any"
dev_black:depends ("adv_set", "1")

queue_lim = s:taboption("advanced", Value, "queue_lim", translate("Buffer Queue Limits"))
queue_lim:value("16")
queue_lim:value("32")
queue_lim:value("64")
queue_lim.default = "32"
queue_lim.datatype = "range(8,1488095)"
queue_lim:depends ("adv_set", "1")

queue_lim_re = s:taboption("advanced", Value, "queue_lim_re", translate("Queue Limits Reset Time"),
	translate(""))
queue_lim_re:value("0")
queue_lim_re:value("300")
queue_lim_re:value("600")
queue_lim_re.default = "0"
queue_lim_re:depends ("adv_set", "1")

recv_wait = s:taboption("advanced", Value, "recv_wait", translate("Receive Waiting"),
	translate(""))
recv_wait:value("0")
recv_wait:value("200")
recv_wait:value("300")
recv_wait.default = "0"
recv_wait:depends ("adv_set", "1")


---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    

dnscurve = s:taboption("advanced", Flag, "dnscurve", translate("DNSCurve"),
	translate("Options for advanced users"))
dnscurve.disabled = "0"
dnscurve.default = "0"
dnscurve:depends ("adv_set", "1")

dnscurve_crypted = s:taboption("advanced", Flag, "dnscurve_crypted", translate("Encryption"),
	translate("Options for advanced users"))
dnscurve_crypted:depends ("dnscurve", "1")

encrypt_ol = s:taboption("advanced", Flag, "encrypt_ol", translate("Encryption Only"),
	translate("Options for advanced users"))
encrypt_ol:depends ("dnscurve_encryption", "1")

dnscurve_protocol = s:taboption("advanced", ListValue, "dnscurve_protocol", translate("DNSCurve Protocol"))
dnscurve_protocol:value("IPv4 + UDP")
dnscurve_protocol:value("IPv4 + TCP")
dnscurve_protocol:value("IPv6 + UDP")
dnscurve_protocol:value("IPv6 + TCP")
dnscurve_protocol:value("IPv4 + IPv6 + UDP")
dnscurve_protocol:value("IPv4 + IPv6 + TCP")
dnscurve_protocol:depends("dnscurve", "1")

dnscurve_ipv4 = s:taboption("advanced", Value, "dnscurve_ipv4", translate("<abbr title=\"Internet protocol Version 4\">IPv4</abbr>-Address")
	, translate("208.67.220.220:443"))
dnscurve_ipv4:value("208.67.220.220:443")
dnscurve_ipv4.default = "208.67.220.220:443"
dnscurve_ipv4:depends ("dnscurve","1")

dnscurve_ipv4_alt = s:taboption("advanced", Value, "dnscurve_ipv4_alt", translate("<abbr title=\"Internet protocol Version 4\">IPv4</abbr>-Address Alternate")
	, translate("113.20.8.17:443"))
dnscurve_ipv4_alt:value("113.20.8.17:443")
dnscurve_ipv4_alt.default = "113.20.8.17:443"
dnscurve_ipv4_alt:depends ("dnscurve","1")

dnscurve_ipv6 = s:taboption("advanced", Value, "dnscurve_ipv6", translate("<abbr title=\"Internet protocol Version 6\">IPv6</abbr>- Address")
	, translate("[2620:0:CCC::2]:443"))
dnscurve_ipv6:value("[2620:0:CCC::2]:443")
dnscurve_ipv6.default = "[2620:0:CCC::2]:443"
dnscurve_ipv6:depends ("dnscurve", "1")

dnscurve_ipv6_alt = s:taboption("advanced", Value, "dnscurve_ipv6_alt", translate("<abbr title=\"Internet protocol Version 6\">IPv6</abbr>-Address Alternate ")
	, translate("[2A00:D880:3:1::A6C1:2E89]:443"))
dnscurve_ipv6_alt:value("[2A00:D880:3:1::A6C1:2E89]:443")
dnscurve_ipv6_alt.default = "[2A00:D880:3:1::A6C1:2E89]:443"
dnscurve_ipv6_alt:depends ("dnscurve", "1")

---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- Users Host File
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------   

host_fil_p = s:taboption("users_host_file", Value, "host_fil_p", translate("Host File"), 
	translate(".*\bbaidu\.com"))
host_fil_p.template = "cbi/tvalue"
host_fil_p.rows = 30
host_fil_p:depends ("part_mod", "H")


function host_fil_p.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/pcap_dnsproxy/WhiteList_User.txt")
end

function host_fil_p.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("//etc/pcap_dnsproxy/WhiteList_User.txt", value)
end

---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


-- Config File
---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------   

config_file_p = s:taboption("config_file", Value, "config_file_p", translate("Config File"), 
	translate(""))
config_file_p.template = "cbi/tvalue"
config_file_p.rows = 30
config_file_p:depends ("conf_fil", "1")


function config_file_p.cfgvalue(self, section)
	return nixio.fs.readfile("/etc/pcap_dnsproxy/user/Config.conf")
end

function config_file_p.write(self, section, value)
	value = value:gsub("\r\n?", "\n")
	nixio.fs.writefile("//etc/pcap_dnsproxy/user/Config.conf", value)
end

---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    ---------    


local apply = luci.http.formvalue("cbi.apply")
if apply then
	io.popen("/etc/init.d/pcap_dnsproxy restart")
end




return m
