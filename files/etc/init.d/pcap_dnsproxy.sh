#!/bin/sh /etc/rc.common

START=95

EXTRA_COMMANDS="status atosys rmfsys help"
EXTRA_HELP=<<EOF
	Available Commands: 
		status
		atosys
		rmfsys
		help
EOF

PROGRAM="/usr/sbin/Pcap_DNSProxy"
O_CONF_FIL="/etc/pcap_dnsproxy/config"
CONF_FIL="/etc/pcap_dnsproxy/Config.conf"

CONF_DIR="/etc/pcap_dnsproxy"
CONF_DIR_USER="/etc/pcap_dnsproxy/user"

TMP_DIR="/tmp/etc/pcap_dnsproxy"
TMP_FIL="$TMP_DIR/config-tmp.conf"

general_set() {
	local opera_mode
	local server_port
	local listen_protocol
	local read_timeout
	local gen_ipv4_req
	local alt_ipv4_req
	local gen_ipv4_lo_req
	local alt_ipv4_lo_req
	local gen_ipv6_req
	local alt_ipv6_req
	local gen_req_set
	local local_req_set
	local swi_set
	local adv_set
	local proxy_set
	local gen_ipv6_lo_req
	local alt_ipv6_lo_req
	local dns_protocol
	

	config_get opera_mode $1 opera_mode
	config_get server_port $1 server_port
	config_get listen_protocol $1 listen_protocol
	config_get read_timeout $1 read_timeout
	config_get gen_ipv4_req $1 gen_ipv4_req
	config_get alt_ipv4_req $1 alt_ipv4_req
	config_get gen_ipv4_lo_req $1 gen_ipv4_lo_req
	config_get alt_ipv4_lo_req $1 alt_ipv4_lo_req
	config_get gen_ipv6_req $1 gen_ipv6_req
	config_get alt_ipv6_req $1 alt_ipv6_req
	config_get gen_ipv6_lo_req $1 gen_ipv6_lo_req
	config_get alt_ipv6_lo_req $1 alt_ipv6_lo_req
	config_get gen_req_set $1 gen_req_set
	config_get local_req_set $1 local_req_set
	config_get swi_set $1 swi_set
	config_get proxy_set $1 proxy_set
	config_get adv_set $1 adv_set
	
	config_get dns_protocol $1 dns_protocol

	sed -i -e "/Operation Mode/c Operation Mode = $opera_mode" \
		-e "/Listen Port/c Listen Port = $server_port" \
		-e "/Listen Protocol/c Listen Protocol = $listen_protocol" \
		-e "/Pcap Reading Timeout/c Pcap Reading Timeout = $read_timeout" $TMP_FIL

	sed -i -e "/IPv4 DNS Address = 8.8.4.4:53/c IPv4 DNS Address = $gen_ipv4_req" \
		-e "/IPv4 Alternate DNS Address = 8.8.8.8:53/c IPv4 Alternate DNS Address = $alt_ipv4_req" \
		-e "/IPv4 Local DNS Address/c IPv4 Local DNS Address = $gen_ipv4_lo_req" $TMP_FIL 

	sed -i -e "/IPv4 Local Alternate DNS Address/c IPv4 Local Alternate DNS Address = $alt_ipv4_lo_req" \
		-e "/IPv6 DNS Address = ipv6/c IPv6 DNS Address = $gen_ipv6_req" \
		-e "/IPv6 Alternate DNS Address = ipv6/c IPv6 Alternate DNS Address = $alt_ipv6_req" \
		-e "/IPv6 Local DNS Address = ipv6/c IPv6 Local DNS Address = $gen_ipv6_lo_req" \
		-e "/IPv6 Local Alternate DNS Address = ipv6/c IPv6 Local Alternate DNS Address = $alt_ipv6_lo_req" $TMP_FIL

	GEN_REQ_SET=$gen_req_set
	LOCAL_REQ_SET=$local_req_set
	SWI_SET=$swi_set
	PROXY_SET=$proxy_set
	ADV_SET=$adv_set
	
	DNS_P=$dns_protocol

}

general_req() {
	local dns_protocol
	local dir_req
	local cache_type
	local cache_par
	local def_ttl

	config_get dns_protocol $1 dns_protocol
	config_get dir_req $1 dir_req
	config_get cache_type $1 cache_type
	config_get cache_par $1 cache_par
	config_get def_ttl $1 def_ttl

	echo "Loading General DNS Request Settings... "
	sed -i -e "/Protocol = req_Protocol/c Protocol = $dns_protocol" \
		-e "/Direct Request/c Direct Request = $dir_req" \
		-e "/Cache Type/c Cache Type = $cache_type" \
		-e "/Cache Parameter/c Cache Parameter = $cache_par" \
		-e "/Default TTL/c Default TTL = $def_ttl" $TMP_FIL

	echo '	General Settings loaded. '
	
}

local_req() {
	local local_protocol
	local req_partition
	local part_mod
	local hosts_fil
	local local_routing 

	config_get local_protocol $1 local_protocol
	config_get req_partition $1 req_partition
	config_get part_mod $1 part_mod
	config_get hosts_fil $1 hosts_fil
	config_get local_routing $1 local_routing

	echo "Loading Local DNS Request Settings... "
	sed -i -e "/Local Protocol/c Local Protocol = $local_protocol" $TMP_FIL

	if [ $req_partition ]
	then
		if [ $part_mod == H ] 
		then
			sed -i -e "/Local Hosts/c Local Hosts = 1" \
			-e "/Hosts File Name/c Hosts File Name = $hosts_fil" $TMP_FIL
			echo "	Local Hosts Enabled."
		else if [ $part_mod == M -a $local_routing == 1 ] 
			then
				sed -i -e "/Local Main/c Local Main = 1" \
				-e "/Local Routing/c Local Routing = 1" $TMP_FIL
				echo "	Local Main Enabled."
				echo "	Local Routing Enabled. "
			else if [ $part_mod == M -a $local_routing = 0 ] 
					then 
						sed -i -e "/Local Main/c Local Main = 1" \
						-e "/Local Routing/c Local Routing = 0" $TMP_FIL
						echo "	Local Main Enabled. Local Routing Disable. "
				fi 
			fi
		fi
	else echo '	Request Partition(Local Prefer) Disable. '
	fi
	
}

adv_switches() {
	local TCP_fast
	local alt_mul_req
	local mul_req
	local compress

	config_get TCP_fast $1 TCP_fast
	config_get alt_mul_req $1 alt_mul_req
	config_get mul_req $1 mul_req
	config_get compress $1 compress

	echo "Loading Advanced Switches Settings... "
	sed -i -e "/TCP Fast Open/c TCP Fast Open = $TCP_fast" \
		-e "/Alternate Multi Request/c Alternate Multi Request = $alt_mul_req" \
		-e "/Multi Request Times/c Multi Request Times = $mul_req" \
		-e "/Compression Pointer Mutation/c Compression Pointer Mutation = $compress" $TMP_FIL
	echo '	Advanced Switches loaded. '
	
}

proxy() {
	local proxy
	local socks_proxy
	local socks_proxy_ol
	local socks_permisson
	local socks_user
	local socks_pwd
	local socks_ipv4
	local socks_ipv6
	local socks_ip
	local soscks_tcp_tiout
	local soscks_udp_tiout
	local socks_version
	local socks_protocol
	local http_proxy
	local http_proxy_ol
	local http_permisson
	local http_user
	local http_pwd
	local http_ipv4
	local http_ipv6
	local http_ip
	local http_protocol

	config_get proxy $1 proxy
	config_get socks_proxy $1 socks_proxy
	config_get socks_proxy_ol $1 socks_proxy_ol
	config_get socks_permisson $1 socks_permisson
	config_get socks_user $1 socks_user
	config_get socks_pwd $1 socks_pwd
	config_get socks_ipv4 $1 socks_ipv4
	config_get socks_ipv6 $1 socks_ipv6
	config_get socks_ip $1 socks_ip
	config_get soscks_tcp_tiout $1 soscks_tcp_tiout
	config_get soscks_udp_tiout $1 soscks_udp_tiout
	config_get socks_version $1 socks_version
	config_get socks_protocol $1 socks_protocol
	config_get http_proxy $1 http_proxy
	config_get http_proxy_ol $1 http_proxy_ol
	config_get http_permisson $1 http_permisson
	config_get http_user $1 http_user
	config_get http_pwd $1 http_pwd
	config_get http_ipv4 $1 http_ipv4
	config_get http_ipv6 $1 http_ipv6
	config_get http_ip $1 http_ip
	config_get http_protocol $1 http_protocol

	echo 'Loading Proxy Settings... '

	if [ $proxy ]
		then {

#			socks_proxy
			if [ $socks_proxy ]
			then {
				sed -i -e "/SOCKS Proxy/c SOCKS Proxy = $socks_proxy" \
				-e "/SOCKS Proxy Only/c SOCKS Proxy Only = $socks_proxy_ol" \
				-e "/SOCKS IPv4 Address/c SOCKS IPv4 Address = $socks_ipv4" \
				-e "/SOCKS IPv6 Address/c SOCKS IPv6 Address = $socks_ipv6" \
				-e "/SOCKS Target Server/c SOCKS Target Server = $socks_ip" $TMP_FIL
				sed -i -e "/SOCKS Reliable Socket Timeout/c SOCKS Reliable Socket Timeout = $soscks_tcp_tiout" \
				-e "/SOCKS Unreliable Socket Timeout/c SOCKS Unreliable Socket Timeout = $soscks_udp_tiout" \
				-e "/SOCKS Version/c SOCKS Version = $socks_version" \
				-e "/SOCKS Protocol/c SOCKS Protocol = $socks_protocol" $TMP_FIL

				[ $socks_permisson ] && sed -i \
				-e "/SOCKS Username/c SOCKS Username = $socks_user" \
				-e "/SOCKS Password/c SOCKS Password = $socks_pwd" $TMP_FIL

				echo '	Socks Proxy Enabled. '
				}
			else echo '	Socks Proxy Disabled. '
			fi
		
#			http_proxy
			if [ $http_proxy ]
			then {
				sed -i -e "/HTTP Proxy/c HTTP Proxy = $http_proxy" \
				-e "/HTTP Proxy Only/c HTTP Proxy Only = $http_proxy_ol" \
				-e "/HTTP IPv4 Address/c HTTP IPv4 Address = $http_ipv4" \
				-e "/HTTP IPv6 Address/c HTTP IPv6 Address = $http_ipv6" \
				-e "/HTTP Target Server/c HTTP Target Server = $http_ip" \
				-e "/HTTP Protocol/c HTTP Protocol = $http_protocol" $TMP_FIL

				[ $http_permisson ] && sed -i \
				-e "/SHTTP Proxy Authorization/c HTTP Proxy Authorization = $http_user:$http_pwd" $TMP_FIL
			
				echo '	HTTP Proxy Enabled. '
				}
			else echo '	HTTP Proxy Disabled. '
			fi
		}
		else echo '	Proxy Disabled. '
	fi

}

advanced_set() {
	local server_name
	local addit_path
	local ipfil
	local ipfil_type
	local ipfil_lv
	local dev_black
	local queue_lim
	local queue_lim_re
	local recv_wait
	local dnscurve
	local dnscurve_crypted
	local encrypt_ol
	local dnscurve_protocol
	local dnscurve_ipv4
	local dnscurve_ipv4_alt
	local dnscurve_ipv6
	local dnscurve_ipv6_alt 
	
	config_get server_name $1 server_name
	config_get addit_path $1 addit_path
	config_get ipfil $1 ipfil
	config_get ipfil_type $1 ipfil_type
	config_get ipfil_lv $1 ipfil_lv
	config_get dev_black $1 dev_black
	config_get queue_lim $1 queue_lim
	config_get queue_lim_re $1 queue_lim_re
	config_get recv_wait $1 recv_wait
	config_get dnscurve $1 dnscurve
	config_get dnscurve_crypted $1 dnscurve_crypted
	config_get encrypt_ol $1 encrypt_ol
	config_get dnscurve_protocol  $1 dnscurve_protocol
	config_get dnscurve_ipv4 $1 dnscurve_ipv4
	config_get dnscurve_ipv4_alt $1 dnscurve_ipv4_alt
	config_get dnscurve_ipv6 $1 dnscurve_ipv6
	config_get dnscurve_ipv6_alt $1 dnscurve_ipv6_alt

	echo "Loading Advanced Settings... "

	sed -i -e "/Localhost Server Name/c Localhost Server Name = $server_name" $TMP_FIL
	sed -i -e "/Additional Path/c Additional Path = $addit_path" $TMP_FIL
	sed -i -e "/IPFilter File Name/c IPFilter File Name = $ipfil" $TMP_FIL
	sed -i -e "/Pcap Devices Blacklist/c Pcap Devices Blacklist = $dev_black" $TMP_FIL
	sed -i -e "/Buffer Queue Limits/c Buffer Queue Limits = $queue_lim" $TMP_FIL
	sed -i -e "/Queue Limits Reset Time/c Queue Limits Reset Time = $queue_lim_re" $TMP_FIL
	sed -i -e "/Receive Waiting/c Receive Waiting = $recv_wait" $TMP_FIL
	
	if [ $dnscurve ]
	then {
		sed -i -e "/DNSCurve = 0/c DNSCurve = $dnscurve" \
			-e "/DNSCurve Protocol/c DNSCurve Protocol = $dnscurve_protocol" \
			-e "/Encryption = /c DNSCurve = $dnscurve_crypted" \
			-e "/Encryption Only/c Encryption Only = $encrypt_ol" $TMP_FIL
		sed -i -e "/DNSCurve IPv4 DNS Address/c DNSCurve IPv4 DNS Address = $dnscurve_ipv4" \
			-e "/DNSCurve IPv4 Alternate DNS Address/c DNSCurve IPv4 Alternate DNS Address = $dnscurve_ipv4_alt" \
			-e "/DNSCurve IPv6 DNS Address/c DNSCurve IPv6 DNS Address = $dnscurve_ipv6" \
			-e "/Alternate DNS Address/c Alternate DNS Address = $dnscurve_ipv6_alt" $TMP_FIL
		echo '	DNSCurve Enable. '
		}
	else echo '	DNSCurve Disable. '
	fi

}

dispcap_capture() {
	local pcap_cap
	local hosts_fil

	config_get hosts_fil $1 hosts_fil

	echo "Loading Dispcap Capture Settings... "
	sed -i -e "/Pcap Capture/c Pcap Capture = $pcap_cap" \
		-e "/Hosts File Name/c Hosts File Name = $hosts_fil" $TMP_FIL
	echo '	Dispcap Capture Loaded. '

}

pcap_header() {
	local enabled
	local pcap_cap
	local conf_fil

	config_get enabled $1 enabled
	config_get pcap_cap $1 pcap_cap
	config_get conf_fil $1 conf_fil

	ENABLE=$enabled
	PCAP_CAP=$pcap_cap
	CONF_FIL_EN=$conf_fil

}

start() {
	mkdir -p $TMP_DIR
	cp  $O_CONF_FIL $TMP_FIL
	echo 'Checking Configuration... '

	if [ -e "$CONF_FIL" ] 
	then
		echo "Config File Link exist. Rebuilting... "
		rm -f $CONF_FIL
		ln -s $TMP_FIL $CONF_FIL
		echo "Config File Link Rebuilted. "
	else 
		ln -s $TMP_FIL $CONF_FIL
		echo "Config File Link Rebuilted. "
	fi

	config_load pcap_dnsproxy
	config_foreach pcap_header

	if [ $ENABLE == 1 -a $CONF_FIL_EN == 1 ]
		then
		service_start $PROGRAM -c $CONF_DIR_USER
		[ $(ps|grep ${PROGRAM}|grep -v grep|wc -l) -ge 1 ] && echo "Pcap_DNSProxy Running. PID: $(pidof ${PROGRAM##*/})" || echo "Pcap_DNSProxy Stopped. "
		else if [ $ENABLE == 1 -a ! $PCAP_CAP  ] 
			then {		
				config_foreach general_set
				
				[ $GEN_REQ_SET == 0 ] && {
						echo "dns_protocol: $dns_protocol"
						sed -i -e "/Protocol = req_Protocol/c Protocol = IPv4 + UDP" $TMP_FIL
				}
				
				[ $GEN_REQ_SET == 1 ] && config_foreach general_req 
				[ $LOCAL_REQ_SET == 1 ] && config_foreach local_req 
				[ $SWI_SET == 1 ] && config_foreach adv_switches 
				[ $PROXY_SET == 1 ] && config_foreach proxy 
				[ $ADV_SET == 1 ] && config_foreach advanced_set 
				
				echo "Config Loading finished. "
				echo 'Pcap_DNSProxy Starting...'
				service_start $PROGRAM -c $CONF_DIR
				[ $(ps|grep ${PROGRAM}|grep -v grep|wc -l) -ge 1 ] && echo "Pcap_DNSProxy Running. PID: $(pidof ${PROGRAM##*/})" || echo "Pcap_DNSProxy Stopped. "
				}
			else if [ $ENABLE == 1 -a $PCAP_CAP == 1 ]
					then
						config_foreach dispcap_capture
						echo 'Pcap_DNSProxy Pcap Capture Disabled. Limited.'
						service_start $PROGRAM -c $CONF_DIR
						[ $(ps|grep ${PROGRAM}|grep -v grep|wc -l) -ge 1 ] && echo "Pcap_DNSProxy Running. PID: $(pidof ${PROGRAM##*/})" || echo "Pcap_DNSProxy Stopped. "
					else 
					stop
					echo 'Pcap_DNSProxy Pcap Disabled.'
			fi
		fi
	fi
	echo ' '
}

stop() {
	service_stop $PROGRAM
	[ $(ps|grep ${PROGRAM}|grep -v grep|wc -l) -ge 1 ] && echo "Pcap_DNSProxy Still Running. PID: $(pidof ${PROGRAM##*/})" || echo "Pcap_DNSProxy Stopped. "
}

restart() {
	stop
	sleep 3
	echo ''
	start

}

status() {
	local enabled=`uci get pcap_dnsproxy.@base[0].enabled`
	local listen_protocol=`uci get pcap_dnsproxy.@base[0].listen_protocol 2>/dev/null`
	local opera_mode=`uci get pcap_dnsproxy.@base[0].opera_mode 2>/dev/null`
	local server_port=`uci get pcap_dnsproxy.@base[0].server_port 2>/dev/null`
	local gen_ipv4_req=`uci get pcap_dnsproxy.@base[0].gen_ipv4_req 2>/dev/null`
	local gen_ipv4_lo_req=`uci get pcap_dnsproxy.@base[0].gen_ipv4_lo_req 2>/dev/null`
	local TCP_fast=`uci get pcap_dnsproxy.@base[0].TCP_fast 2>/dev/null`
	local alt_mul_req=`uci get pcap_dnsproxy.@base[0].alt_mul_req 2>/dev/null`
	local mul_req=`uci get pcap_dnsproxy.@base[0].mul_req 2>/dev/null`
	local compress=`uci get pcap_dnsproxy.@base[0].compress 2>/dev/null`
	local proxy=`uci get pcap_dnsproxy.@base[0].proxy 2>/dev/null`
	local socks_proxy=`uci get pcap_dnsproxy.@base[0].socks_proxy 2>/dev/null`
	local http_proxy=`uci get pcap_dnsproxy.@base[0].http_proxy 2>/dev/null`
	local part_mod=`uci get pcap_dnsproxy.@base[0].part_mod 2>/dev/null`
	local local_routing=`uci get pcap_dnsproxy.@base[0].local_routing 2>/dev/null`

	echo ''
	echo 'Pcap_DNSProxy Version: '
	$PROGRAM --lib-version
	echo ''
	[ $enabled == 1 ] && echo -e "	Autostarts: 			\033[40;32;1m Enable \033[0m" || echo -e "	Autostarts: 			\033[40;31;1m Disable \033[0m"
	[ $TCP_fast -a $TCP_fast == 1 ] && echo -e "	TCP Fast Open: 			\033[40;32;1m Enable \033[0m" || echo -e "	TCP Fast Open: 			\033[40;31;1m Disable \033[0m"
	[ $alt_mul_req -a $alt_mul_req == 1 ] && echo -e "	Alternate Multi Request: 	\033[40;32;1m Enable \033[0m" || echo -e "	Alternate Multi Request: 	\033[40;31;1m Disable \033[0m"
	if [ $part_mod == H ] 
	then
		echo -e "	Partition Mod: 			\033[40;33;1m Local Hosts \033[0m"
	else if [ $part_mod == M ]
		then 
		[ $local_routing -a $local_routing == 1 ] && echo -e "	Partition Mod: 			\033[40;33;1m Local Main + Local Routing \033[0m" || echo -e "	Partition Mod: 			\033[40;33;1m Local Main \033[0m"
		else echo -e "	Partition Mod: 			\033[40;31;1m Disable \033[0m"
		fi
	fi
	if [ $proxy -a $proxy == 1 ] 
	then
		[ $socks_proxy -a $http_proxy ] && echo -e "	Proxy:				\033[40;33;1m Socks + Http \033[0m" || echo -e "	Proxy:				\033[40;33;1m Http \033[0m"
	else echo -e "	Proxy:				\033[40;31;1m Disable \033[0m"
	fi
	echo -e "	Alternate Multi Request:	\033[40;34;1m $mul_req \033[0m"
	echo -e "	Compression Pointer Mutation : 	\033[40;34;1m $compress \033[0m"
	echo ''
	echo "	Listen Protocol:		 $listen_protocol"
	echo "	Operation Mode:			 $opera_mode"
	echo "	IPv4 DNS Address:		 $gen_ipv4_req"
	echo "	IPv4 Local DNS Address:		 $gen_ipv4_lo_req"
	echo ''

	[ $(ps|grep ${PROGRAM}|grep -v grep|wc -l) -ge 1 ] && echo -e "	Pcap_DNSProxy Running. PID: 	\033[40;34;1m $(pidof ${PROGRAM##*/}) \033[0m" || echo "	Pcap_DNSProxy Stoped. "
	echo ''
}

atosys() {
	local server_port=`uci get pcap_dnsproxy.@base[0].server_port 2>/dev/null`

	sed -i -e "/server=127.0.0.1/d" \
	-e "/no-resolv/d" /etc/dnsmasq.conf
	echo "server=127.0.0.1#$server_port" >> /etc/dnsmasq.conf
	echo "no-resolv" >> /etc/dnsmasq.conf

	/etc/init.d/dnsmasq restart
}

rmfsys() {
	sed -i -e "/server=127.0.0.1/d" \
	-e "/no-resolv/d" /etc/dnsmasq.conf

	/etc/init.d/dnsmasq restart
	exit 0
}

help() {
	echo ''
	echo 'Pcap_DNSProxy Version: '
	$PROGRAM --lib-version

	echo ''
	echo -e 'Available Commands:'
	echo -e '	\033[40;33;1m status \033[0m	Checking Program status.'
	echo -e '	\033[40;33;1m atosys \033[0m	Apply Pcap_DNSProxy to System Dnsmasq.'
	echo -e '	\033[40;33;1m rmfsys \033[0m	Remove Pcap_DNSProxy from System Dnsmasq.'
	echo -e '	\033[40;33;1m help \033[0m		This help. '
	echo ''
}

	while [ -n "$1" ]; do
	case $1 in
		help) help;shift 1;;
		h) help;shift 1;;
		-h) help;shift 1;;
	esac
	done
