
# Python code to analysis fw trace
  
import sys
import binascii


def get_hex(valuestring):
    convert_dec = int(valuestring, base=16)
    return convert_dec

def dword_big(packet, base):
	value = (packet[base]<<24) + (packet[base+1]<<16)+ (packet[base+2]<<8)+ (packet[base+3])
	return value
	
def dword_little(packet, base):
	value = (packet[base+3]<<24) + (packet[base+2]<<16)+ (packet[base+1]<<8)+ (packet[base])
	return value	

def word_big(packet, base):
	value = (packet[base]<<8) + (packet[base+1])
	return value
	
def word_little(packet, base):
	value = (packet[base+1]<<8) + (packet[base])
	return value	

def check_response_code(response, reason):
	std_resp = ["completed", "Command failed", "Command unavailable", "Command unsupported"]
	std_reason =[ "no error","Interface Initialization required", "Parameter invalid/unsupported/out_of_range", "channel not ready", "package not ready", "invalid payload length"]
	if( response != 0 ) or (reason != 0	):
		resp_str = ""
		if( response < len( std_resp ) ):
			resp_str = std_resp[response]
		reason_str = ""
		if( reason < len(std_reason)):
			reason_str = std_reason[reason]
		if( reason == 0x8004 ):
			reason_str = "No response from the module"
		if( reason == 0x8005 ):
			reason_str = "module is not enabled as not connected or power down"
		if( reason == 0x8006 ):
			reason_str = "module serial interface cannot be locked"	
		if( reason == 0xb07 ):
			reason_str = "the VLAN ID is invalid (VLAN ID = 0)"			
		print("---->>>> Failed: resp_code=", hex(response), resp_str, " reason_code=", hex(reason), reason_str)
		return False
	return True	

def check_package_channel(channel):
	if( channel != 0x1f ):
		print("------>>>>>>>> WARN: channel id != 0x1f ")
		
def check_completion_code(code):
	if( code != 0 ):
		code_str = ""
		if( code == 2 ):
			code_str = "invalid data"
		if( code == 3 ):
			code_str = "invalid length"
		if( code == 4 ):
			code_str = "not ready"
		if( code == 5 ):
			code_str = "unsupported pldm cmd"
		if( code == 0x20 ):
			code_str = "invalid pldm type"
		print("------>>>>>>>> Failed, completion code", hex(code), code_str)
		return False
	return True
	
def Package_req(line, packet, base, cidx, channel):
	pkg_id = channel>>5
	channel_id = channel & 0x1f
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx], "pkg", pkg_id, "Ch", hex(channel_id) )
	check_package_channel(channel_id)
	
def Package_resp(line,packet, base, cidx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	pkg_id = channel>>5
	channel_id = channel & 0x1f	
	print("[",line,"][NCSI]re:",  ncsi_cmd_str[cidx], "pkg", pkg_id, "Ch", hex(channel_id) )
	check_response_code(resp_code, reason_code)
	
def Channel_req(line,packet, base, cidx, channel):
	pkg_id = channel>>5
	channel_id = channel & 0x1f	
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx], "pkg", pkg_id, "Ch", hex(channel_id) )

	
def Channel_resp(line,packet, base, cidx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]re:",  ncsi_cmd_str[cidx],  "pkg", pkg_id, "Ch", hex(channel_id) )
	check_response_code(resp_code, reason_code)

def Select_package(line,packet, base, cidx, channel):
	hw_arbit_disable = packet[base+3]
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx],  "pkg", pkg_id, "Ch", hex(channel_id), "hw_arbit_disable", hw_arbit_disable )
	
def AENEnable_req(line,packet, base, cidx, channel):
	aen_mc_id = packet[base+3]
	aen_ctrl = packet[base+7]
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx],  "pkg", pkg_id, "Ch", hex(channel_id), "AEN MC ID", aen_mc_id, "Ctrl", aen_ctrl )
	

def SetLink(line,packet, base, cidx, channel):
	print( ncsi_cmd_str[cidx] )
	

	
def GetLinkStatus_res(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	LinkStatus = dword_big(packet, base+4)
	OtherIndications = dword_big(packet, base+8)
	OEMLinkStatus = dword_big(packet, base+12)
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	bit_link_flag = LinkStatus & 0x1
	link_flag = "Link Down"
	if( bit_link_flag == 1):
		link_flag = "Link Up"
	
	arr_speed_duplex = ["[AN not complete or Serdes=1]", "10BASE-T half-duplex", "10BASE-T full-duplex", "100BASE-TX half-duplex", "100BASE-T4", "100BASE-TX full-duplex", "1000BASE-T half-duplex", "1000BASE-T full-duplex", "10 Gbps", "20 Gbps", "25 Gbps", "40 Gbps", "50 Gbps", "100 Gbps", "2.5 Gbps", "Enhanced Speed and Duplex"]
	arr_ext_speed= ["[AN not complete or Serdes=1]", "10BASE-T half-duplex", "10BASE-T full-duplex", "100BASE-TX half-duplex", "100BASE-T4", "100BASE-TX full-duplex", "1000BASE-T half-duplex", "1000BASE-T full-duplex", "10 Gbps", "20 Gbps", "25 Gbps", "40 Gbps", "50 Gbps", "100 Gbps", "2.5 Gbps", "Enhanced Speed and Duplex", "1Gbps(none Base-T)","200Gbps", "400Gbps", "800Gbps"]
	bit_speed_duplex = (LinkStatus >> 1) & 0xf
	bit_AN_flag = (LinkStatus >> 5)& 0x1
	bit_AN_complete_flag = (LinkStatus >> 6)& 0x1
	bit_parallel_detect_flag = (LinkStatus >> 7)& 0x1
	bit_serdes_link = (LinkStatus >> 20)& 0x1
	bits_ext_speed = (LinkStatus >> 24)& 0xff
	str_AN_enable = "Enabled"
	if( bit_AN_flag == 0):
		str_AN_enable = "disabled"	
	str_AN_completed = "Completed"
	if( bit_AN_complete_flag == 0):
		str_AN_completed = "not completed"			
	print("[",line,"][NCSI]re:", ncsi_cmd_str[cmd_idx],"pkg", pkg_id, "Ch", hex(channel_id), link_flag, arr_speed_duplex[bit_speed_duplex], ",AN is ",str_AN_enable, str_AN_completed, ",serdes=", bit_serdes_link )	
	if bit_speed_duplex == (len(arr_speed_duplex)-1) :
		if bits_ext_speed < len(arr_ext_speed):
			print(" ext speed: ", arr_ext_speed[bits_ext_speed] )
	check_response_code(resp_code, reason_code)

def SetVLANFilter(line,packet, base, cidx, channel):
	vlanhd = word_big( packet,base+2 )
	vid = vlanhd & 0xfff
	filter_sel = packet[base+6]
	enable = packet[base+7] & 0x1
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print( "[",line,"][NCSI]   ", ncsi_cmd_str[cidx],"pkg", pkg_id, "Ch", hex(channel_id)," vid=",hex(vid)," filterSel=",filter_sel," En", enable)
	
	
def SetMACAddress(line,packet, base, cidx, channel):
	mac5 = packet[base]
	mac4 = packet[base+1]
	mac3 = packet[base+2]
	mac2 = packet[base+3]
	mac1 = packet[base+4]
	mac0 = packet[base+5]
	mac_num = packet[base+6]
	mac_at = packet[base+7] >> 5 
	mac_en = packet[base+7] & 0x1
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx],"pkg", pkg_id, "Ch", hex(channel_id), "AT:E:num",mac_at, mac_en,mac_num,"MAC",format(mac5,'x'),format(mac4,'x'),format(mac3,'x'),format(mac2,'x'),format(mac1,'x'),format(mac0,'x'))
	

def EnableBroadcastFilter(line,packet, base, cidx, channel):
	filter = packet[base+3]
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx],"pkg", pkg_id, "Ch", hex(channel_id), "Filter", hex(filter) )

	
def EnableGlobalMulticastFilter(line,packet, base, cidx, channel):
	filter = packet[base+3]
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx], "pkg", pkg_id, "Ch", hex(channel_id), "Filter", hex(filter) )
	


def SetNCSIFlowControl(line,packet, base, cidx, channel):
	flow_ctrl_en = packet[base+3]
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]   ", ncsi_cmd_str[cidx], "pkg", pkg_id, "Ch", hex(channel_id), "flow ctrl enable", flow_ctrl_en )
	check_package_channel(channel_id)
	

def GetVersionID_resp(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	strname =""
	#for i in range(0, 12 ):
	#	if(packet[base+12+i] == 0 ):
	#		break;	
	#	try:
	#		name = ( chr( packet[base+12+i] ) )
	#	except UnicodeEncodeError:
	#		break;
	#	else:
	#		strname = strname + name;

	fw_version3 = packet[base+24]
	fw_version2 = packet[base+25]
	fw_version10 = (packet[base+26]<<8) + packet[base+27]
	
	did = (packet[base+28]*256) + packet[base+29]
	vid = (packet[base+30]<<8) + packet[base+31]
	sdid = (packet[base+32]<<8) + packet[base+33]	
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print( "[",line,"][NCSI]re:", ncsi_cmd_str[cmd_idx],strname,"pkg", pkg_id, "Ch", hex(channel_id)," vid=",hex(vid)," did=",hex(did)," sdid=",hex(sdid)," FW", fw_version3,".",fw_version2,".",fw_version10, sep="")
	check_response_code(resp_code, reason_code)
	
def GetCapabilities_resp(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	cap_flag = packet[base+7]
	NC2MC = "no NC2MC"
	MC2NC = "no MC2NC"
	if(cap_flag & 0x4):
		NC2MC = "NC2MC"
	if(cap_flag & 0x8):
		MC2NC = "MC2NC"	
	BroadcastCapabilities = dword_big(packet, base+8)
	MulticastCapabilities = dword_big( packet, base+12)
	BuffCapability  = dword_big( packet, base+16)
	AENControl   = dword_big( packet, base+20)
	Vlan_filter_cnt = packet[base+24]
	Mixed_filter_cnt = packet[base+25]
	Multicast_filter_cnt = packet[base+26]
	Unicast_filter_cnt = packet[base+27]
	Vlan_mode_support= packet[base+30]
	Channel_cnt = packet[base+31]
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print("[",line,"][NCSI]re:", ncsi_cmd_str[cmd_idx],"pkg", pkg_id, "Ch", hex(channel_id), NC2MC, MC2NC, 
	"cap_flag:%02x BC:%x MC:%x buff:%x AEN:%x VlanMode:%x Channel:%x"%(cap_flag,BroadcastCapabilities,MulticastCapabilities,BuffCapability,AENControl,Vlan_mode_support,Channel_cnt ) )
	check_response_code(resp_code, reason_code)
	
def GetParameters_resp(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	MacCount = packet[base+4]
	MacFlags = packet[base+7]
	linksettings = dword_big( packet, base+12)
	BCSettings = dword_big( packet, base+16)
	ConfFlags = dword_big( packet, base+20)
	vlanMode = packet[base+24]
	FCEnable = packet[base+25]
	AENControl = dword_big(packet,base+28)
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print( "[",line,"][NCSI]re:", ncsi_cmd_str[cmd_idx],"pkg", pkg_id, "Ch", hex(channel_id))
	print( "         MAC count=%d,Flags=0x%x LinkSetting=%x BC=%x Conf=%x VLAN mode=%x FC=%x AEN=%x"%(MacCount,MacFlags,linksettings,BCSettings,ConfFlags,vlanMode,FCEnable,AENControl) )
	check_response_code(resp_code, reason_code)
	
def GetControllerPacketStatistics_resp(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	Total_bytes_rx = dword_big(packet, base+12)
	Total_bytes_tx = dword_big(packet, base+16)
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print( "[",line,"][NCSI]re:", ncsi_cmd_str[cmd_idx],"pkg", pkg_id, "Ch", hex(channel_id))
	print( "      total bytes rx=%d, total bytes tx=%d"%(Total_bytes_rx,Total_bytes_tx))
	check_response_code(resp_code, reason_code)


def GetNCSIStatistics_resp(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	CommandsReceived = dword_big(packet, base+4)
	ControlPacketsDropped = dword_big(packet, base+8)
	TypeErrors = dword_big(packet, base+12)
	ChecksumErrors = dword_big(packet, base+16)
	rx = dword_big(packet, base+20)
	tx = dword_big(packet, base+24)
	AENsSent	 = dword_big(packet, base+28)
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print( "[",line,"][NCSI]re:", ncsi_cmd_str[cmd_idx],"pkg", pkg_id, "Ch", hex(channel_id))
	print( "      cmds rx=%d, drop=%d, type err=%d,chs err=%d pkt rx=%d, tx=%d"%(CommandsReceived,ControlPacketsDropped,TypeErrors,ChecksumErrors,rx,tx ))
	check_response_code(resp_code, reason_code)

def GetNCSIPassthroughStatistics_resp(line,packet, base, cmd_idx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	MCtoNC_rx = dword_big(packet, base+4)
	MCtoNC_drop = dword_big(packet, base+8)
	MCtoNC_channel_state_err = dword_big(packet, base+12)
	MCtoNC_undersize_err = dword_big(packet, base+16)
	MCtoNC_oversize_err = dword_big(packet, base+20)
	NCtoMC_rx = dword_big(packet, base+24)
	NCtoMC_drop = dword_big(packet, base+28)
	NCtoMC_channel_state_err = dword_big(packet, base+32)
	NCtoMC_undersize_err = dword_big(packet, base+36)
	NCtoMC_oversize_err	 = dword_big(packet, base+40)
	pkg_id = channel>>5
	channel_id = channel & 0x1f		
	print( "   re:", ncsi_cmd_str[cmd_idx],"pkg", pkg_id, "Ch", hex(channel_id))
	print( "      MCtoNC rx=%d, drop=%d, ch state err=%d,undersize=%d oversize=%d"%(MCtoNC_rx,MCtoNC_drop,MCtoNC_channel_state_err,MCtoNC_undersize_err,MCtoNC_oversize_err ))	
	print( "      NCtoMC rx=%d, drop=%d, ch state err=%d,undersize=%d oversize=%d"%(NCtoMC_rx,NCtoMC_drop,NCtoMC_channel_state_err,NCtoMC_undersize_err,NCtoMC_oversize_err ))	
	check_response_code(resp_code, reason_code)


def GetPackageStatus(line,packet, base, cidx, channel):
	print( ncsi_cmd_str[cidx] )	
	
def OEMCommand_req(line,packet, base, cidx, channel):
	manufactureID_hi = packet[base+2]
	manufactureID_lo = packet[base+3]
	mellanox_cmd = packet[base+5]
	parameter = packet[base+6]
	cmd_str = ""
	oemfun = None
	for i in range(0,len(oemcmd)):
		if( oemcmd[i] == mellanox_cmd ):
			for j in range(0, len(oemparam[i]) ):
				if( oemparam[i][j] == parameter ) : 
					cmd_str = oemparam_str[i][j]
					oemfun = oemfun_req[i][j]
	pkg_id = channel>>5
	channel_id = channel & 0x1f						
	print("[",line,"][ NCSI  ]", ncsi_cmd_str[cidx],"pkg", pkg_id, "Ch", hex(channel_id), "IANA",format(manufactureID_hi*256+manufactureID_lo,'x'),"CMD",hex(mellanox_cmd),"paramter",hex(parameter), cmd_str  )
	if( oemfun != None ):
		if( oemfun(packet, base+7) != True ):
			check_package_channel(channel_id)
	

def OEMCommand_resp(line,packet, base, cidx, channel):
	resp_code = word_big(packet,base)
	reason_code = word_big( packet,base+2 )
	manufactureID = dword_big(packet, base+4)
	mellanox_cmd = packet[base+9]
	parameter = packet[base+10]
	cmd_str = ""	
	oemfun = None	
	for i in range(0,len(oemcmd)):
		if( oemcmd[i] == mellanox_cmd ):
			for j in range(0, len(oemparam[i]) ):
				if( oemparam[i][j] == parameter ) : 
					cmd_str = oemparam_str[i][j]	
					oemfun = oemfun_resp[i][j]
	pkg_id = channel>>5
	channel_id = channel & 0x1f						
	print("[",line,"][re:NCSI]", ncsi_cmd_str[cidx],"pkg", pkg_id, "Ch", hex(channel_id), "IANA",format(manufactureID,'x'),"CMD",hex(mellanox_cmd),"paramter",hex(parameter), cmd_str)
	if( check_response_code(resp_code, reason_code) == False ):
		return
	if( oemfun != None ):
		oemfun(packet, base+11)

def PLDM(line,packet, base, cmd_idx, channel):
	print( ncsi_cmd_str[cmd_idx] )	

def GetPackageUUID(line,packet, base, cmd_idx, channel):
	print( ncsi_cmd_str[cmd_idx] )	

def AENpacket(line,packet, base, cmd_idx, channel):
	AEN_type  = packet[base+3]
	print( "[",line,"] ", ncsi_cmd_str[cmd_idx], " AEN type=", AEN_type )		

	
ncsi_cmd =[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x50, 0x51, 0x52, 0xff ]
ncsi_cmd_str =[ 
 "Clear Initial State", 	
 "Select Package", 		
 "Deselect Package",	
 "Enable Channel",  		
 "Disable Channel",  		
 "Reset Channel",  		    
 "Enable Channel Network TX ", 	
 "Disable Channel Network TX ", 
 "AEN Enable 	", 	        
 "Set Link 	", 		
 "Get Link Status ", 	
 "Set VLAN Filter ", 	
 "Enable VLAN ", 		
 "Disable VLAN ", 		
 "Set MAC Address ",    
 "Enable Broadcast Filter ", 	        
 "Disable Broadcast Filter 	 ",        
 "Enable Global Multicast Filter ", 	
 "Disable Global Multicast Filter 	", 
 "Set NC-SI Flow Control ", 	        
 "Get Version ID 	", 	            
 "Get Capabilities 	", 	            
 "Get Parameters 	", 	            
 "Get Controller Packet Statistics ", 	
 "Get NC-SI Statistics 		", 		
 "Get NC-SI Passthrough Statistics ", 
 "Get Package Status",  				
 "OEM Command ", 						
 "PLDM 		", 						
 "Get Package UUID 	", 				
 "AEN packet "
]

ncsi_cmd_req =[ 
 Channel_req, 	
 Select_package, 		
 Package_req,	
 Channel_req,  		
 Channel_req,  		
 Channel_req,  		    
 Channel_req, 	
 Channel_req, 
 AENEnable_req 	, 	        
 SetLink 	, 		
 Channel_req , 	
 SetVLANFilter , 	
 Channel_req , 		
 Channel_req, 		
 SetMACAddress ,    
 EnableBroadcastFilter , 	        
 Channel_req 	 ,        
 EnableGlobalMulticastFilter , 	
 Channel_req 	, 
 SetNCSIFlowControl , 	        
 Channel_req 	, 	            
 Channel_req 	, 	            
 Channel_req, #GetParameters 	, 	            
 Channel_req, #GetControllerPacketStatistics, 	
 Channel_req, #GetNCSIStatistics 		, 		
 Channel_req, #GetNCSIPassthroughStatistics , 
 Package_req,  				
 OEMCommand_req , 						
 PLDM 		, 						
 GetPackageUUID 	, 				
 AENpacket 
]

ncsi_cmd_res =[ 
 Channel_resp, 	
 Package_resp, 		
 Package_resp,	
 Channel_resp,  		
 Channel_resp,  		
 Channel_resp,  		    
 Channel_resp, 	
 Channel_resp, 
 Channel_resp 	, 	        
 SetLink 	, 		
 GetLinkStatus_res , 	
 Channel_resp , 	
 Channel_resp , 		
 Channel_resp, 		
 Channel_resp ,    
 Channel_resp , 	        
 Channel_resp 	 ,        
 Channel_resp , 	
 Channel_resp 	, 
 Package_resp , 	        
 GetVersionID_resp 	, 	            
 GetCapabilities_resp 	, 	            
 GetParameters_resp 	, 	            
 GetControllerPacketStatistics_resp, 	
 GetNCSIStatistics_resp 		, 		
 GetNCSIPassthroughStatistics_resp , 
 Package_resp,  				
 OEMCommand_resp , 						
 PLDM 		, 						
 GetPackageUUID 	, 				
 AENpacket 
]

oemcmd=[ 0x0, 0x1, 0x10, 0x11,0x12,0x13]
oemparam = [ 
[0x0 ,0x1 ,0x2 ,0x3 ,0x4 , 0x5 , 0x6 ,0xA , 0x1A,0x1B, 0x1C, 0x20, 0x21, 0x22, 0x23,0x24, 0x25, 0x26,0x27, 0x28, 0x29,0x2A,0x2B, 0x2E, 0x2F, 0x31], 
[0x0 ,0x1 ,0x2 ,0x3 ,0x4 ,0x5 ,0x6 ,0x7 ,0x1A,0x1C,0x23,0x24,0x25,0x26,0x28,0x2C,0x2D,0x2E,0x30,0x31], 
[0x0 ,0x1 ,0x10,0x11,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68], 
[0x0 ,0xF ,0x10,0x11,0x61,0x66,0x67,0x68,0x62,0x64,0x65], 
[0x0 ,0x1 ,0x3 ,0x4 ,0xA ,0xB ,0xC ,0xE ,0x10,0x11,0x12,0x15,0x16,0x18,0x19,0x21,0x23,0x25,0x28], 
[0x0 ,0x1 ,0x2 ,0x3 ,0x4 ,0x5 ,0x6 ,0x7 ,0x8 ,0x9 ,0xB ,0xC ,0x11,0x12,0x13,0x14,0x17,0x19,0x22,0x24,0x26,0x27]]
oemparam_str = [
[
"Get PF MAC Address                 ",
"Get FCoE Configuration             ",
"Get PXE Configuration              ",
"Get Multi-PF Capabilities          ",
"Get SR-IOV Configuration           ",
"Get Enhanced Tagging Configuration ",
"Get iSCSI Configuration            ",
"Get Addresses Groups Count         ",
" Get Addresses                     ",
" Get Allocated Management Address  ",
" Get Safe Mode Configuration       ",
" Get Driver Information            ",
" Get Cable Information             ",
" Get Card VPD Information          ",
" Get Card TLV Information          ",
" Query Hosts                       ",
" Get Chassis Rate Limiting         ",
" Get Rate Limiting                 ",
" Get Port ID                       ",
" Get Self Recovery Setting         ",
" Get Interface Info                ",
" Get Device ID                     ",
" Get Port ECC Counters             ",
" Get LLDP NB                       ",
" Get Log Information               ",
" Get Network Debug Info            "
],
[
"Set PF MAC Address         ",
"Set FCoE Configuration     ",
"Set PXE Configuration      ",
"Set Multi-PF Configuration ",
"Set SR-IOV Configuration   ",
"Set Enhanced Tagging Configuration",
"Set iSCSI Configuration    ",
"Set MC affinity            ",
" Set Addresses             ",
" Set Safe Mode Configuration",
" Set Card TLV Information  ",
" Enable Hosts              ",
" Set Chassis Rate Limiting ",
" Set Rate Limiting         ",
" Set Self Recovery Setting ",
" Set MH PTP mode           ",
" Set PTP Parameters        ",
" Set LLDP NB               ",
" Erase Log Information     ",
" Set Network Debug Info    "
],
[
"Get Management Filtering Enable       ",
"Get Management Filters Banks Count    ",
" Get Flex Filter mask and length      ",
" Get Flex Filter Data                 ",
" Get Mellanox decision filter         ",
" Get ARP Offload                      ",
" Get Configurable UDP/TCP ports       ",
" Get IPv4 Address                     ",
" Get IPv6 Address                     ",
" Get Configurable MAC Address         ",
" Get Configurable EtherType           ",
" Get Mellanox Extended decision filter"
],
[
"Set Management Filtering Enable       ",
"Set Management Only                   ",
" Set Flex Filter mask and length      ",
" Set Flex Filter Data                 ",
" Set Mellanox decision filter         ",
" Set Configurable MAC Address         ",
" Set Configurable EtherType           ",
" Set Mellanox Extended decision filter",
" Set ARP Offload                      ",
" Set IPv4 Address                     ",
" Set IPv6 Address                     "
],
[
"Set Port LED control             ",
"Set Temperature Controls         ",
"Set Register                     ",
"Set Mellanox AEN Controls        ",
"Reset NIC                        ",
"Reset Smart NIC                  ",
"Set Chip Registers               ",
"Disable Token                    ",
" Module Re-Plug                  ",
" Send Module Serial data         ",
" Send PHY Serial data            ",
" Set Token                       ",
" Set FRU WP control              ",
" Interrupt Smart NIC             ",
" Set Host Access to Smart NIC CPU",
" Set Time                        ",
" Set BMC Certificates            ",
" Enable Trust                    ",
" Set Smart NIC Boot Option       "
],
[
"  Get Port LED control           ",
"Get Temperature Controls         ",
"Get Temperature                  ",
"Get Register                     ",
"Get Mellanox AEN Controls        ",
"Get Mellanox Link Status         ",
"Get Electrical Sensors Count     ",
"Get Electrical Sensor            ",
"Get Electrical Sensors           ",
"Get System Thermal Sensors Count ",
"Get PCIe Parameters              ",
"Get Chip Registers               ",
" Get Module Serial Data          ",
" Get PHY Serial Data             ",
" Get Challenge                   ",
" Get Debug Mode Info             ",
" Get Smart NIC OS state          ",
" Get Host Access to Smart NIC CPU",
" Get Smart NIC PCIe Errors       ",
" Get Nonce                       ",
" Query Trust Status              ",
" Get Smart NIC Boot Options      "
]
]



mctp_ctrl_cmd = [0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12,0x13,0x14]
mctp_ctrl_cmd_str = [
"Set Endpoint ID               ",
"Get Endpoint ID               ",
"Get Endpoint UUID             ",
"Get MCTP Version              ",
"Get Message Type Support   ",
"Get Vendor Defined Message    ",
"Resolve Endpoint ID           ",
"Allocate Endpoint IDs         ",
"Routing Information Update    ",
"Get Routing Table Entries     ",
"Prepare for Endpoint Discovery",
"Endpoint Discovery            ",
"Discovery Notify              ",
"Get Network ID                ",
"Query Hop                     ",
"Resolve UUID                  ",
"Query rate limit              ",
"Request TX rate limit         ",
"Update rate limit             ",
"Query Supported Interfaces    "
]


pldmType = [0, 2, 4, 5]
pldmCMDcode = [
[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09],
[0x01,0x02,0x03,0x04,0x05,0x0A,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x20,0x21,0x22,0x30,0x31,0x32,0x38,0x39,0x3A,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x50,0x51,0x52,0x58],
[0x01,0x02,0x03,0x04],
[0x01,0x02,0x03,0x04,0x05,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20]
]

pldmCMDcode_str = [
[
"SetTID                      ",
"GetTID                      ",
"GetPLDMVersion              ",
"GetPLDMTypes                ",
"GetPLDMCommands             ",
"SelectPLDMVersion           ",
"NegotiateTransferParameters ",
"MultipartSend               ",
"MultipartReceive            "
],
[
 "SetTID                    ",
 "GetTID                    ",
 "GetTerminusUID            ",
 "SetEventReceiver          ",
 "GetEventReceiver          ",
 "PlatformEventMessage      ",
 "SetNumericSensorEnable    ",
 "GetSensorReading          ",
 "GetSensorThresholds       ",
 "SetSensorThresholds       ",
 "RestoreSensorThresholds   ",
 "GetSensorHysteresis       ",
 "SetSensorHysteresis       ",
 "InitNumericSensor         ",
 "SetStateSensorEnables     ",
 "GetStateSensorReadings    ",
 "InitStateSensor           ",
 "SetNumericEffecterEnable  ",
 "SetNumericEffecterValue   ",
 "GetNumericEffecterValue   ",
 "SetStateEffecterEnables   ",
 "SetStateEffecterStates    ",
 "GetStateEffecterStates    ",
 "GetPLDMEventLogInfo       ",
 "EnablePLDMEventLogging    ",
 "ClearPLDMEventLog         ",
 "GetPLDMEventLogTimestamp  ",
 "SetPLDMEventLogTimestamp  ",
 "ReadPLDMEventLog          ",
 "GetPLDMEventLogPolicyInfo ",
 "SetPLDMEventLogPolicy     ",
 "FindPLDMEventLogEntry     ",
 "GetPDRRepositoryInfo      ",
 "GetPDR                    ",
 "FindPDR                   ",
 "RunInitAgent              "
],
[
"GetFRURecordTableMetadata",
"GetFRURecordTable        ",
"SetFRURecordTable        ",
"GetFRURecordByOption     "
],
[
"QueryDeviceIdentifiers           ",
"GetFirmwareParameters            ",
"QueryDownstreamDevices           ",
"QueryDownstreamIdentifiers       ",
"GetDownstreamFirmwareParameters  ",
"RequestUpdate                    ",
"GetPackageData                   ",
"GetDeviceMetaData                ",
"PassComponentTable               ",
"UpdateComponent                  ",
"RequestFirmwareData              ",
"TransferComplete                 ",
"VerifyComplete                   ",
"ApplyComplete                    ",
"GetMetaData                      ",
"ActivateFirmware                 ",
"GetStatus                        ",
"CancelUpdateComponent            ",
"CancelUpdate                     ",
"ActivatePendingComponentImageSet ",
"ActivatePendingComponentImage    ",
"RequestDownstreamDeviceUpdate    "
]
]

def TerminusLocatorPDR(packet, base):
	PLDMTerminusHandle = packet[base] + (packet[base+1]<<8)
	validity = packet[base+2]
	TID = packet[base+3]
	containerID = packet[base+4] + (packet[base+5]<<8)
	print("                       : PLDMTerminusHandle",hex(PLDMTerminusHandle),"valid",validity, "containerID",hex(containerID))
	
def NumericSensorPDR_old_version(packet, base):
	PLDMTerminusHandle = packet[base] + (packet[base+1]<<8)
	sensorID = packet[base+2] 
	entityType = packet[base+3]+(packet[base+4]<<8)
	entityInstanceNumber = packet[base+5]+(packet[base+6]<<8)
	containerID = packet[base+7] + (packet[base+8]<<8)
	sensorInit = packet[base+9]
	sensorAux = packet[base+10]	
	print("                       : PLDMTerminusHandle0",hex(PLDMTerminusHandle),"sensorID",hex(sensorID),"entityType",hex(entityType), "containerID",hex(containerID), "sensorInit", sensorInit,"sensorAux", sensorAux)
	
def NumericSensorPDR(packet, base):
	PLDMTerminusHandle = word_little(packet, base)
	sensorID = word_little( packet, base+2)
	entityType = word_little( packet, base+4) 
	entityInstanceNumber = word_little( packet, base+6) 
	containerID = word_little( packet, base+8 ) 
	sensorInit = packet[base+10]
	sensorAux = packet[base+11]
	if( containerID != 0x8119 ):
		NumericSensorPDR_old_version(packet, base)
	else:
		print("                       : PLDMTerminusHandle",hex(PLDMTerminusHandle),"sensorID",hex(sensorID),"entityType",hex(entityType), "containerID",hex(containerID),"sensorInit", sensorInit,"sensorAux", sensorAux )

#State Sensor PDR
def StateSensorPDR(packet, base):
	PLDMTerminusHandle = word_little(packet, base)
	sensorID = word_little( packet, base+2)
	entityType = word_little( packet, base+4) 
	entityInstanceNumber = word_little( packet, base+6) 
	containerID = word_little( packet, base+8 ) 
	sensorInit = packet[base+10]
	sensorAux = packet[base+11]
	compositeSensorCount = packet[base+12]
	print("                       : StateSensorPDR",hex(PLDMTerminusHandle),"sensorID",hex(sensorID),"entityType",hex(entityType), "containerID",hex(containerID),"sensorInit", sensorInit,"sensorAux", sensorAux,"compositeSensorCount",compositeSensorCount)
	

	
PDRType_str=[
"",
"Terminus Locator PDR               ",
"Numeric Sensor PDR                 ",
"Numeric Sensor Initialization PDR  ",
"State Sensor PDR                   ",
"State Sensor Initialization PDR    ",
"Sensor Auxiliary Names PDR         ",
"OEM Unit PDR                       ",
"OEM State Set PDR                  ",
"Numeric Effecter PDR               ",
"Numeric Effecter Initialization PDR",
"State Effecter PDR                 ",
"State Effecter Initialization PDR  ",
"Effecter Auxiliary Names PDR       ",
"Effecter OEM Semantic PDR          ",
"Entity Association PDR             ",
"Entity Auxiliary Names PDR         ",
"OEM Entity ID PDR                  ",
"Interrupt Association PDR          ",
"PLDM Event Log PDR                 ",
"FRU Record Set PDR                 ",
"Compact Numeric Sensor PDR         ",
"Redfish Resource PDR               ",
"Redfish Entity Association PDR     ",
"Redfish Action PDR                 "
]

PDRType_fun=[
None, #"",
TerminusLocatorPDR               ,
NumericSensorPDR                 ,
None, #"Numeric Sensor Initialization PDR  ",
StateSensorPDR, #"State Sensor PDR                   ",
None, #"State Sensor Initialization PDR    ",
None, #"Sensor Auxiliary Names PDR         ",
None, #"OEM Unit PDR                       ",
None, #"OEM State Set PDR                  ",
None, #"Numeric Effecter PDR               ",
None, #"Numeric Effecter Initialization PDR",
None, #"State Effecter PDR                 ",
None, #"State Effecter Initialization PDR  ",
None, #"Effecter Auxiliary Names PDR       ",
None, #"Effecter OEM Semantic PDR          ",
None, #"Entity Association PDR             ",
None, #"Entity Auxiliary Names PDR         ",
None, #"OEM Entity ID PDR                  ",
None, #"Interrupt Association PDR          ",
None, #"PLDM Event Log PDR                 ",
None, #"FRU Record Set PDR                 ",
None, #"Compact Numeric Sensor PDR         ",
None, #"Redfish Resource PDR               ",
None, #"Redfish Entity Association PDR     ",
None #"Redfish Action PDR                 "
]

def GetSensorReading_req(line,packet, base, cmd_str):
	sensorID = packet[base] + (packet[base+1]<<8) 
	rearmEventState = packet[base+2]
	print("[",line,"][pldm]:", cmd_str, "sensorID", hex(sensorID), "rearm", rearmEventState )	

def GetSensorReading_resp(line,packet, base, cmd_str):
	completion = packet[base]
	sensorDataSize = packet[base+1]
	sensorOperationalState = packet[base+2] 
	sensorEventMessageEnable=packet[base+3]
	presentState=packet[base+4]
	previousState=packet[base+5]
	eventState=packet[base+6]
	presentReading=packet[base+7]
	completion_str = "failed"
	if( completion == 0 ):
		completion_str = "success"
	elif(completion == 0x80 ):
		completion_str = "INVALID_SENSOR_ID"
	elif(completion == 0x81 ):
		completion_str = "REARM_UNAVAILABLE_IN_PRESENT_STATE"	
	print("[",line,"][pldm]         Re:", cmd_str,  completion_str)
	op_stat_str=["enabled", "disabled", "unavailable", "statusUnknown", "failed", "initializing", "shuttingDown", "inTest"  ]
	value = presentReading
	if( sensorDataSize > 1):
		value = presentReading + (packet[base+8] << 8)
	if( completion == 0 ):	
		print("                       :",op_stat_str[sensorOperationalState], value )
	

def GetPDR_req(line,packet, base, cmd_str):
	recordHandle    = packet[base] + (packet[base+1]<<8)+ (packet[base+2]<<16)+ (packet[base+3]<<24) 
	dataTransferHandle = packet[base+4] + (packet[base+5]<<8)+ (packet[base+6]<<16)+ (packet[base+7]<<24)
	transferOperationFlag = packet[base+8]
	requestCount = packet[base+9]+(packet[base+10]<<8)
	recordChangeNumber = packet[base+11]+(packet[base+12]<<8)
	flag = "error flag!"
	if( transferOperationFlag == 0 ):
		flag = "GetNextPart"
	elif( transferOperationFlag == 1 ):
		flag = "GetFirstPart"
	print("[",line,"][pldm]:", cmd_str, "recordhandle", recordHandle, flag, "requestCount",hex(requestCount) )	

def Common_PDR_header(packet, base):
	recordHandle = packet[base] + (packet[base+1]<<8)+ (packet[base+2]<<16)+ (packet[base+3]<<24)
	PDRHeaderVersion = packet[base+4]
	PDRType = packet[base+5]
	recordChangeNumber = packet[base+6] + (packet[base+7]<<8)
	dataLength = packet[base+8] + (packet[base+9]<<8)
	print("                       :",PDRType_str[PDRType],  "recordHandle",recordHandle, "dataLength",dataLength)
	data = packet[base+10]
	if( PDRType_fun[PDRType] != None ):
		PDRType_fun[PDRType](packet, base+10)


def GetPDR_resp(line,packet, base, cmd_str):
	completion = packet[base]
	nextRecordHandle = packet[base+1] + (packet[base+2]<<8)+ (packet[base+3]<<16)+ (packet[base+4]<<24)
	nextDataTransferHandle  = packet[base+5] + (packet[base+6]<<8)+ (packet[base+7]<<16)+ (packet[base+8]<<24)
	transferFlag = packet[base+9]
	responseCount = packet[base+10] + (packet[base+11]<<8)
	# The number of PDR data bytes returned in this field must match responseCount. 
	recoreData = packet[base+12]
	completion_str = "failed"
	if( completion == 0 ):
		completion_str = "success"
	elif(completion == 0x80 ):
		completion_str = "INVALID_DATA_TRANSFER_HANDLE"
	elif(completion == 0x81 ):
		completion_str = "INVALID_TRANSFER_OPERATION_FLAG"	
	elif(completion == 0x82 ):
		completion_str = "INVALID_RECORD_HANDLE"
	elif(completion == 0x83 ):
		completion_str = "INVALID_RECORD_CHANGE_NUMBER"		
	elif(completion == 0x84 ):
		completion_str = "TRANSFER_TIMEOUT"
	elif(completion == 0x85 ):
		completion_str = "REPOSITORY_UPDATE_IN_PROGRESS"	
	flag = "error flag!"
	if( transferFlag == 0 ):
		flag = "Start"
	elif( transferFlag == 1 ):
		flag = "Middle"	
	if( transferFlag == 4 ):
		flag = "End"
	elif( transferFlag == 5 ):
		flag = "StartAndEnd"			
	print("[",line,"][pldm]         Re:", cmd_str,  completion_str, flag)
	print("                       : nextRecordHandle",nextRecordHandle,"responseCount",hex(responseCount) )
	Common_PDR_header(packet, base+12)

def RequestUpdate_req(line,packet, base, cmd_str):
	MaximumTransferSize = dword_little(packet, base)
	NumberOfComponents  = word_little(packet, base+4)
	MaximumOutstandingTransferRequests = packet[base+6]
	PackageDataLength   = word_little(packet, base+7)
	ComponentImageSetVersionStringType  = packet[base+9]
	ComponentImageSetVersionStringLength = packet[base+10]
	ComponentImageSetVersionString = packet[base+11:base+11+ComponentImageSetVersionStringLength]
	print("                  MaximumTransferSize", hex(MaximumTransferSize), "PackageDataLength=", 
		hex(PackageDataLength),ComponentImageSetVersionStringType,ComponentImageSetVersionStringLength,end=" " )	
	for i in range(len(ComponentImageSetVersionString)):
		if( ComponentImageSetVersionString[i] == 0 ):
			break
		print(chr(ComponentImageSetVersionString[i]) , end="")
	print()
	
def RequestUpdate_resp(line,packet, base, cmd_str):
	completion = packet[base]
	FirmwareDeviceMetaDataLength  = word_little(packet, base+1)
	FDWillSendGetPackageDataCommand  = packet[base+2]
	print("                  FirmwareDeviceMetaDataLength", hex(FirmwareDeviceMetaDataLength),
		"FDWillSendGetPackageDataCommand=", hex(FDWillSendGetPackageDataCommand) )	

def PassComponentTable_req(line,packet, base, cmd_str):
	TransferFlag             = packet[base]
	ComponentClassification  = word_little(packet, base+1)
	ComponentIdentifier      = word_little(packet, base+3)
	ComponentClassificationIndex = packet[base+5]
	ComponentComparisonStamp     = dword_little(packet, base+6)
	ComponentVersionStringType   = packet[base+10]
	ComponentVersionStringLength = packet[base+11]
	ComponentVersionString = packet[base+12:base+12+ComponentVersionStringLength]
	print("                  TransferFlag", hex(TransferFlag),  
		hex(ComponentClassification),hex(ComponentIdentifier),ComponentClassificationIndex,
		hex(ComponentComparisonStamp), ComponentVersionStringType, ComponentVersionStringLength, end=" " )	
	for i in range(len(ComponentVersionString)):
		if( ComponentVersionString[i] == 0 ):
			break
		print(chr(ComponentVersionString[i]) , end="")
	print()		
	
def PassComponentTable_resp(line,packet, base, cmd_str):
	completion = packet[base]
	ComponentResponse = packet[base+1]
	ComponentResponseCode = packet[base+2]
	print("                  ComponentResponse", hex(ComponentResponse),hex(ComponentResponseCode))	

def UpdateComponent_req(line,packet, base, cmd_str):
	ComponentClassification  = word_little(packet, base)
	ComponentIdentifier      = word_little(packet, base+2)
	ComponentClassificationIndex = packet[base+4]
	ComponentComparisonStamp     = dword_little(packet, base+5)
	ComponentImageSize           = dword_little(packet, base+9)
	UpdateOptionFlags            = dword_little(packet, base+13)
	ComponentVersionStringType   = packet[base+17]
	ComponentVersionStringLength = packet[base+18]
	ComponentVersionString = packet[base+19:base+19+ComponentVersionStringLength]
	print("                  ComponentClassification",hex(ComponentClassification),hex(ComponentIdentifier),
		hex(ComponentComparisonStamp),"ImageSize", hex(ComponentImageSize),hex(UpdateOptionFlags),
		ComponentVersionStringType, ComponentVersionStringLength, end=" " )	
	for i in range(len(ComponentVersionString)):
		if( ComponentVersionString[i] == 0 ):
			break
		print(chr(ComponentVersionString[i]) , end="")
	print()		
	
def UpdateComponent_resp(line,packet, base, cmd_str):
	completion = packet[base]
	ComponentCompatibilityResponse = packet[base+1]
	ComponentCompatibilityResponse_code = packet[base+2] 
	UpdateOptionFlagsEnabled  = dword_little(packet, base+3)
	EstimatedTime = word_little(packet, base+7)
	print("                  ComponentCompatibility", hex(ComponentCompatibilityResponse),  
		hex(ComponentCompatibilityResponse_code), hex(UpdateOptionFlagsEnabled), EstimatedTime)	

def RequestFirmwareData_req(line,packet, base, cmd_str):
	Offset  = dword_little(packet, base)
	Length  = dword_little(packet, base+4)
	print("                  offset",hex(Offset),"Length", hex(Length) )


	
pldmCMDcode_req = [
[
None, #"SetTID                      ",
None, #"GetTID                      ",
None, #"GetPLDMVersion              ",
None, #"GetPLDMTypes                ",
None, #"GetPLDMCommands             ",
None, #"SelectPLDMVersion           ",
None, #"NegotiateTransferParameters ",
None, #"MultipartSend               ",
None #"MultipartReceive            "
],
[
None, # "SetTID                    ",
None, # "GetTID                    ",
None, # "GetTerminusUID            ",
None, # "SetEventReceiver          ",
None, # "GetEventReceiver          ",
None, # "PlatformEventMessage      ",
None, # "SetNumericSensorEnable    ",
GetSensorReading_req         ,
None, # "GetSensorThresholds       ",
None, # "SetSensorThresholds       ",
None, # "RestoreSensorThresholds   ",
None, # "GetSensorHysteresis       ",
None, # "SetSensorHysteresis       ",
None, # "InitNumericSensor         ",
None, # "SetStateSensorEnables     ",
None, # "GetStateSensorReadings    ",
None, # "InitStateSensor           ",
None, # "SetNumericEffecterEnable  ",
None, # "SetNumericEffecterValue   ",
None, # "GetNumericEffecterValue   ",
None, # "SetStateEffecterEnables   ",
None, # "SetStateEffecterStates    ",
None, # "GetStateEffecterStates    ",
None, # "GetPLDMEventLogInfo       ",
None, # "EnablePLDMEventLogging    ",
None, # "ClearPLDMEventLog         ",
None, # "GetPLDMEventLogTimestamp  ",
None, # "SetPLDMEventLogTimestamp  ",
None, # "ReadPLDMEventLog          ",
None, # "GetPLDMEventLogPolicyInfo ",
None, # "SetPLDMEventLogPolicy     ",
None, # "FindPLDMEventLogEntry     ",
None, # "GetPDRRepositoryInfo      ",
GetPDR_req                    ,
None, # "FindPDR                   ",
None # "RunInitAgent              "
],
[
None, #"GetFRURecordTableMetadata",
None, #"GetFRURecordTable        ",
None, #"SetFRURecordTable        ",
None #"GetFRURecordByOption     "
],
[
None, #"QueryDeviceIdentifiers           ",
None, #"GetFirmwareParameters            ",
None, #"QueryDownstreamDevices           ",
None, #"QueryDownstreamIdentifiers       ",
None, #"GetDownstreamFirmwareParameters  ",
RequestUpdate_req, #"RequestUpdate                    ",
None, #"GetPackageData                   ",
None, #"GetDeviceMetaData                ",
PassComponentTable_req, #"PassComponentTable               ",
UpdateComponent_req, #"UpdateComponent                  ",
RequestFirmwareData_req, #"RequestFirmwareData              ",
None, #"TransferComplete                 ",
None, #"VerifyComplete                   ",
None, #"ApplyComplete                    ",
None, #"GetMetaData                      ",
None, #"ActivateFirmware                 ",
None, #"GetStatus                        ",
None, #"CancelUpdateComponent            ",
None, #"CancelUpdate                     ",
None, #"ActivatePendingComponentImageSet ",
None, #"ActivatePendingComponentImage    ",
None #"RequestDownstreamDeviceUpdate    "
]
]

def QueryDeviceIdentifiers_resp(line, packet, base, cmd_str):
	completion = packet[base]
	DeviceIdentifiersLength = dword_little(packet, base+1)
	DescriptorCount  = packet[base+5]
	next = base+6
	for x in range( DescriptorCount ):
		InitialDescriptorType = word_little(packet, next)
		InitialDescriptorLength = word_little(packet, next+2)
		if( InitialDescriptorType == 0x0000 ):
			VID = word_little(packet, next+4)
			print( "                  PCI Vendor ID ", hex(VID) )
			next=next+6
		if( InitialDescriptorType == 0x0001 ):
			IANA = dword_little(packet, next+4)
			next=next+8
			print( "                  IANA ", IANA )	
		if( InitialDescriptorType == 0x0002 ):
			UUID = packet[next+4:next+20]
			next = next + 20
			print( "                  UUID ", UUID )	
		if( InitialDescriptorType == 0x0100 ):
			DID = word_little(packet, next+4)
			next = next + 6
			print(  "                  Device ID ", hex( DID) )		
		if( InitialDescriptorType == 0x0101 ):
			svID = word_little(packet, next+4)
			next = next + 6
			print(  "                  sub Vendor ID ", hex(svID) )			
		if( InitialDescriptorType == 0x0102 ):
			sDID = word_little(packet, next+4)
			next = next + 6
			print(  "                  sub Device ID ", hex(sDID) )	
		if( InitialDescriptorType == 0x0103 ):
			revision = packet[next+4]
			next = next + 5
			print( "                  PCI revision ID ", revision )		
		if( InitialDescriptorType == 0xffff ):
			#different than table 9 in dsp0267_v1.1.0
			VendorDefinedLength = word_little(packet, next+2) 
			VendorDefinedString = packet[next+6:next+4+VendorDefinedLength]
			next = next + 4 + VendorDefinedLength
			print(  "                  VendorDefined ", end="" )
			for i in range(len(VendorDefinedString)):
				if( VendorDefinedString[i] == 0 ):
					break
				print(chr(VendorDefinedString[i]) , end="")
			print()

def GetFirmwareParameters_resp(line, packet, base, cmd_str):
	completion = packet[base]
	CapabilitiesDuringUpdate = dword_little(packet, base+1)
	ComponentCount = word_little( packet, base+5 )
	ActiveImageType  = packet[base+7]
	ActiveImageLength = packet[base+8]
	PendingImageType  = packet[base+9]
	PendingImageLength = packet[base+10]
	ActiveImageStr = packet[base+11:base+11+ActiveImageLength]
	print("                  Capabilities=", hex(CapabilitiesDuringUpdate), 
		  "ComponentCount=", ComponentCount, 
		  ActiveImageType,ActiveImageLength,
		  PendingImageType,PendingImageLength, end=" " )
	for i in range(len(ActiveImageStr)):
		if( ActiveImageStr[i] == 0 ):
			break
		print(chr(ActiveImageStr[i]) , end="")
	print()		  
	
pldmCMDcode_resp = [
[
None, #"SetTID                      ",
None, #"GetTID                      ",
None, #"GetPLDMVersion              ",
None, #"GetPLDMTypes                ",
None, #"GetPLDMCommands             ",
None, #"SelectPLDMVersion           ",
None, #"NegotiateTransferParameters ",
None, #"MultipartSend               ",
None #"MultipartReceive            "
],
[
None, # "SetTID                    ",
None, # "GetTID                    ",
None, # "GetTerminusUID            ",
None, # "SetEventReceiver          ",
None, # "GetEventReceiver          ",
None, # "PlatformEventMessage      ",
None, # "SetNumericSensorEnable    ",
GetSensorReading_resp          ,
None, # "GetSensorThresholds       ",
None, # "SetSensorThresholds       ",
None, # "RestoreSensorThresholds   ",
None, # "GetSensorHysteresis       ",
None, # "SetSensorHysteresis       ",
None, # "InitNumericSensor         ",
None, # "SetStateSensorEnables     ",
None, # "GetStateSensorReadings    ",
None, # "InitStateSensor           ",
None, # "SetNumericEffecterEnable  ",
None, # "SetNumericEffecterValue   ",
None, # "GetNumericEffecterValue   ",
None, # "SetStateEffecterEnables   ",
None, # "SetStateEffecterStates    ",
None, # "GetStateEffecterStates    ",
None, # "GetPLDMEventLogInfo       ",
None, # "EnablePLDMEventLogging    ",
None, # "ClearPLDMEventLog         ",
None, # "GetPLDMEventLogTimestamp  ",
None, # "SetPLDMEventLogTimestamp  ",
None, # "ReadPLDMEventLog          ",
None, # "GetPLDMEventLogPolicyInfo ",
None, # "SetPLDMEventLogPolicy     ",
None, # "FindPLDMEventLogEntry     ",
None, # "GetPDRRepositoryInfo      ",
GetPDR_resp                ,
None, # "FindPDR                   ",
None # "RunInitAgent              "
],
[
None, #"GetFRURecordTableMetadata",
None, #"GetFRURecordTable        ",
None, #"SetFRURecordTable        ",
None #"GetFRURecordByOption     "
],
[
QueryDeviceIdentifiers_resp, #"QueryDeviceIdentifiers           ",
GetFirmwareParameters_resp, #"GetFirmwareParameters            ",
None, #"QueryDownstreamDevices           ",
None, #"QueryDownstreamIdentifiers       ",
None, #"GetDownstreamFirmwareParameters  ",
RequestUpdate_resp, #"RequestUpdate                    ",
None, #"GetPackageData                   ",
None, #"GetDeviceMetaData                ",
PassComponentTable_resp, #"PassComponentTable               ",
UpdateComponent_resp, #"UpdateComponent                  ",
None, #"RequestFirmwareData              ",
None, #"TransferComplete                 ",
None, #"VerifyComplete                   ",
None, #"ApplyComplete                    ",
None, #"GetMetaData                      ",
None, #"ActivateFirmware                 ",
None, #"GetStatus                        ",
None, #"CancelUpdateComponent            ",
None, #"CancelUpdate                     ",
None, #"ActivatePendingComponentImageSet ",
None, #"ActivatePendingComponentImage    ",
None #"RequestDownstreamDeviceUpdate    "
]
]

def SetEndpointID_req(line,packet, base, cmd_idx ):
	ReqData = packet[base+1]
	EID = packet[base+2]
	print("ReqData", hex(ReqData), "EID", EID  )
	
mctp_ctrl_req_fun=[
SetEndpointID_req, #"Set Endpoint ID               ",
None, #"Get Endpoint ID               ",
None, #"Get Endpoint UUID             ",
None, #"Get MCTP Version              ",
None, #"Get Message Type              ",
None, #"Get Vendor Defined Message    ",
None, #"Resolve Endpoint ID           ",
None, #"Allocate Endpoint IDs         ",
None, #"Routing Information Update    ",
None, #"Get Routing Table Entries     ",
None, #"Prepare for Endpoint Discovery",
None, #"Endpoint Discovery            ",
None, #"Discovery Notify              ",
None, #"Get Network ID                ",
None, #"Query Hop                     ",
None, #"Resolve UUID                  ",
None, #"Query rate limit              ",
None, #"Request TX rate limit         ",
None, #"Update rate limit             ",
None #"Query Supported Interfaces    "
]

def SetEndpointID_resp(line,packet, base, cmd_idx ):
	completion_code = packet[base+1]
	EIDstatus = packet[base+2]
	EIDsetting = packet[base+3]
	EIDpoolsize = packet[base+4]
	print("EID status", hex(EIDstatus), "EID setting", EIDsetting, "EID pool size",EIDpoolsize )

def GetEndpointID_resp(line,packet, base, cmd_idx ):
	completion_code = packet[base+1]
	EID = packet[base+2]
	Etype = packet[base+3]
	print("EID", EID, "Endpoint Type", hex(Etype) )

def GetMessageType_resp(line,packet, base, cmd_idx ):
	completion_code = packet[base+1]
	cnt = packet[base+2]
	msgtypes = packet[base+3: base+3+cnt]
	mctptypestr=["00 MCTP control", "01 PLDM","02 NCSI over mctp","03 eth over mctp","04 nvm over mctp","05 SPDM over mctp","06","07","08"]
	for type in msgtypes:
		if type < len(mctptypestr):
			print(mctptypestr[type] )
		else:
			print(f"{type} is out of mctptypestr")

mctp_ctrl_resp_fun=[
SetEndpointID_resp, #"Set Endpoint ID               ",
GetEndpointID_resp, #"Get Endpoint ID               ",
None, #"Get Endpoint UUID             ",
None, #"Get MCTP Version              ",
GetMessageType_resp, #"Get Message Type              ",
None, #"Get Vendor Defined Message    ",
None, #"Resolve Endpoint ID           ",
None, #"Allocate Endpoint IDs         ",
None, #"Routing Information Update    ",
None, #"Get Routing Table Entries     ",
None, #"Prepare for Endpoint Discovery",
None, #"Endpoint Discovery            ",
None, #"Discovery Notify              ",
None, #"Get Network ID                ",
None, #"Query Hop                     ",
None, #"Resolve UUID                  ",
None, #"Query rate limit              ",
None, #"Request TX rate limit         ",
None, #"Update rate limit             ",
None #"Query Supported Interfaces    "
]
def SPDM_GetVersion_resp(line, length, packet, base, cmd_str):
	VersionNumberEntryCount  = packet[base+5]
	next = 6
	for i in range(VersionNumberEntryCount) :
		VersionNumberEntry = word_big(packet, base+next)
		next = next + 2
		major = (VersionNumberEntry >> 12) & 0xf
		minor = (VersionNumberEntry >> 8) & 0xf
		UpdateVersionNumber = (VersionNumberEntry >> 4) & 0xf
		Alpha = (VersionNumberEntry ) & 0xf
		print(f"major={major}, minor={minor}, updateVersion={UpdateVersionNumber}, alpha={Alpha}")
		
def SPDM_GetDigest_resp(line, length, packet, base, cmd_str):
	Param2_Slot_mask  = packet[base+3]
	print(f"Param2_Slot_mask={Param2_Slot_mask} get_digest=", end="")
	for i in range(48) :
		off = base+4+i
		if off >= length :
			break
		Digest = packet[ off ]
		print(f"{Digest:02x}", end="")	
	print("")
	
def SPDM_GetCertificate_req(line, packet, base, cmd_str):
	Param1_slot_num  = packet[base+2]
	offset = word_little(packet, base+4)
	length = word_little(packet, base+6)
	print(f"    Param1_Slot={Param1_slot_num}   get_certificate_off={offset}        len={length}")

def SPDM_Challenge_req(line, packet, base, cmd_str):
	Param1_slot_num  = packet[base+2]
	Param2_hash_type  = packet[base+3]	
	print(f"    Param1_Slot={Param1_slot_num}   Param2_hash_type={Param2_hash_type} ")	

def SPDM_GetCertificate_resp(line, length, packet, base, cmd_str):
	Param1_slot_num  = packet[base+2]
	portion = word_little(packet, base+4)
	remainder = word_little(packet, base+6)

	#for i in range(base,base+ 8):
	#	print(f"{packet[i]:02x}", end="")
	#print("     <-- spdm header")
	portion_start = base + 8
	portion_end = portion_start+portion
	if portion_end > length :
		print(f"Err: portion_end > mctp length")
	cert_chain_length = word_little(packet, portion_start)
	if cert_chain_length == (portion + remainder ): # first portion
		#print(f"cert_chain_length(including cert header 4B + root hash 48B )={cert_chain_length}")
		print(f"    get_certificate_length={cert_chain_length} get_certificate_slot={Param1_slot_num} get_certificate_portion={portion}  get_certificate_remainder={remainder}")
		print("    get_certificate_header=", end="")		
		for i in range( portion_start, portion_start+4):
			print(f"{packet[i]:02x}", end="")		
		print(" get_certificate_root_hash=", end="")		
		for i in range( portion_start+4, portion_start+4+48):
			print(f"{packet[i]:02x}", end="")
		print("")
		portion_start = portion_start+4+48
	else:
		print(f"    get_certificate_slot={Param1_slot_num} get_certificate_portion={portion} get_certificate_remainder={remainder}")
	print("get_certificate_cert=", end="")
	for i in range( portion_start, portion_end):
		print(f"{packet[i]:02x}", end="")
	print("")

def SPDM_Challenge_resp(line, length, packet, base, cmd_str):
	Param1_attr_field  = packet[base+2]
	Param2_slot_mask  = packet[base+3]	
	print(f"    Param1_attr_field={Param1_attr_field} Param2_slot_mask={Param2_slot_mask} Challenge_CertChainHash=", end="")
	endofhash = min(length, base+4+48)
	for i in range( base+4, endofhash):
		print(f"{packet[i]:02x}", end="")
	print("")

spdm_cmd = [0x01,0x02,0x03,0x04,0x05,0x06,0x60,0x61,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x7e,0x7f ]
spdm_cmd_str = [
"Get Digests               ",
"Get Certificate         ",
"Challenge             ",
"Get Version              ",
"Chunk Send              ",
"Chunk Get    ",
"Get Measurements          ",
"Get Capabilities         ",
"Negotiate Algorithms    ",
"Key Exchange     ",
"Finish",
"PSK Exchange          ",
"PSK finish            ",
"Heart Beat              ",
"Key update             ",
"RGET_ENCAPSULATED_REQUEST   ",
"DELIVER_ENCAPSULATED_RESPONSE ",
"END_SESSION        ",
"GET_CSR  ",
"SET_CERTIFICATE ",
"VENDOR_DEFINED_REQUEST",
"RESPOND_IF_READY",
]

spdm_req_fun=[
None,#"Get Digests               ",
SPDM_GetCertificate_req,#"Get Certificate         ",
SPDM_Challenge_req,#"Challenge             ",
None,#"Get Version              ",
None,#"Chunk Send              ",
None,#"Chunk Get    ",
None,#"Get Measurements          ",
None,#"Get Capabilities         ",
None,#"Negotiate Algorithms    ",
None,#"Key Exchange     ",
None,#"Finish",
None,#"PSK Exchange          ",
None,#"PSK finish            ",
None,#"Heart Beat              ",
None,#"Key update             ",
None,#"RGET_ENCAPSULATED_REQUEST   ",
None,#"DELIVER_ENCAPSULATED_RESPONSE ",
None,#"END_SESSION        ",
None,#"GET_CSR  ",
None,#"SET_CERTIFICATE ",
None,#"VENDOR_DEFINED_REQUEST",
None #"RESPOND_IF_READY",
]

spdm_resp_fun=[
SPDM_GetDigest_resp,#"Get Digests               ",
SPDM_GetCertificate_resp,#"Get Certificate         ",
SPDM_Challenge_resp,#"Challenge             ",
SPDM_GetVersion_resp,#"Get Version              ",
None,#"Chunk Send              ",
None,#"Chunk Get    ",
None,#"Get Measurements          ",
None,#"Get Capabilities         ",
None,#"Negotiate Algorithms    ",
None,#"Key Exchange     ",
None,#"Finish",
None,#"PSK Exchange          ",
None,#"PSK finish            ",
None,#"Heart Beat              ",
None,#"Key update             ",
None,#"RGET_ENCAPSULATED_REQUEST   ",
None,#"DELIVER_ENCAPSULATED_RESPONSE ",
None,#"END_SESSION        ",
None,#"GET_CSR  ",
None,#"SET_CERTIFICATE ",
None,#"VENDOR_DEFINED_REQUEST",
None #"RESPOND_IF_READY",
]

def ncsi_checksum(packet, base, payload_length):
	if(base+16+payload_length > 60):
		return
	checksum = 0
	for i in range(base, base+16+payload_length, 2):
		checksum = checksum + word_big(packet, i)
	checksum = 0xffffffff-(checksum)+1
	offset = ((payload_length+3)>>2)<<2
	pkt_check = dword_big(packet,base+16+offset )
	if( checksum != pkt_check ):
		print("------>>>>>>>> checksum err: pkt", hex(pkt_check),"expected:", hex(checksum))
			
def ncsi_check(line, packet, base):
	mcid = packet[base]
	header_revision = packet[base+1]
	iid = packet[base+3]
	command = packet[base+4]
	chid = packet[base+5]
	payload_length=packet[base+7]
	for i in range(0,len(ncsi_cmd)):
		if( ncsi_cmd[i] ==  command ) :
			ncsi_cmd_req[i](line, packet, base+16, i, chid)
			ncsi_checksum(packet, base, payload_length)
		elif( (ncsi_cmd[i]+0x80) == command ):
			ncsi_cmd_res[i](line, packet, base+16, i, chid)

	
def rmii_ncsi(lineno, packet):
	if( packet[12] == 0x88 ) and (packet[13] == 0xf8):
		ncsi_check(lineno, packet, 14)
		
def mctp_ctrl_check(line, packet):
	rq = packet[1] & 0x80 
	command_code = packet[2]
	completion_code = packet[3]
	for i in range(0,len(mctp_ctrl_cmd)):
		if( mctp_ctrl_cmd[i] == command_code ):
			if( rq != 0x80 ):
				print("[",line,"][mctp re:]", mctp_ctrl_cmd_str[i] )	
				if( check_completion_code(completion_code) and  (mctp_ctrl_resp_fun[i] != None )):
					mctp_ctrl_resp_fun[i]( line, packet, 2, i)
			else:
				print("[",line,"][  mctp  ]", mctp_ctrl_cmd_str[i] )
				if(mctp_ctrl_req_fun[i] != None ):
					mctp_ctrl_req_fun[i]( line, packet, 2, i)
			break


def pldm_check(line, packet, base):
	rq = packet[base] & 0x80 
	pldm_type = packet[base+1] & 0x3f
	command_code = packet[base+2]
	# only response has completion code
	completion_code = packet[base+3]

	for i in range(0,len(pldmType)):
		if( pldmType[i] == pldm_type ):
			for j in range(0, len(pldmCMDcode[i]) ):
				if( pldmCMDcode[i][j] == command_code ) : 	
					# if response check check completion
					if( rq != 0x80 ):
						print("[",line,"][pldm",pldm_type,"Re:]",  pldmCMDcode_str[i][j]  )	
						if( check_completion_code(completion_code) and ( pldmCMDcode_resp[i][j] != None )):
							pldmCMDcode_resp[i][j]( line, packet, base+3 ,pldmCMDcode_str[i][j]  )
							
					else:
						print("[",line,"][ pldm ",pldm_type," ]",  pldmCMDcode_str[i][j]  )	
						if( pldmCMDcode_req[i][j] != None ):
							pldmCMDcode_req[i][j]( line, packet, base+3, pldmCMDcode_str[i][j]   )
					break
					
def spdm_check(line, length, packet, base):
	version = packet[base]
	rq = packet[base+1] & 0x80
	code = packet[base+1] & 0x7f
	param1 = packet[base+2]
	param2 = packet[base+3]
	for i in range(0,len(spdm_cmd)):
		if( spdm_cmd[i] == code ):
			if( rq != 0x80 ):
				print("[",line,"][SPDM re:]", spdm_cmd_str[i] )	
				if spdm_resp_fun[i] != None :
					spdm_resp_fun[i](line, length, packet, base, spdm_cmd_str[i])
			else:
				print("[",line,"][  SPDM  ]", spdm_cmd_str[i] )
				if spdm_req_fun[i] != None :
					spdm_req_fun[i](line, packet, base, spdm_cmd_str[i])				
			break	
			
def mctp_ncsi(lineno, length, packet):
	type = packet[0]
	if( type == 0x00 ) :
		#MCTP Control
		mctp_ctrl_check(lineno,packet)
	elif( type == 0x01 ) :
		pldm_check(lineno, packet, 1)
	elif( type == 0x02 ) :
		ncsi_check(lineno, packet, 1)
	elif( type == 0x05 ):
		spdm_check(lineno, length, packet, 1)
	return type
		
def GetPFMACAddress_req(packet, base):
	pf_index = packet[base]
	print("                       pf_index", pf_index )
	return True

def GetPFMACAddress_resp(packet, base):
	pf_index = packet[base]
	mac0 = packet[base+1]
	mac1 = packet[base+2]
	mac2 = packet[base+3]
	mac3 = packet[base+4]
	mac4 = packet[base+5]
	mac5 = packet[base+6]
	rate_limiter = packet[base+7]*256 + packet[base+8]
	print("                       pf_index", pf_index , "MAC ", end="") 
	print("%02x:%02x:%02x:%02x:%02x:%02x" %(mac0, mac1, mac2, mac3, mac4, mac5),  end="" )
	print(" Rate limiter", rate_limiter)

def GetTemp_req(packet, base):
	sp_index = packet[base]
	sp = sp_index >> 7
	sensor = sp_index & 0x7f
	sp_str = "on-chip"
	if( sp == 1 ):
		sp_str = "Port"
	print("                       sp", sp,sp_str, "sensor index", sensor )
	#return false for the up layer to check if the channel id == 0x1f
	return False

def GetTemp_resp(packet, base):
	sp_index = packet[base]
	sp = sp_index >> 7
	sensor = sp_index & 0x7f
	current_temp = packet[base+4]
	sp_str = "on-chip"
	if( sp == 1 ):
		sp_str = "Port"
	print("                       sp", sp,sp_str, "sensor index", sensor, "current_temp", current_temp )	

def GetSendModuleSerialData(packet, base):
	i2c_addr = packet[base+1]
	page_num = packet[base+2]
	dev_addr = word_big(packet,base+3)
	page_lock = packet[base+5]
	operation = packet[base+6]
	transfer_size = word_big(packet, base+7)
	data = dword_big(packet, base+9)
	print("                  i2c addr=", hex(i2c_addr), end="")
	print(" page num=", page_num, end="")
	print(" dev addr=", hex( dev_addr), end="")
	print(" page lock=", page_lock, end="")
	print(" operation=", operation, end="")
	print(" transfer size=", transfer_size, " data[0]=",hex(data))
	return True
	
def GetSmartNICOSstate_req(packet, base):
	#return false for the up layer to check if the channel id == 0x1f
	return False
	
def GetSmartNICOSstate_resp(packet, base):
	state = packet[base+4]
	os_stat_str=["Reset/Boot-ROM", "BL2", "BL31", "UEFI", "OS starting", "OS is running", "Low-Power standby", "firmware updating", "OS crash dumping", "OS crash dump completed", "FW fault crash dumping", "FW fault crash dump completed"  ]
	sstr = "Other"
	if( state < len(os_stat_str) ):
		sstr = os_stat_str[state]
	print("      os state=", sstr)
	
	
def SetLLDPNB_req(packet, base):
	reserved = packet[base]
	mode = packet[base+4]
	print("                       Mode", hex(mode), end="" )
	print(" LLDP_NB_DCBX/RX_mode/TX_mode=", mode&0x1, (mode&0x6)>>1, (mode&0x18)>>3 )	
	#return true for the up layer not to check the channel id
	return True	
	
def ResetNIC_req(packet, base):
	mode = packet[base]
	print("                       Mode=", mode )
	#return False for the up layer to check the channel id==0x1f
	return False		
	
def GetMLNX_Link_Status_resp(packet, base):
	link_type = packet[base+3]
	phy_log_state = packet[base+4]
	phy_state = phy_log_state >> 4
	log_state = phy_log_state & 0x0f
	ib_act_width = packet[base+5]
	ib_act_speed = packet[base+6]
	ib_sup_width = packet[base+7]
	ib_sup_speed = packet[base+8]
	phy_stat_str=["eth", "sleep", "polling", "disable", "training", "linkup", "link err recover", "phy test"]
	log_stat_str=["eth", "down", "init", "arm","active"]
	if link_type == 0 :
		print("                  link type: Ethernet")
	if link_type == 1 :
		print("                  link type: Infiniband" , end="")
		print(" phy stat= ", phy_stat_str[phy_state], end="")
		print(" log stat= ", log_stat_str[log_state], end="")
		print(" ib_act_width=", hex( ib_act_width), end="")
		print(" ib_act_speed=", hex( ib_act_speed), end="")
		print(" ib_sup_width=", hex( ib_sup_width), end="")
		print(" ib_sup_speed=", hex( ib_sup_speed), end="")

	return True	
	
oemfun_req = [
[
GetPFMACAddress_req, #"Get PF MAC Address                 ",
None, #"Get FCoE Configuration             ",
None, #"Get PXE Configuration              ",
None, #"Get Multi-PF Capabilities          ",
None, #"Get SR-IOV Configuration           ",
None, #"Get Enhanced Tagging Configuration ",
None, #"Get iSCSI Configuration            ",
None, #"Get Addresses Groups Count         ",
None, #" Get Addresses                     ",
None, #" Get Allocated Management Address  ",
None, #" Get Safe Mode Configuration       ",
None, #" Get Driver Information            ",
None, #" Get Cable Information             ",
None, #" Get Card VPD Information          ",
None, #" Get Card TLV Information          ",
None, #" Query Hosts                       ",
None, #" Get Chassis Rate Limiting         ",
None, #" Get Rate Limiting                 ",
None, #" Get Port ID                       ",
None, #" Get Self Recovery Setting         ",
None, #" Get Interface Info                ",
None, #" Get Device ID                     ",
None, #" Get Port ECC Counters             ",
None, #" Get LLDP NB                       ",
None, #" Get Log Information               ",
None, #" Get Network Debug Info            "
],
[
None, #"Set PF MAC Address         ",
None, #"Set FCoE Configuration     ",
None, #"Set PXE Configuration      ",
None, #"Set Multi-PF Configuration ",
None, #"Set SR-IOV Configuration   ",
None, #"Set Enhanced Tagging Configuration",
None, #"Set iSCSI Configuration    ",
None, #"Set MC affinity            ",
None, #" Set Addresses             ",
None, #" Set Safe Mode Configuration",
None, #" Set Card TLV Information  ",
None, #" Enable Hosts              ",
None, #" Set Chassis Rate Limiting ",
None, #" Set Rate Limiting         ",
None, #" Set Self Recovery Setting ",
None, #" Set MH PTP mode           ",
None, #" Set PTP Parameters        ",
SetLLDPNB_req, #" Set LLDP NB               ",
None, #" Erase Log Information     ",
None, #" Set Network Debug Info    "
],
[
None, #"Get Management Filtering Enable       ",
None, #"Get Management Filters Banks Count    ",
None, #" Get Flex Filter mask and length      ",
None, #" Get Flex Filter Data                 ",
None, #" Get Mellanox decision filter         ",
None, #" Get ARP Offload                      ",
None, #" Get Configurable UDP/TCP ports       ",
None, #" Get IPv4 Address                     ",
None, #" Get IPv6 Address                     ",
None, #" Get Configurable MAC Address         ",
None, #" Get Configurable EtherType           ",
None, #" Get Mellanox Extended decision filter"
],
[
None, #"Set Management Filtering Enable       ",
None, #"Set Management Only                   ",
None, #" Set Flex Filter mask and length      ",
None, #" Set Flex Filter Data                 ",
None, #" Set Mellanox decision filter         ",
None, #" Set Configurable MAC Address         ",
None, #" Set Configurable EtherType           ",
None, #" Set Mellanox Extended decision filter",
None, #" Set ARP Offload                      ",
None, #" Set IPv4 Address                     ",
None, #" Set IPv6 Address                     "
],
[
None, #"Set Port LED control             ",
None, #"Set Temperature Controls         ",
None, #"Set Register                     ",
None, #"Set Mellanox AEN Controls        ",
ResetNIC_req, #"Reset NIC                        ",
None, #"Reset Smart NIC                  ",
None, #"Set Chip Registers               ",
None, #"Disable Token                    ",
None, #" Module Re-Plug                  ",
GetSendModuleSerialData, #" Send Module Serial data         ",
None, #" Send PHY Serial data            ",
None, #" Set Token                       ",
None, #" Set FRU WP control              ",
None, #" Interrupt Smart NIC             ",
None, #" Set Host Access to Smart NIC CPU",
None, #" Set Time                        ",
None, #" Set BMC Certificates            ",
None, #" Enable Trust                    ",
None, #" Set Smart NIC Boot Option       "
],
[
None, #"  Get Port LED control           ",
None, #"Get Temperature Controls         ",
GetTemp_req, #"Get Temperature                  ",
None, #"Get Register                     ",
None, #"Get Mellanox AEN Controls        ",
None, #"Get Mellanox Link Status         ",
None, #"Get Electrical Sensors Count     ",
None, #"Get Electrical Sensor            ",
None, #"Get Electrical Sensors           ",
None, #"Get System Thermal Sensors Count ",
None, #"Get PCIe Parameters              ",
None, #"Get Chip Registers               ",
GetSendModuleSerialData, #" Get Module Serial Data          ",
None, #" Get PHY Serial Data             ",
None, #" Get Challenge                   ",
None, #" Get Debug Mode Info             ",
GetSmartNICOSstate_req, #" Get Smart NIC OS state          ",
None, #" Get Host Access to Smart NIC CPU",
None, #" Get Smart NIC PCIe Errors       ",
None, #" Get Nonce                       ",
None, #" Query Trust Status              ",
None, #" Get Smart NIC Boot Options      "
]
]

def GetCableInformation_resp(packet, base):
	cage_id = packet[base]
	cable_state = packet[base+1]
	cable_type = packet[base+2]
	print("                  cage id=", cage_id, end="")
	print(" cable state=", cable_state, end="")
	print(" cable info type=", cable_type)
	

def GetLLDPNB_resp(packet, base):
	reserved = packet[base]
	mode = packet[base+4]
	print("                       Mode", hex(mode), end="" )
	print(" LLDP_NB_DCBX/RX_mode/TX_mode=", mode&0x1, (mode&0x6)>>1, (mode&0x18)>>3 )	
	
def SetLLDPNB_resp(packet, base):
	reserved = packet[base]
	mode = packet[base+4]
	print("                       Mode", hex(mode), end="" )
	print(" LLDP_NB_DCBX/RX_mode/TX_mode=", mode&0x1, (mode&0x6)>>1, (mode&0x18)>>3 )	
	
oemfun_resp = [
[
GetPFMACAddress_resp, #"Get PF MAC Address                 ",
None, #"Get FCoE Configuration             ",
None, #"Get PXE Configuration              ",
None, #"Get Multi-PF Capabilities          ",
None, #"Get SR-IOV Configuration           ",
None, #"Get Enhanced Tagging Configuration ",
None, #"Get iSCSI Configuration            ",
None, #"Get Addresses Groups Count         ",
None, #" Get Addresses                     ",
None, #" Get Allocated Management Address  ",
None, #" Get Safe Mode Configuration       ",
None, #" Get Driver Information            ",
GetCableInformation_resp, #" Get Cable Information             ",
None, #" Get Card VPD Information          ",
None, #" Get Card TLV Information          ",
None, #" Query Hosts                       ",
None, #" Get Chassis Rate Limiting         ",
None, #" Get Rate Limiting                 ",
None, #" Get Port ID                       ",
None, #" Get Self Recovery Setting         ",
None, #" Get Interface Info                ",
None, #" Get Device ID                     ",
None, #" Get Port ECC Counters             ",
GetLLDPNB_resp, #" Get LLDP NB                       ",
None, #" Get Log Information               ",
None, #" Get Network Debug Info            "
],
[
None, #"Set PF MAC Address         ",
None, #"Set FCoE Configuration     ",
None, #"Set PXE Configuration      ",
None, #"Set Multi-PF Configuration ",
None, #"Set SR-IOV Configuration   ",
None, #"Set Enhanced Tagging Configuration",
None, #"Set iSCSI Configuration    ",
None, #"Set MC affinity            ",
None, #" Set Addresses             ",
None, #" Set Safe Mode Configuration",
None, #" Set Card TLV Information  ",
None, #" Enable Hosts              ",
None, #" Set Chassis Rate Limiting ",
None, #" Set Rate Limiting         ",
None, #" Set Self Recovery Setting ",
None, #" Set MH PTP mode           ",
None, #" Set PTP Parameters        ",
SetLLDPNB_resp, #" Set LLDP NB               ",
None, #" Erase Log Information     ",
None, #" Set Network Debug Info    "
],
[
None, #"Get Management Filtering Enable       ",
None, #"Get Management Filters Banks Count    ",
None, #" Get Flex Filter mask and length      ",
None, #" Get Flex Filter Data                 ",
None, #" Get Mellanox decision filter         ",
None, #" Get ARP Offload                      ",
None, #" Get Configurable UDP/TCP ports       ",
None, #" Get IPv4 Address                     ",
None, #" Get IPv6 Address                     ",
None, #" Get Configurable MAC Address         ",
None, #" Get Configurable EtherType           ",
None, #" Get Mellanox Extended decision filter"
],
[
None, #"Set Management Filtering Enable       ",
None, #"Set Management Only                   ",
None, #" Set Flex Filter mask and length      ",
None, #" Set Flex Filter Data                 ",
None, #" Set Mellanox decision filter         ",
None, #" Set Configurable MAC Address         ",
None, #" Set Configurable EtherType           ",
None, #" Set Mellanox Extended decision filter",
None, #" Set ARP Offload                      ",
None, #" Set IPv4 Address                     ",
None, #" Set IPv6 Address                     "
],
[
None, #"Set Port LED control             ",
None, #"Set Temperature Controls         ",
None, #"Set Register                     ",
None, #"Set Mellanox AEN Controls        ",
None, #"Reset NIC                        ",
None, #"Reset Smart NIC                  ",
None, #"Set Chip Registers               ",
None, #"Disable Token                    ",
None, #" Module Re-Plug                  ",
GetSendModuleSerialData, #" Send Module Serial data         ",
None, #" Send PHY Serial data            ",
None, #" Set Token                       ",
None, #" Set FRU WP control              ",
None, #" Interrupt Smart NIC             ",
None, #" Set Host Access to Smart NIC CPU",
None, #" Set Time                        ",
None, #" Set BMC Certificates            ",
None, #" Enable Trust                    ",
None, #" Set Smart NIC Boot Option       "
],
[
None, #"  Get Port LED control           ",
None, #"Get Temperature Controls         ",
GetTemp_resp, #"Get Temperature                  ",
None, #"Get Register                     ",
None, #"Get Mellanox AEN Controls        ",
GetMLNX_Link_Status_resp, #"Get Mellanox Link Status         ",
None, #"Get Electrical Sensors Count     ",
None, #"Get Electrical Sensor            ",
None, #"Get Electrical Sensors           ",
None, #"Get System Thermal Sensors Count ",
None, #"Get PCIe Parameters              ",
None, #"Get Chip Registers               ",
GetSendModuleSerialData, #" Get Module Serial Data          ",
None, #" Get PHY Serial Data             ",
None, #" Get Challenge                   ",
None, #" Get Debug Mode Info             ",
GetSmartNICOSstate_resp, #" Get Smart NIC OS state          ",
None, #" Get Host Access to Smart NIC CPU",
None, #" Get Smart NIC PCIe Errors       ",
None, #" Get Nonce                       ",
None, #" Query Trust Status              ",
None, #" Get Smart NIC Boot Options      "
]
]

def store(lineoff, message, base, packet):
	idx = 16* lineoff
	for i in range( 0, 16):
		packet[idx + i] = 0
	
	for i in range(base, len(message) ) :
		str = message[i]
		if( len(str) != 8 ):
			break
		packet[idx]  = get_hex(str[0:2])
		packet[idx+1]= get_hex(str[2:4])
		packet[idx+2]= get_hex(str[4:6])
		packet[idx+3]= get_hex(str[6:8])
		idx = idx+4
	return idx
	
def storepkt(offset, message, base, packet):
	idx = offset
	for i in range(base, len(message) ) :
		str = message[i]
		if( len(str) != 8 ):
			break
		packet[idx]  = get_hex(str[0:2])
		packet[idx+1]= get_hex(str[2:4])
		packet[idx+2]= get_hex(str[4:6])
		packet[idx+3]= get_hex(str[6:8])
		idx = idx+4
	return idx
	
def decode_mctp(lineno, length, buffer):
	mctp_ncsi(lineno, length, buffer)
	

Stat_MCTPo = ["[000]:","payload:", "[000]:", "[010]:","[020]:","[030]:","[040]:","[050]:","[060]:","[070]:","[080]:","[090]:"]
class MCTPo:
	def __init__(self, lineno, type):
		self.buffer = [0]*65536
		self.statexp = 0
		self.type = type
		self.sop = 0
		self.eop = 0
		self.const_payload_start = 2
		self.off = 0
		self.lineno = lineno
		#print(f"{lineno} create type={type}")
		
	def decode_header(self, line):
		if self.type == 0 : # rx
			self.sop = 1
			self.eop = 1
		elif self.type == 2: #smbus tx
			self.sop = 1
			self.eop = 1			
		elif self.type == 1 : # tx
			#decode the SOP EOP
			msg = line.split()
			for i in range(len(msg)):
				if "[000]:" == msg[i]:
					header = [0] * 16
					hlen = storepkt(0, msg, i+1, header)
					if hlen > 1 :
						flag = header[hlen-1]
						self.sop = (flag&0x80) >> 7
						self.eop = (flag&0x40) >> 6
					#print(f"    sop={self.sop} eop={self.eop}")
		if self.sop == 1:
			self.off = 0
		
	def store(self, expstr, line):
		msg = line.split()
		for i in range(len(msg)):
			if expstr == msg[i]:
				self.off = storepkt(self.off, msg, i+1, self.buffer)
			
	def decode(self, line):
		#print(f"{line}")
		if self.statexp > self.const_payload_start :
			if "===END===" in line:
				if self.eop == 1:
					decode_mctp(self.lineno, self.off, self.buffer)
					return 1
				else:
					self.statexp = -1
					return 0
		expstr = Stat_MCTPo[self.statexp]
		if expstr in line:
			if self.statexp == 0 : # header
				self.decode_header(line)
			elif expstr == "payload:" :
				payload = 1
			else: #payloads
				self.store( expstr, line )
			self.statexp = self.statexp + 1
		else:
			return 1
		return 0
			
Stat_RMII = Stat_MCTPo[2:6]
class RMII:
	def __init__(self, lineno, type):
		self.buffer = [0]*65536
		self.statexp = 0
		self.type = type
		self.off = 0
		self.lineno = lineno
		
	def store(self, expstr, line):
		msg = line.split()
		for i in range(len(msg)):
			if expstr == msg[i]:
				self.off = storepkt(self.off, msg, i+1, self.buffer)
			
	def decode(self, line):
		#print(f"{line}")
		if "===END===" in line:
			rmii_ncsi(self.lineno, self.buffer)
			return 1
		expstr = Stat_RMII[self.statexp]
		if expstr in line:
			self.store( expstr, line )
			self.statexp = self.statexp + 1
		else:
			return 1
		return 0
						
				
def decodelog(Lines):
	lineid = 0
	pkt = None
	for line in Lines:
		lineid = lineid + 1
				
		if "===PCI MESSAGE RECIVED(mctp header)===" in line or "===SMBUS TRANSACTION RECIVED===" in line:
			pkt = MCTPo(lineid, 0)
		elif "===PCI MESSAGE SENT(vdm header)===" in line:
			if pkt != None and pkt.type == 1 and pkt.eop == 0 :
				pkt.statexp = 0
				print(f"    {lineid} middle pkt")
			else:
				#print("smbus sent")
				pkt = MCTPo(lineid, 1)
		elif "===SMBUS TRANSACTION SENT" in line:
			pkt = MCTPo(lineid, 2)
		elif "===RMII PACKET RECIVED===" in line :
			pkt = RMII(lineid, 0)
		elif "===RMII PACKET SENT===" in line:
			pkt = RMII(lineid, 1)
		else:
			if pkt != None and pkt.statexp != -1 :
				if pkt.decode(line) :
					pkt = None
					
def main():
	tfile = ""
	argc = len(sys.argv)

	if( argc > 1 ):
		tfile = sys.argv[1]
		print("fw.trace.analysis v2026.04.23, the input trace log: ", tfile)
	else:
		print("no input fw trace file")
		return
		
	file1 = open(tfile, 'r')
	Lines = file1.readlines()
	decodelog(Lines)
			
			
def main_old():
	tfile = ""
	argc = len(sys.argv)

	if( argc > 0 ):
		tfile = sys.argv[1]
		print("fw.trace.analysis v2026.04.21, the input trace log: ", tfile)
	else:
		print("no input fw trace file")
	file1 = open(tfile, 'r')
	Lines = file1.readlines()

	focus = 0
	for line in Lines:
		msg = line.split()
		for i in range(0, len(msg)):
			if( msg[i] == "[000]:") :
				focus = i
				break;
		if(focus > 0):
			break;


	if( focus == 0):
		print( "it is a bad fw trace file! no focus inside!")
		return

	count = 0

	mst_status = 0
	mctp = 0
	pkt = [0]*65536
	off_str = ["[000]:", "[010]:","[020]:","[030]:","[040]:","[050]:","[060]:","[070]:","[080]:","[090]:"]
	for line in Lines:
		count = count + 1
		msg = line.split()
		msg_cnt = len(msg)
		if( msg_cnt > focus + 1 ):
			for i in range(0, len(off_str)):
				if( msg[focus] == off_str[i] ) :
					if( mst_status == i ):
						store( mst_status, msg, focus+1, pkt)
						mst_status = i+1
					else:
						if( mst_status != -1 ) and (mst_status < len(off_str)):
							print("[",count,"] line err -->> ", off_str[mst_status], "is expected, but got", msg[focus])
						mst_status = -1
					break

					
		if( msg_cnt == focus+1 ) and (msg[focus] == "===END===" ) :
			if( mctp == 1 ) and (mst_status > 0):
				mctp_ncsi(count, 0, pkt)
			elif(mctp ==0) and ( mst_status > 1 ):
				#print("NCSI[",count,"]")
				rmii_ncsi(count, pkt )
			mst_status = 0
			mctp = 0
		
		if( msg_cnt == focus+1 ) and (msg[focus] == "payload:" ) :
			#check if previous header [7]=7f, [10:11]=1AB4, and then check [15]&0x80 SOM bit
			if( mst_status == 1):
				mst_status = 0
				if( pkt[7] == 0x7f) and (pkt[10]==0x1a) and (pkt[11]==0xb4):
					if(( pkt[15]&0x80 ) != 0x80 ):
						mst_status = -1
			mctp = 1
	

	

if __name__ == '__main__':
	main()
##############
# usage:
#     fw.trace.analysis.py <fw.trace.log> 
#
##############


