ticap_proto = Proto("ticap","TICAP")

-- UDP and TCP Dissector Tables
udp_table = DissectorTable.get("udp.port")
tcp_table = DissectorTable.get("tcp.port")

dissector_version = "1.0.1"
dissector_date = "2020-01-31"

ticap_proto.fields.info = ProtoField.uint8("ticap.info", "Info", base.HEX)
ticap_proto.fields.seq = ProtoField.uint16("ticap.seq", "Seq")
ticap_proto.fields.len = ProtoField.uint16("ticap.len", "Len")
ticap_proto.fields.bytes = ProtoField.bytes("ticap.bytes", "Packet Data")
ticap_proto.fields.rssi = ProtoField.int8("ticap.rssi", "RSSI")
ticap_proto.fields.status = ProtoField.uint8("ticap.status", "Status", base.HEX)


function ticap_proto.dissector(buffer,pinfo,tree)
	if buffer:len() < 17 then  -- We don't have enough to figure out message length
		pinfo.desegment_len = 17 - buffer:len() -- get more data.
    return
  end

  pinfo.cols.protocol = "SmartRF"

  pktinfo = buffer(0,1):le_uint()
  pktnum = buffer(1,4):le_uint()
  pkttime = buffer(5,8):le_uint64()
  pktlen = buffer(13,2):le_uint()

  pkt2 = buffer(15,pktlen)

  pktrssi = buffer(15+pktlen-2,1):le_int()
  pktstatus = buffer(15+pktlen-1,1):le_uint()


  subtree = tree:add(ticap_proto, buffer(), string.format("SmartRF packet %d Seq:%d Len:%d", pktinfo, pktnum, buffer:len()))

  subtree:add(ticap_proto.fields.info, buffer(0,1))
  subtree:add_le(ticap_proto.fields.seq, buffer(1,4))
  subtree:add(buffer(5,8), "Time: " .. (pkttime/32) .. "uS")
  subtree:add_le(ticap_proto.fields.len, buffer(13,2))
  subtree:add(ticap_proto.fields.bytes, buffer(15,pktlen-2))
  subtree:add(ticap_proto.fields.rssi, buffer(15+pktlen-2,1))
  subtree:add(ticap_proto.fields.status, buffer(15+pktlen-1,1))

  wpan:call(pkt2(1):tvb(), pinfo, subtree)

end


udp_table:add(5000,ticap_proto)

data_handle = Dissector.get("data")
--wpan = Dissector.get("wpan_nofcs")
wpan = Dissector.get("wpan_cc24xx")
--ieee = Dissector.get("ieee802154")
