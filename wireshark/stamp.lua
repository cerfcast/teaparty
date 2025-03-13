--- A Wireshark dissector for STAMP packets.

local stamp_protocol = Proto("STAMP", "STAMP Protocol")


--- Field Sizes

local sequence_field_size = 4
local timestamp_field_size = 8
local error_estimate_field_size = 2
local ssid_field_size = 2
local hmac_field_size = 16
local reflected_authenticated_mbz1_size = 12
local reflected_authenticated_mbz2_size = 4 -- NOTE: Set to 4 (not six) because of SSID.
local reflected_authenticated_mbz3_size = 8
local reflected_authenticated_mbz4_size = 12
local reflected_authenticated_mbz5_size = 6
local reflected_authenticated_mbz6_size = 15
local session_sender_base_length = 28
local session_sender_authenticated_base_length = 68


--- A means for fetching the protofields for different timestamps in the STAMP packets.
local timestamp_fields = {}

--- Dissect an error estimate
-- @tparam Tvb buffer Bytes containing the raw contents of the error estimate.
-- @tparam string name The name of the particular timestamp field to which the
-- to-be-dissected error estimate is attached.
-- @tparam TreeItem tree The tree on which to attach the dissected error estimate.
-- @treturn int The size of the error estimate field.
local function dissect_error_estimate(buffer, name, tree)
	local base_protofield = timestamp_fields[name]["error_estimate"][""]
	local s_protofield = timestamp_fields[name]["error_estimate"]["s"]
	local z_protofield = timestamp_fields[name]["error_estimate"]["z"]
	local scale_protofield = timestamp_fields[name]["error_estimate"]["scale"]
	local multiplier_protofield = timestamp_fields[name]["error_estimate"]["multiplier"]

	local error_tree = tree:add(base_protofield, buffer(0, 2))
	error_tree:add(s_protofield, buffer(0, 1))
	error_tree:add(z_protofield, buffer(0, 1))
	error_tree:add(scale_protofield, buffer(0, 1))
	error_tree:add(multiplier_protofield, buffer(1, 1))
	return 2
end

--- Dissect a timestamp (with or without an error estimate)
-- @tparam Tvb buffer Bytes containing the raw contents of the timestamp and (optionally) error estimate.
-- @tparam string name The name of the timestamp field to be dissected.
-- @tparam string display The display name for the dissected timestamp and (optionally) error estimate field.
-- @tparam bool include_error_estimate Whether or not to dissecte an associated error estimate.
-- @tparam TreeItem tree The tree on which to attach the dissected timestamp and (maybe) error estimate.
-- @treturn int The size of the dissected timestamp and (maybe) error estimate that was decoded.
local function dissect_timestamp(buffer, name, display, include_error_estimate, tree)
	local minimum_size = timestamp_field_size + (include_error_estimate and error_estimate_field_size or 0)
	if buffer:len() < minimum_size then
		tree:add(buffer, "Error")
		return false
	end

	local base_protofield = timestamp_fields[name][""]
	local seconds_protofield = timestamp_fields[name]["seconds"]
	local fractions_protofield = timestamp_fields[name]["fractions"]

	local timestamp_tree = tree:add(base_protofield, buffer(0, 8))
	timestamp_tree.text = display -- Necessary to make sure that the bytes are not printed,
	-- but we get wireshark to highlight the bytes.
	timestamp_tree:add(seconds_protofield, buffer(0, 4))
	timestamp_tree:add(fractions_protofield, buffer(4, 4))
	return 8 + (include_error_estimate and dissect_error_estimate(buffer(8, 2), name, timestamp_tree) or 0)
end

-- Sequence
local sequence_protofield = ProtoField.uint32("stamp.sequence", "Sequence", base.DEC)
local sender_sequence_protofield = ProtoField.uint32("stamp.sender.sequence", "Sequence", base.DEC)

-- Timestamp
local ts_protofield = ProtoField.none("stamp.timestamp", "Timestamp", base.HEX)
local ts_seconds_protofield = ProtoField.uint32("stamp.timestamp.seconds", "Seconds", base.DEC)
local ts_fractions_protofield = ProtoField.uint32("stamp.timestamp.fractions", "Fractions", base.DEC)

-- Error Estimate
local error_protofield = ProtoField.none("stamp.timestamp.error_estimate", "Error Estimate", base.HEX)
local error_s_protofield = ProtoField.bool("stamp.timestamp.error_estimate.s", "S", 8,
	{ [1] = "Synchronized", [2] = "Not synchronized" }, 0x80,
	"Whether source generating the timestamp is synchronized with an external source.")
local error_z_protofield = ProtoField.bool("stamp.timestamp.error_estimate.z", "Z", 8, { [1] = "Not Zero", [2] = "Zero" },
	0x40, "Must be zero.")
local error_scale_protofield = ProtoField.uint8("stamp.timestamp.error_estimate.scale", "Scale", base.UNIT_STRING, { "" },
	0x3f,
	"Scale")
local error_multiplier_protofield = ProtoField.uint8("stamp.timestamp.error_estimate.multiplier", "Multiplier", base.DEC,
	{ "" }, 0xff, "Multiplier")

timestamp_fields["stamp.timestamp"] = {
	[""] = ts_protofield,
	["seconds"] = ts_seconds_protofield,
	["fractions"] = ts_fractions_protofield,
	["error_estimate"] = {
		[""] = error_protofield,
		["s"] = error_s_protofield,
		["z"] = error_z_protofield,
		["scale"] = error_scale_protofield,
		["multiplier"] = error_multiplier_protofield,
	}
}

-- Received Timestamp
local ts_received_protofield = ProtoField.none("stamp.received_timestamp", "Timestamp", base.HEX)
local ts_received_seconds_protofield = ProtoField.uint32("stamp.received_timestamp.seconds", "Seconds", base.DEC)
local ts_received_fractions_protofield = ProtoField.uint32("stamp.received_timestamp.fractions", "Fractions", base.DEC)

timestamp_fields["stamp.received_timestamp"] = {
	[""] = ts_received_protofield,
	["seconds"] = ts_received_seconds_protofield,
	["fractions"] = ts_received_fractions_protofield,
	["error_estimate"] = nil
}

-- Sender Timestamp
local ts_sender_protofield = ProtoField.none("stamp.sender_timestamp", "Timestamp", base.HEX)
local ts_sender_seconds_protofield = ProtoField.uint32("stamp.sender_timestamp.seconds", "Seconds", base.DEC)
local ts_sender_fractions_protofield = ProtoField.uint32("stamp.sender_timestamp.fractions", "Fractions", base.DEC)

-- Sender Error Estimate
local sender_error_protofield = ProtoField.none("stamp.sender_timestamp.error_estimate", "Error Estimate", base.HEX)
local sender_error_s_protofield = ProtoField.bool("stamp.sender_timestamp.error_estimate.s", "S", 8,
	{ [1] = "Synchronized", [2] = "Not synchronized" }, 0x80,
	"Whether source generating the timestamp is synchronized with an external source.")
local sender_error_z_protofield = ProtoField.bool("stamp.sender_timestamp.error_estimate.z", "Z", 8,
	{ [1] = "Not Zero", [2] = "Zero" }, 0x40, "Must be zero.")
local sender_error_scale_protofield = ProtoField.uint8("stamp.sender_timestamp.error_estimate.scale", "Scale",
	base.UNIT_STRING, { "" }, 0x3f,
	"Scale")
local sender_error_multiplier_protofield = ProtoField.uint8("stamp.sender_timestamp.error_estimate.multiplier",
	"Multiplier", base.DEC, { "" }, 0xff, "Multiplier")

timestamp_fields["stamp.sender_timestamp"] = {
	[""] = ts_sender_protofield,
	["seconds"] = ts_sender_seconds_protofield,
	["fractions"] = ts_sender_fractions_protofield,
	["error_estimate"] = {
		[""] = sender_error_protofield,
		["s"] = sender_error_s_protofield,
		["z"] = sender_error_z_protofield,
		["scale"] = sender_error_scale_protofield,
		["multiplier"] = sender_error_multiplier_protofield,
	}
}

-- TTL
local sender_ttl_protofield = ProtoField.uint8("stamp.sender_ttl", "Sender TTL", base.DEC)

-- Ssid
local ssid_protofield = ProtoField.uint16("stamp.ssid", "SSID", base.HEX)

-- HMAC
local hmac_protofield = ProtoField.bytes("stamp.hmac", "HMAC")

stamp_protocol.fields = { sequence_protofield, sender_sequence_protofield,
	ts_protofield, ts_seconds_protofield, ts_fractions_protofield,
	error_protofield, error_s_protofield, error_z_protofield, error_scale_protofield, error_multiplier_protofield,
	sender_error_protofield, sender_error_s_protofield, sender_error_z_protofield, sender_error_scale_protofield,
	sender_error_multiplier_protofield,
	ts_received_protofield, ts_received_seconds_protofield, ts_received_fractions_protofield,
	ts_sender_protofield, ts_sender_seconds_protofield, ts_sender_fractions_protofield,
	ssid_protofield,
	sender_ttl_protofield,
	hmac_protofield,
}

local dscp_type_map =
{
	[0] = "CS0",
	[8] = "CS1",
	[16] = "CS2",
	[24] = "CS3",
	[32] = "CS4",
	[40] = "CS5",
	[48] = "CS6",
	[56] = "CS7",
	[10] = "AF11",
	[12] = "AF12",
	[14] = "AF13",
	[18] = "AF21",
	[20] = "AF22",
	[22] = "AF23",
	[26] = "AF31",
	[28] = "AF32",
	[30] = "AF33",
	[34] = "AF41",
	[36] = "AF42",
	[38] = "AF43",
	[46] = "EF",
	[44] = "VOICEADMIT",
}

local ecn_type_map =
{
	[0] = "Not ECT",
	[1] = "ECT(1)",
	[2] = "ECT(0)",
	[3] = "CE",
}

-- TLV Dissectors


-- TLV Dissectors: DSCP ECN
local dscp_ecn_tlv_protofield = ProtoField.bytes("stamp.tlv.dscp_ecn", "DSCP ECN TLV")
local dscp1_dscp_ecn_tlv_protofield = ProtoField.uint8("stamp.tlv.dscp_ecn.dscp1", "DSCP1", base.HEX, dscp_type_map, 0xfc,
	"DSCP1 Field")
local ecn1_dscp_ecn_tlv_protofield = ProtoField.uint8("stamp.tlv.dscp_ecn.ecn1", "ECN1", base.HEX, ecn_type_map, 0x03,
	"ECN1 Field")
local dscp2_dscp_ecn_tlv_protofield = ProtoField.uint8("stamp.tlv.dscp_ecn.dscp2", "DSCP2", base.HEX, dscp_type_map, 0xfc,
	"DSCP2 Field")
local ecn2_dscp_ecn_tlv_protofield = ProtoField.uint8("stamp.tlv.dscp_ecn.ecn2", "ECN2", base.HEX, ecn_type_map, 0x03,
	"ECN2 Field")
local rp_dscp_ecn_tlv_protofield = ProtoField.bool("stamp.tlv.dscp_ecn.rp", "RP", 8,
	{ [1] = "Forward Path", [2] = "Forward and Reverse Path" }, 0x01,
	"Reverse Path")

stamp_protocol.fields = { dscp_ecn_tlv_protofield,
	dscp1_dscp_ecn_tlv_protofield,
	ecn1_dscp_ecn_tlv_protofield,
	dscp2_dscp_ecn_tlv_protofield,
	ecn2_dscp_ecn_tlv_protofield,
	rp_dscp_ecn_tlv_protofield,
}

------
--- Dissect the DSCP/ECN TLV.
-- Dissect the contents of a [DSCP/ECN TLV](https://www.ietf.org/archive/id/draft-white-ippm-stamp-ecn-00.html).
-- @tparam Tvb buffer Bytes that constitute the TLV to be dissected
-- @tparam TreeItem tree The tree under which to append this dissected TLV
-- @treturn bool true or false depending upon whether the bytes given in `buffer` are a valid DSCP/ECN TLV.
local function tlv_dscp_ecn_dissector(buffer, tree)
	if buffer:len() < 4 then
		return false
	end

	local dscp_ecn_tree = tree:add(dscp_ecn_tlv_protofield, buffer(0))
	dscp_ecn_tree.text = "DSCP ECN TLV"
	dscp_ecn_tree:add(dscp1_dscp_ecn_tlv_protofield, buffer(0, 1))
	dscp_ecn_tree:add(ecn1_dscp_ecn_tlv_protofield, buffer(0, 1))
	dscp_ecn_tree:add(dscp2_dscp_ecn_tlv_protofield, buffer(1, 1))
	dscp_ecn_tree:add(ecn2_dscp_ecn_tlv_protofield, buffer(1, 1))
	dscp_ecn_tree:add(rp_dscp_ecn_tlv_protofield, buffer(1, 1))
	return true
end

-- TLV Dissectors: COS

local cos_tlv_protofield = ProtoField.bytes("stamp.tlv.cos", "DSCP ECN TLV")
local dscp1_cos_tlv_protofield = ProtoField.uint16("stamp.tlv.cos.dscp1", "DSCP1", base.HEX, dscp_type_map, 0xfc00,
	"DSCP1 Field")
local dscp2_cos_tlv_protofield = ProtoField.uint16("stamp.tlv.cos.dscp2", "DSCP2", base.HEX, dscp_type_map, 0x03f0,
	"DSCP2 Field")
local ecn_cos_tlv_protofield = ProtoField.uint16("stamp.tlv.cos.ecn", "ECN", base.HEX, ecn_type_map, 0x000c,
	"ECN Field")
local rp_cos_tlv_protofield = ProtoField.bool("stamp.tlv.cos.rp", "RP", 16,
	{ [1] = "Forward Path", [2] = "Forward and Reverse Path" }, 0x01,
	"Reverse Path")

stamp_protocol.fields = { cos_tlv_protofield,
	dscp1_cos_tlv_protofield,
	dscp2_cos_tlv_protofield,
	ecn_cos_tlv_protofield,
	rp_cos_tlv_protofield,
}

------
--- Dissect the Class Of Service TLV.
-- Dissect the contents of a [Class of Service TLV](https://datatracker.ietf.org/doc/html/rfc8972#name-class-of-service-tlv).
-- @tparam Tvb buffer Bytes that constitute the TLV to be dissected
-- @tparam TreeItem tree The tree under which to append this dissected TLV
-- @treturn bool true or false depending upon whether the bytes given in `buffer` are a valid Class of Service TLV.
local function tlv_cos_dissector(buffer, tree)
	if buffer:len() < 4 then
		return false
	end

	local cos_tree = tree:add(cos_tlv_protofield, buffer(0))
	cos_tree.text = "Class of Service"
	cos_tree:add(dscp1_cos_tlv_protofield, buffer(0, 2))
	cos_tree:add(dscp2_cos_tlv_protofield, buffer(0, 2))
	cos_tree:add(ecn_cos_tlv_protofield, buffer(0, 2))
	cos_tree:add(rp_cos_tlv_protofield, buffer(0, 2))
	return true
end

-- TLV Dissectors: Padding

local padding_tlv_protofield = ProtoField.bytes("stamp.tlv.padding", "Padding TLV")
local padding_padding_tlv_protofield = ProtoField.bytes("stamp.tlv.padding.padding", "Padding")

stamp_protocol.fields = { padding_tlv_protofield, padding_padding_tlv_protofield }

------
--- Dissect the Padding TLV.
-- Dissect the contents of a [Padding TLV](https://datatracker.ietf.org/doc/html/rfc8972#name-extra-padding-tlv).
-- @tparam Tvb buffer Bytes that constitute the TLV to be dissected
-- @tparam TreeItem tree The tree under which to append this dissected TLV
-- @treturn bool true or false depending upon whether the bytes given in `buffer` are a valid Padding TLV.
local function tlv_padding_dissector(buffer, tree)
	local padding_tree = tree:add(cos_tlv_protofield, buffer(0))
	padding_tree.text = "Padding"
	padding_tree:add(padding_padding_tlv_protofield, buffer(0))
	return true
end

-- TLV Dissectors: Followup

local stamp_timestamping_methods =
{
	[0] = "Reserved",
	[1] = "HW Assist",
	[2] = "SW Local",
	[3] = "Control Plane",
}

-- Followup Timestamp
local ts_followup_tlv_protofield = ProtoField.none("stamp.tlv.followup.timestamp", "Timestamp", base.HEX)
local ts_followup_tlv_seconds_protofield = ProtoField.uint32("stamp.tlv.followup.timestamp", "Seconds", base.DEC)
local ts_followup_tlv_fractions_protofield = ProtoField.uint32("stamp.tlv.followup.fractions", "Fractions", base.DEC)

timestamp_fields["stamp.tlv.followup.timestamp"] = {
	[""] = ts_followup_tlv_protofield,
	["seconds"] = ts_followup_tlv_seconds_protofield,
	["fractions"] = ts_followup_tlv_fractions_protofield,
}

local followup_tlv_protofield = ProtoField.bytes("stamp.tlv.followup", "Followup TLV")
local followup_sequence_no_protofield = ProtoField.bytes("stamp.tlv.followup.sequence_no", "Sequence Number")
local followup_timestamp_source_protofield = ProtoField.uint8("stamp.tlv.followup.timestamp_source", "Timestamp Source", base.HEX, stamp_timestamping_methods)

stamp_protocol.fields = { followup_tlv_protofield, followup_sequence_no_protofield, ts_followup_tlv_protofield,
	ts_followup_tlv_seconds_protofield, ts_followup_tlv_fractions_protofield,
	followup_timestamp_source_protofield }

------
--- Dissect the Followup TLV.
-- Dissect the contents of a [Followup TLV](https://datatracker.ietf.org/doc/html/rfc8972#name-follow-up-telemetry-tlv).
-- @tparam Tvb buffer Bytes that constitute the TLV to be dissected
-- @tparam TreeItem tree The tree under which to append this dissected TLV
-- @treturn bool true or false depending upon whether the bytes given in `buffer` are a valid Followup TLV.
local function tlv_followup_dissector(buffer, tree)
	if buffer:len() < 16 then
		return false
	end

	local followup_tree = tree:add(followup_tlv_protofield, buffer(0))
	followup_tree.text = "Follow Up"

	followup_tree:add(followup_sequence_no_protofield, buffer(0, sequence_field_size))

	local next_field_start = sequence_field_size
	next_field_start = next_field_start +
		dissect_timestamp(buffer(next_field_start), "stamp.tlv.followup.timestamp", "Timestamp", false, followup_tree)
	followup_tree:add(followup_timestamp_source_protofield, buffer(next_field_start, 1))
	next_field_start = next_field_start + 1

	return true
end


local tlv_type_map = { [0xb3] = "DSCP ECN", [0x1] = "Padding", [0x4] = "Class of Service", [0x7] = "Followup" }
local tlv_dissector_map = { [0xb3] = tlv_dscp_ecn_dissector, [0x1] = tlv_padding_dissector, [0x04] = tlv_cos_dissector,
	[0x7] = tlv_followup_dissector }

-- TLV General
local tlv_protofield = ProtoField.bytes("stamp.tlv", "TLV")
local u_flags_tlv_protofield = ProtoField.bool("stamp.tlv.flags.u", "U", 8, { [1] = "Unrecognized", [2] = "Recognized" },
	0x80,
	"Description")
local m_flags_tlv_protofield = ProtoField.bool("stamp.tlv.flags.m", "M", 8, { [1] = "Malformed", [2] = "Well formed" },
	0x40,
	"Description")
local i_flags_tlv_protofield = ProtoField.bool("stamp.tlv.flags.i", "I", 8,
	{ [1] = "Integrity - OK", [2] = "Integrity - Failed" }, 0x20,
	"Description")
local type_tlv_protofield = ProtoField.uint8("stamp.tlv.type", "Type", base.HEX, tlv_type_map, "Type")
local length_tlv_protofield = ProtoField.uint16("stamp.tlv.length", "Length", base.UNIT_STRING, { "" }, "Length")

stamp_protocol.fields = {
	tlv_protofield,
	u_flags_tlv_protofield,
	i_flags_tlv_protofield,
	m_flags_tlv_protofield,
	type_tlv_protofield,
	length_tlv_protofield,
}
stamp_protocol.fields = {}

------
--- Determine whether all the bytes in a `Tvb` are 0.
-- @tparam Tvb buffer Bytes to scan.
-- @treturn bool true or false depending upon whether all the bytes in `buffer` are `0`.
local function all_zeros(buffer)
	for i = 0, buffer:len() - 1 do
		if buffer:get_index(i) ~= 0 then
			return false
		end
	end
	return true
end

------
--- Determine whether the bytes in `buffer` constitute an authenticated STAMP packet.
-- @tparam Tvb buffer Bytes to scan.
-- @treturn bool true or false depending upon whether the bytes in `buffer` represent an authenticated STAMP packet.
local function authenticated_packet(buffer)
	-- the 12 bytes after the 4th should be 0 for an
	-- authenticated packet.
	local mbz_authenticated = buffer:bytes(4, 12)
	return all_zeros(mbz_authenticated)
end

--- Determine whether the bytes in `buffer` constitute a session-sender STAMP packet.
-- @tparam Tvb buffer Bytes to scan.
-- @tparam bool authenticated Whether the session-sender STAMP packet is authenticated.
-- @treturn bool true or false depending upon whether the bytes in `buffer` represent a session-sender STAMP packet.
local function sender_packet(buffer, authenticated)
	if authenticated then
		return all_zeros(buffer:bytes(28, 68))
	end
	return all_zeros(buffer:bytes(16, 28))
end

--- Dissect an HMAC
-- @tparam Tvb buffer Bytes containing the raw contents of the HMAC.
-- @tparam TreeItem tree The tree on which to attach the dissected HMAC.
-- @treturn int The size of the HMAC field.
local function dissect_hmac(buffer, tree)
	if buffer:len() < 16 then
		tree:add(buffer, "Error")
		return 0
	end
	tree:add(hmac_protofield, buffer(0, hmac_field_size))
	return hmac_field_size
end

--- Dissect an SSID
-- @tparam Tvb buffer Bytes containing the raw contents of the SSID.
-- @tparam TreeItem tree The tree on which to attach the dissected SSID.
-- @treturn int The size of the SSID field.
local function dissect_ssid(buffer, tree)
	if buffer:len() < ssid_field_size then
		tree:add(buffer, "Error")
		return false
	end
	tree:add(ssid_protofield, buffer(0, ssid_field_size))
	return 2
end

--- Convert between a TLV's type and its name
-- @tparam int type TLV type identifier.
-- @treturn string The name of the TLV identified by `type`.
local function tlv_type_to_name(type)
	local type_name = tlv_type_map[type]

	if type_name == nil then
		return "Unknown"
	end
	return type_name
end

--- Dissect a TLV.
-- @tparam Tvb buffer Bytes containing the raw contents of the timestamp and (optionally) error estimate.
-- @tparam TreeItem tree The tree on which to attach the dissected TLV.
-- @treturn int The size of the dissected TLV (including type and length fields).
local function dissect_tlv(buffer, tree)
	if buffer:len() < 4 then
		tree:add(buffer, "Error")
	end

	local tlv_length = buffer(2, 2):uint()
	local tlv_type = buffer(1, 1):uint()
	local tlv_tree = tree:add(tlv_protofield, buffer(0, tlv_length + 4))
	tlv_tree.text = "TLV: " .. tlv_type_to_name(tlv_type)
	tlv_tree:add(u_flags_tlv_protofield, buffer(0, 1))
	tlv_tree:add(m_flags_tlv_protofield, buffer(0, 1))
	tlv_tree:add(i_flags_tlv_protofield, buffer(0, 1))
	tlv_tree:add(type_tlv_protofield, buffer(1, 1))
	tlv_tree:add(length_tlv_protofield, buffer(2, 2))

	local handler = tlv_dissector_map[tlv_type]

	if handler ~= nil then
		handler(buffer(4, tlv_length), tlv_tree)
	end

	return tlv_length + 4
end


--- Dissect the body of a STAMP test packet sent from a session reflector.
-- Because the sequence number and timestamp/error estimate (and optionally MBZ) fields
-- are common to test packets from a session sender and reflector, those are dissected earlier.
-- @tparam Tvb buffer Bytes containing the raw contents of a packet sent by the session reflector.
-- @tparam bool authenticated Whether the session-sender STAMP packet is authenticated.
-- @tparam TreeItem tree The tree on which to attach the dissected reflector body.
-- @treturn int The size of the dissected STAMP test packet sent from a session reflector.
local function dissect_reflected_body(buffer, authenticated, tree)
	local next_field_start = 0
	next_field_start = next_field_start +
		dissect_timestamp(buffer(next_field_start, timestamp_field_size), "stamp.received_timestamp",
			"Received Timestamp", false, tree)
	if authenticated then
		next_field_start = next_field_start + reflected_authenticated_mbz3_size
	end

	tree:add(sender_sequence_protofield, buffer(next_field_start, sequence_field_size))
	next_field_start = next_field_start + sequence_field_size
	if authenticated then
		next_field_start = next_field_start + reflected_authenticated_mbz4_size
	end

	next_field_start = next_field_start +
		dissect_timestamp(buffer(next_field_start, (timestamp_field_size + error_estimate_field_size)),
			"stamp.sender_timestamp", "Sender Timestamp", true, tree)
	if authenticated then
		next_field_start = next_field_start + reflected_authenticated_mbz5_size
	else
		next_field_start = next_field_start + 2
	end

	tree:add(sender_ttl_protofield, buffer(next_field_start, 1))
	next_field_start = next_field_start + 1

	if authenticated then
		next_field_start = next_field_start + reflected_authenticated_mbz6_size
	else
		next_field_start = next_field_start + 3
	end
	return next_field_start
end

function stamp_protocol.dissector(buffer, pinfo, tree)
	local raw_packet_length = buffer:len()
	if raw_packet_length == 0 then return end

	if raw_packet_length < 44 then
		tree:add(buffer, "Packet too small")
		return
	end

	pinfo.cols.protocol = stamp_protocol.name

	local is_authenticated = authenticated_packet(buffer)
	local is_sender = sender_packet(buffer, is_authenticated)

	-- Calculate the header.
	local stamp_header = "STAMP"
	if is_sender then
		stamp_header = stamp_header .. " Session-Sender"
	else
		stamp_header = stamp_header .. " Session-Reflector"
	end

	if is_authenticated then
		stamp_header = stamp_header .. " Authenticated"
	end
	stamp_header = stamp_header .. " Packet"

	local subtree = tree:add(stamp_protocol, buffer(), stamp_header)

	local next_field_start = 0
	subtree:add(sequence_protofield, buffer(next_field_start, sequence_field_size))
	next_field_start = next_field_start + sequence_field_size

	if is_authenticated then
		next_field_start = next_field_start + reflected_authenticated_mbz1_size
	end

	next_field_start = next_field_start +
		dissect_timestamp(buffer(next_field_start), "stamp.timestamp", "Timestamp", true, subtree)
	next_field_start = next_field_start + dissect_ssid(buffer(next_field_start), subtree)

	if is_sender then -- a packet from a STAMP session sender.
		local extent = session_sender_base_length
		if is_authenticated then
			extent = session_sender_authenticated_base_length
		end
		subtree:add(buffer(next_field_start, extent), "Sender (MBZ)")
		next_field_start = next_field_start + extent
	else -- a packet from a STAMP session reflector.
		if is_authenticated then
			next_field_start = next_field_start + reflected_authenticated_mbz2_size
		end
		local reflector_body = subtree:add(buffer(next_field_start), "Reflector")
		next_field_start = next_field_start +
			dissect_reflected_body(buffer(next_field_start), is_authenticated, reflector_body)
	end

	if is_authenticated then
		next_field_start = next_field_start + dissect_hmac(buffer(next_field_start), subtree)
	end

	-- As long as there are more bytes in the packet, try to parse TLVs!
	while next_field_start < buffer:len() do
		next_field_start = next_field_start + dissect_tlv(buffer(next_field_start), subtree)
	end
end

-- Now, register what we have with wireshark!
local udp_port = DissectorTable.get("udp.port")
udp_port:add(862, stamp_protocol)
