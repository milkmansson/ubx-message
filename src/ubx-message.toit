// Copyright (C) 2025 Toit contributors.
// Use of this source code is governed by a MIT-style license that can be found
// in the LICENSE file.

/**
Support for the UBX messages from the UBX data protocol.

The UBX data protocol is used by the ublox GNSS receivers in the Max-M*
  series. Some messages are deprecated between versions.

The description for each receiver describes the supported UBX message.
- Max-M8: https://www.u-blox.com/en/docs/UBX-13003221
- Max-M9: https://www.u-blox.com/en/docs/UBX-19035940
*/

/*
To do list:
- MGA-* (AssistNow) messages: Assisted GNSS injection (time, eph/almanac) for
  fast TTFF.  A path for MGA-INI-TIME_UTC at minimum.
- ESF-* for combination with DR/ADR/IMU fusion.
- CFG-TP5: Complete so setters and getters match, and avoid PROTVER15-16
  differences.
*/

import io
import io show LITTLE-ENDIAN
import io show BIG-ENDIAN
import reader as old-reader

/**
A UBX message from the UBX data protocol.
*/
class Message:
  /** Maximum size of an encoded message. */
  /*
  The protocol allows length up to 65535 (2-byte field), though most real
    messages are far smaller. 2 KB is sensible safety cap, but some messages
    (for example, MGA assistance blocks, large MON dumps) can exceed that on
    newer firmware.  May need to set this differently later, possibly 8K/16K.
  */
  static MAX-MESSAGE-SIZE_ ::= 2048

  /** The Navigation result (NAV) class byte. */
  static NAV ::= 0x01
  /** The Receiver Manager (RXM) class byte. */
  static RXM ::= 0x02
  /** The Information (INF) class byte. */
  static INF ::= 0x04
  /** The ack/nak (ACK) class byte. */
  static ACK ::= 0x05
  /** The Configuration Input (CFG) class byte. */
  static CFG ::= 0x06
  /** The Firmware Update (UPD) class byte. */
  static UPD ::= 0x09
  /** The Monitoring (MON) class byte. */
  static MON ::= 0x0A
  /** The AssistNow Aiding (AID) class byte. */
  static AID ::= 0x0B
  /** The Time (TIM) class byte. */
  static TIM ::= 0x0D
  /** The External Sensor Fusion class byte. */
  static ESF ::= 0x10
  /** The Multiple GNSS Assistance (MGA) class byte.*/
  static MGA ::= 0x13
  /** The Logging (LOG) class byte. */
  static LOG ::= 0x21
  /** The Security Feature (SEC) class byte. */
  static SEC ::= 0x27
  /** The High-Rate Navigation Result (HNR) class byte. */
  static HNR ::= 0x28

  /**
  Map from class byte to its string representation.
  */
  static PACK-CLASSES ::= {
    NAV: "NAV",
    RXM: "RXM",
    INF: "INF",
    ACK: "ACK",
    CFG: "CFG",
    UPD: "UPD",
    MON: "MON",
    AID: "AID",
    TIM: "TIM",
    ESF: "ESF",
    MGA: "MGA",
    LOG: "LOG",
    SEC: "SEC",
    HNR: "HNR"}

  /**
  Map from Message byte/type to its string representation.

  Not all messages are handled in this driver, however all message ID's found in
    6M and M8 manuals have been added.  This is to help where an information
    message presents itself that may not yet be implemented.  Implemented as
    nested Maps.
  */
  static PACK-MESSAGE-TYPES := {
    // NAV (0x01).
    NAV: {
      0x01: "POSECEF",
      0x02: "POSLLH",
      0x03: "STATUS",
      0x04: "DOP",
      0x05: "ATT",        // M8+.
      0x06: "SOL",
      0x07: "PVT",        // M8+.
      0x09: "ODO",        // M8+.
      0x10: "RESETODO",   // M8+.
      0x11: "VELECEF",
      0x12: "VELNED",
      0x13: "HPPOSECEF",  // M8+.
      0x14: "HPPOSLLH",   // M8+.
      0x20: "TIMEGPS",
      0x21: "TIMEUTC",
      0x23: "TIMEGLO",    // M8+.
      0x24: "TIMEBDS",    // M8+.
      0x25: "TIMEGAL",    // M8+.
      0x26: "TIMELS",     // M8+.
      0x28: "NMI",        // M8+.
      0x30: "SVINFO",
      0x31: "DGPS",
      0x32: "SBAS",
      0x35: "SAT",        // M8+.
      0x39: "GEOFENCE",   // M8+.
      0x3B: "SVIN",       // M8+.
      0x3C: "RELPOSNED",  // M8+.
      0x3D: "EELL",       // M8+.
      0x42: "SLAS",       // M8+.
      0x60: "AOPSTATUS",
      0x61: "EOE",        // M8+.
    },

    // RXM (0x02).
    RXM: {
      0x10: "RAW",     // 6-series.
      0x11: "SFRB",    // 6-series.
      0x13: "SFRBX",   // M8+.
      0x14: "MEASX",   // M8+.
      0x15: "RAWX",    // M8+.
      0x20: "SVSI",
      0x30: "ALM",
      0x31: "EPH",
      0x32: "RTCM",    // M8+.
      0x41: "PMREQ",
      0x59: "RLM",     // M8+.
      0x61: "IMES",    // M8+.
    },

    // ACK (0x05).
    ACK: {
      0x00: "ACK-NAK",
      0x01: "ACK-ACK",
    },

    // CFG (0x06).
    CFG: {
      0x00: "PRT",
      0x01: "MSG",
      0x02: "INF",
      0x04: "RST",
      0x06: "DAT",
      0x07: "TP",
      0x08: "RATE",
      0x09: "CFG",
      0x0E: "FXN",       // 6-series.
      0x11: "RXM",
      0x12: "EKF",       // 6-series LEA-6R.
      0x13: "ANT",
      0x16: "SBAS",
      0x17: "NMEA",
      0x1B: "USB",
      0x1D: "TMODE",     // 6-series.
      0x1E: "ODO",
      0x23: "NAVX5",
      0x24: "NAV5",
      0x29: "ESFGWT",    // 6-series (LEA-6R).
      0x31: "TP5",
      0x34: "RINV",
      0x39: "ITFM",
      0x3B: "PM2",
      0x3D: "TMODE2",
      0x3E: "GNSS",      // M8+.
      0x47: "LOGFILTER", // M8+.
      0x53: "TXSLOT",    // M8+.
      0x56: "ESFALG",    // M8+.
      0x57: "PWR",       // M8+.
      0x5C: "HNR",       // M8+.
      0x60: "ESRC",      // M8+.
      0x61: "DOSC",      // M8+.
      0x62: "SMGR",      // M8+.
      0x64: "SPT",       // M8+.
      0x69: "GEOFENCE",  // M8+.
      0x70: "DGNSS",     // M8+.
      0x71: "TMODE3",    // M8+.
      0x82: "ESFWT",     // M8+.
      0x86: "PMS",       // M8+.
      0x88: "SENIF",     // M8+.
      0x8D: "SLAS",      // M8+.
      0x93: "BATCH",     // M8+.

      0x8A: "VALSET",    // M8/9+.
      0x8B: "VALGET",    // M8/9+.
      0x8C: "VALDEL",    // M8/9+.
    },

    // MON (0x0A).
    MON: {
      0x02: "IO",
      0x04: "VER",
      0x06: "MSGPP",
      0x07: "RXBUF",
      0x08: "TXBUF",
      0x09: "HW",
      0x0B: "HW2",
      0x21: "RXR",
      0x27: "PATCH",     // M8+.
      0x28: "GNSS",      // M8+.
      0x2E: "SMGR",      // M8+.
      0x2F: "SPT",       // M8+.
      0x32: "BATCH",     // M8+.
    },

    // AID (0x0B) — legacy assistance (6 & M8).
    AID: {
      0x01: "INI",
      0x02: "HUI",
      0x30: "ALM",
      0x31: "EPH",
      0x33: "AOP",
      0x50: "ALP",   // 6-series.
      0x10: "DATA",  // 6-series.
      0x32: "ALPSRV" // 6-series.
    },

    // TIM (0x0D).
    TIM: {
      0x01: "TP",
      0x03: "TM2",
      0x04: "SVIN",
      0x06: "VRFY",    // 6-series.
      0x11: "DOSC",    // M8+.
      0x12: "TOS",     // M8+.
      0x13: "SMEAS",   // M8+.
      0x15: "VCOCAL",  // M8+.
      0x16: "FCHG",    // M8+.
      0x17: "HOC",     // M8+.
    },

    // ESF (0x10) — external sensor fusion.
    ESF: {
      0x02: "MEAS",  // 6-series LEA-6R / M8 ESF-MEAS (different payloads).
      0x03: "RAW",   // M8+.
      0x10: "STATUS",// 6-series LEA-6R / M8 ESF-STATUS.
      0x14: "ALG",   // M8+.
      0x15: "INS",   // M8+.
    },

    // MGA (0x13) — M8+ multi-GNSS assistance (index only; many subtypes).
    MGA: {
      0x00: "GPS",
      0x02: "GAL",
      0x03: "BDS",
      0x05: "QZSS",
      0x06: "GLO",
      0x20: "ANO",
      0x40: "INI",
      0x60: "ACK",
      0x80: "DBD",
    },

    // LOG (0x21) — M8+.
    LOG: {
      0x03: "ERASE",
      0x07: "CREATE",
      0x0B: "INFO",
      0x0D: "RETRIEVE",
      0x0E: "RETRIEVEPOS",
      0x0F: "RETRIEVESTRING",
      0x10: "FINDTIME",
      0x11: "BATCH",
    },

    // SEC (0x27) — M8+.
    SEC: {
      0x03: "SEC-UNIQID",
    },

    // HNR (0x28) — M8+.
    HNR: {
      0x00: "PVT",
      0x01: "ATT",
      0x02: "INS",
    },

  }

  // Fix type constants used through several messages.

  static INVALID-UBX-MESSAGE_ ::= "INVALID UBX MESSAGE"
  static RESERVED_ ::= 0

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /** The class of this message. */
  cls/int
  /** The ID of this message. */
  id/int
  /** The Payload of this message. */
  payload/ByteArray

  /** Constructs a UBX message with the given $cls, $id, and $payload. */
  constructor.private_ .cls .id .payload:

  /**
  Constructs a UBX message with the given $cls, $id, and $payload.

  If message is implemented in this package, then it returns the appropriate
    sub-class.
  */
  constructor cls id payload:
    if cls == Message.ACK:
      if id == AckAck.ID:
        return AckAck.private_ payload
      else if id == AckNak.ID:
        return AckNak.private_ payload

    if cls == Message.NAV:
      if id == NavPvt.ID:
        return NavPvt.private_ payload
      else if id == NavStatus.ID:
        return NavStatus.private_ payload
      else if id == NavSat.ID:
        return NavSat.private_ payload
      else if id == NavPosLlh.ID:
        return NavPosLlh.private_ payload
      else if id == NavSvInfo.ID:
        return NavSvInfo.private_ payload
      else if id == NavSol.ID:
        return NavSol.private_ payload
      else if id == NavTimeUtc.ID:
        return NavTimeUtc.private_ payload

    if cls == Message.MON:
      if id == MonVer.ID:
        return MonVer.private_ payload

    if cls == Message.CFG:
      if id == CfgPrt.ID:
        return CfgPrt.private_ payload
      if id == CfgTp5.ID:
        return CfgTp5.private_ payload
      if id == CfgNav5.ID:
        return CfgNav5.private_ payload
      if id == CfgGnss.ID:
        return CfgGnss.private_ payload
      if id == CfgGnss.ID:
        return CfgGnss.private_ payload
      if id == CfgValGet.ID:
        return CfgValGet.private_ payload
      if id == CfgValSet.ID:
        return CfgValSet.private_ payload
      if id == CfgValDel.ID:
        return CfgValDel.private_ payload

    return Message.private_ cls id payload

  /**
  Constructs a UBX message from the given $bytes.

  The $bytes must be a valid UBX message (contain the sync bytes and a valid
    checksum).
  */
  constructor.from-bytes bytes/ByteArray:
    if not is-valid-frame_ bytes: throw INVALID-UBX-MESSAGE_
    cls = bytes[2]
    id = bytes[3]
    length := LITTLE-ENDIAN.uint16 bytes 4
    if bytes.size != length + 8: throw INVALID-UBX-MESSAGE_
    payload = bytes[6 .. 6 + length]

  /**
  Constructs a UBX message from the given $reader.

  The $reader must be able to provide a valid UBX frame.

  If message is implemented in this package, then it returns the appropriate
    sub-class.

  The $reader should be an $io.Reader, but an $old-reader.Reader is also accepted
    for backwards compatibility. The use of $old-reader.Reader is deprecated and
    will be removed in a future release.
  */
  constructor.from-reader reader/old-reader.Reader:
    io-reader/io.Reader := reader is io.Reader ? reader as io.Reader : io.Reader.adapt reader

    if (io-reader.peek-byte 0) != 0xb5 or (io-reader.peek-byte 1) != 0x62: throw INVALID-UBX-MESSAGE_

    // Verify the length and get full the packet.
    length ::= (io-reader.peek-byte 4) | (((io-reader.peek-byte 5) & 0xff) << 8)
    if not 0 <= length <= MAX-MESSAGE-SIZE_: throw INVALID-UBX-MESSAGE_
    frame ::= io-reader.peek-bytes length + 8

    // Verify the checksum.
    if not is-valid-frame_ frame: throw INVALID-UBX-MESSAGE_

    msg-class ::= frame[2]
    msg-id    ::= frame[3]
    payload   ::= frame[6..length + 6]
    io-reader.skip length + 8
    return Message msg-class msg-id payload

  // Checks frame is valid - lets callers determine what to do if it fails.
  static is-valid-frame_ frame/ByteArray -> bool:
    // Check the sync bytes.
    if frame[0] != 0xb5 or frame[1] != 0x62: return false

    // Check the payload length.
    length ::= LITTLE-ENDIAN.uint16 frame 4
    if not 0 <= length <= MAX-MESSAGE-SIZE_: return false
    if frame.size != length + 8: return false

    ck-a ::= frame[frame.size - 2]
    ck-b ::= frame[frame.size - 1]

    compute-checksum_ frame: | a b |
      return ck-a == a and ck-b == b
    unreachable

  /**
  Computes the checksum of the given $bytes.

  Calls the $callback with the computed checksum values ck_a and ck_b as
    arguments.
  */
  static compute-checksum_ bytes/ByteArray [callback]:
    ck-a := 0
    ck-b := 0
    bytes = bytes[2..bytes.size - 2]
    bytes.size.repeat: | i |
      ck-a = (ck-a + bytes[i]) & 0xff
      ck-b = (ck-b + ck-a) & 0xff
    callback.call ck-a ck-b

  /**
  Transforms this message to a byte array that can be send to a ublox
    GNSS receiver.

  The byte array contains the starting magic bytes 0xB5 and 0x62 as well as
    the trailing checksum.
  */
  to-byte-array -> ByteArray:
    bytes := ByteArray 8 + payload.size
    bytes[0] = 0xB5
    bytes[1] = 0x62
    bytes[2] = cls
    bytes[3] = id
    LITTLE-ENDIAN.put-uint16 bytes 4 payload.size
    bytes.replace 6 payload
    compute-checksum_ bytes: | ck-a ck-b |
      bytes[bytes.size - 2] = ck-a
      bytes[bytes.size - 1] = ck-b
    return bytes

  class-string_ -> string:
    return PACK-CLASSES.get cls --if-absent=:
      return "0x$(%02x cls)"

  id-string_ -> string:
    if Message.PACK-MESSAGE-TYPES.contains cls and
        Message.PACK-MESSAGE-TYPES[cls].contains id:
      return Message.PACK-MESSAGE-TYPES[cls].get id
    return "0x$(%02x id)"

  /** See $super. */
  stringify -> string:
    return "UBX-$class-string_-$id-string_"

  /** Hash code for use as an identifier in a Map. */
  hash-code:
    return payload.hash-code ^ ((cls << 16) | id)

  /** Helper to return an int8 from payload index. */
  int8_ index --payload=payload -> int: return LITTLE-ENDIAN.int8 payload index

  /** Helper to return an uint8 from payload index. */
  uint8_ index --payload=payload -> int: return payload[index]

  /** Helper to return an int16 from payload index. */
  int16_ index --payload=payload -> int: return LITTLE-ENDIAN.int16 payload index

  /** Helper to return an uint16 from payload index. */
  uint16_ index --payload=payload -> int: return LITTLE-ENDIAN.uint16 payload index

  /** Helper to return an int32 from payload index. */
  int32_ index --payload=payload -> int: return LITTLE-ENDIAN.int32 payload index

  /** Helper to return an uint32 from payload index. */
  uint32_ index --payload=payload -> int: return LITTLE-ENDIAN.uint32 payload index


  /** Helper to insert an int8 into payload index. */
  put-int8_ index value --payload=payload -> none:
    LITTLE-ENDIAN.put-int8 payload index value

  /** Helper to insert an uint8 into payload index. */
  put-uint8_ index value --payload=payload -> none:
    payload[index] = value

  /** Helper to insert an int16 into payload index. */
  put-int16_ index value --payload=payload -> none:
    LITTLE-ENDIAN.put-int16 payload index value

  /** Helper to insert an uint16 into payload index. */
  put-uint16_ index value --payload=payload -> none:
    LITTLE-ENDIAN.put-uint16 payload index value

  /** Helper to insert an int32 into payload index. */
  put-int32_ index value --payload=payload -> none:
    LITTLE-ENDIAN.put-int32 payload index value

  /** Helper to insert an uint32 into payload index. */
  put-uint32_ index value --payload=payload -> none:
    LITTLE-ENDIAN.put-uint32 payload index value

  /** Helper to add a byte-array to the end of the payload. */
  /* Necessary because even though ByteArray is mutable, += does not mutate it. */
  append_ ba/ByteArray --payload=payload -> none:
    payload += ba

/**
The UBX-ACK-ACK message.

Contains the class ID and message ID of the acknowledged message.
*/
class AckAck extends Message:
  /** The UBX-ACK-ACK message ID. */
  static ID ::= 0x01

  /** Lowest protocol version with this message type. */
  static MIN-PROTVER ::= "12.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /** Constructs a dummy acknowledge message. */
  constructor.private_ cls id:
    super.private_ Message.ACK ID #[cls, id]

  /** Constructs a dummy acknowledge message. */
  constructor.private_ payload:
    super.private_ Message.ACK ID payload

  id-string_ -> string:
    return "ACK"

  /** The class ID of the acknowledged message. */
  class-id -> int:
    return uint8_ 0

  /** The class ID (converted to text) of the acknowledged message. */
  class-id-text -> string:
    return Message.PACK-CLASSES[class-id]

  /** The message ID of the acknowledged message. */
  message-id -> int:
    return uint8_ 1

  /** The message ID (converted to text, if known) of the acknowledged message. */
  message-id-text -> string:
    output := ""
    if Message.PACK-MESSAGE-TYPES.contains class-id:
      if Message.PACK-MESSAGE-TYPES[class-id].contains message-id:
        output = Message.PACK-MESSAGE-TYPES[class-id][message-id]
    return output

  /** See $super. */
  stringify -> string:
    return  "$(super.stringify): [$(class-id):$(class-id-text),$(message-id):$(message-id-text)]"

/**
The UBX-ACK-NAK message.

Contains the class ID and message ID of the NAK (not acknowledged) message.
*/
class AckNak extends Message:
  /** The UBX-ACK-NAK message ID. */
  static ID ::= 0x00

  /** Lowest protocol version with this message type. */
  static MIN-PROTVER ::= "12.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""


  /** Constructs a dummy NAK message. */
  constructor.private_ cls id:
    super.private_ Message.ACK ID #[cls, id]

  constructor.private_ bytearray/ByteArray:
    super.private_ Message.ACK ID bytearray

  id-string_ -> string:
    return "NAK"

  /** The class ID of the NAK message. */
  class-id -> int:
    return uint8_ 0

  /** The class ID (converted to text) of the negative-acknowledge message. */
  class-id-text -> string:
    return Message.PACK-CLASSES[class-id]

  /** The message ID of the NAK message. */
  message-id -> int:
    return uint8_ 1

  /** The message ID (converted to text, if known) of the acknowledged message. */
  message-id-text -> string:
    output := ""
    if Message.PACK-MESSAGE-TYPES.contains class-id and
        Message.PACK-MESSAGE-TYPES[class-id].contains message-id:
      output = Message.PACK-MESSAGE-TYPES[class-id][message-id]
    return output

  /** See $super. */
  stringify -> string:
    return  "$(super.stringify): [$(class-id):$(class-id-text),$(message-id):$(message-id-text)]"


/**
The UBX-CFG-MSG message.

Configures the rate at which messages are sent by the receiver.
*/
class CfgMsg extends Message:
  /** The UBX-CFG-MSG message ID. */
  static ID ::= 0x01

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /**
  Constructs a configuration message.

  When sent to the receiver, the message with the given $msg-class and
    $msg-id will be sent at the given $rate.
  */
  constructor.message-rate --msg-class --msg-id --rate:
    super.private_ Message.CFG ID #[msg-class, msg-id, rate]

  /** Poll the configuration. */
  constructor.poll --msg-class --msg-id:
    super.private_ Message.CFG ID #[msg-class, msg-id]

  /** Set per-port rates. */
  constructor.per-port --msg-class --msg-id --rates/ByteArray:
    assert: rates.size == 6
    super.private_ Message.CFG ID (#[msg-class, msg-id] + rates)

  id-string_ -> string:
    return "MSG"


/**
The UBX-CFG-PRT message.

Configures a port (most commonly UART1) for baud rate, framing, and protocol masks.
Also supports polling a port's current configuration.
*/
/*
Payload layout (legacy M8/M9):
  offset size  field
  0      1     portID
  1      1     reserved0
  2      2     txReady (ignored here)
  4      4     mode       (bitfield: data bits, parity, stop bits)
  8      4     baudRate   (uint32, e.g., 115200)
  12     2     inProtoMask  (bit0=UBX, bit1=NMEA, bit2=RTCM2, bit5=RTCM3...)
  14     2     outProtoMask (same bit layout)
  16     2     flags
  18     2     reserved1
Total payload length: 20 bytes
*/
class CfgPrt extends Message:
  /** The UBX-CFG-PRT message ID. */
  static ID ::= 0x00

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := "23.0"  // Manual says not after this version.

  // Common constants (see u-blox docs).
  static PORT-UART1 ::= 0x01
  static PORT-UART2 ::= 0x02

  // Todo: expose these on the constructor.
  // mode bitfield shortcut: 8 data bits, no parity, 1 stop (8N1).
  // (charLen=3 -> bits 6..7 = 0b11; parity=0 -> bits 9..11 = 0; nStop=1 -> bit 12 = 0).
  // u-blox ref value: 0x000008D0.
  static MODE-DATA-BITS-MASK_ := 0b00000000_01100000
  static MODE-PARITY-MASK_    := 0b00000111_00000000
  static MODE-STOP-BITS-MASK_ := 0b00011000_00000000

  // Common Mode Presets.
  static MODE-8N1 ::= 0x000008D0
  static MODE-7E1 ::= 0x00000080
  static MODE-8O2 :=  0x000000C0

  // Protocol mask bits (legacy).
  static PROTO-UBX   ::= 0b00000001
  static PROTO-NMEA  ::= 0b00000010
  static PROTO-RTCM2 ::= 0b00000100
  static PROTO-RTCM3 ::= 0b00100000

  /**
  Build a configuration to set a UART port.

  Defaults: UART1, 115200 baud, 8N1, UBX-only (in/out).  Explicit proto masks
    can be specified via --in-proto/--out-proto.
  */
  constructor.uart
      --port-id/int=PORT-UART1
      --baud/int=9600
      --mode/int=MODE-8N1
      --in-proto/int=PROTO-UBX
      --out-proto/int=PROTO-UBX
      --flags/int=0:
    super.private_ Message.CFG ID (ByteArray 20)

    // PortID, Reserved0, TxReady(2).
    put-uint8_ 0 port-id
    put-uint8_ 1 0
    put-uint16_ 2 0     // txReady off.

    // Mode (framing).
    put-uint32_ 4 mode

    // BaudRate.
    put-uint32_ 8 baud

    // In/out proto masks.
    put-uint16_ 12 in-proto
    put-uint16_ 14 out-proto

    // Flags, reserved1.
    put-uint16_ 16 flags
    put-uint16_ 18 0

  /**
  Poll the configuration for a given port.
  The poll payload is a single byte: $port-id, which must be one of
    $PORT-UART1, or $PORT-UART2.
  */
  constructor.poll --port-id/int=PORT-UART1:
    super.private_ Message.CFG ID #[port-id]

  /** Construct from an incoming payload. */
  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  id-string_ -> string:
    return "PRT"

  /**
  Ublox internal port ID.

  Depending on the device, there can be more than 1 UART, as well as DDC (I2C
    compatible) USB and SPI types.  See the ublox Integration Manual for all
    valid UART port IDs.
  */
  port-id -> int:
    return uint8_ 0

  mode -> int:
    return uint32_ 4

  baud-rate -> int:
    return uint32_ 8

  in-proto-mask -> int:
    return uint16_ 12

  out-proto-mask -> int:
    return uint16_ 14

  flags -> int:
    return uint16_ 16

/**
The UBX-CFG-RST message.

Resets the receiver.
*/
class CfgRst extends Message:
  /** The UBX-CFG-RST message ID. */
  static ID ::= 0x04

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /**
  Constructs a reset message.

  The default parameters are a controlled software reset with a cold start.
  See the description for other parameter options.
  */
  constructor --clear-sections=0xFFFF --reset-mode=2:
    super.private_ Message.CFG ID (ByteArray 4)
    put-uint16_ 0 clear-sections
    put-uint8_ 2 reset-mode
    put-uint8_ 3 Message.RESERVED_

  id-string_ -> string:
    return "RST"

/**
The UBX-NAV-STATUS message.

The receiver navigation status.
*/
class NavStatus extends Message:
  /** The UBX-NAV-STATUS message ID. */
  static ID ::= 0x03

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /** Unknown GNSS fix. */
  static NO-FIX ::= 0
  /** Dead reckoning only. */
  static DEAD-RECKONING-ONLY ::= 1
  /** 2D fix. */
  static FIX-2D ::= 2
  /** 3D fix. */
  static FIX-3D ::= 3
  /** GPS and dead reckoning. */
  static GPS-DEAD-FIX ::= 4
  /** Time only fix. */
  static TIME-ONLY ::= 5

  /** Constructs a message to poll for a UBX-NAV-STATUS message. */
  constructor.poll:
    super.private_ Message.NAV ID #[]

  /** Constructs a UBX-NAV-STATUS message from raw byte array. */
  constructor.private_ payload:
    super.private_ Message.NAV ID payload

  id-string_ -> string:
    return "STATUS"

  /** The GPS interval time of week of the navigation epoch. */
  itow -> int:
    return uint32_ 0

  /**
  The current fix type.

  One of $NO-FIX, $DEAD-RECKONING-ONLY, $FIX-2D, $FIX-3D, $GPS-DEAD-FIX, $TIME-ONLY.
  */
  gps-fix -> int:
    return uint8_ 4

  /**
  Navigation status flags.

  See receiver specification for details.
  */
  flags -> int:
    return uint8_ 5

  /**
  Fix status information.

  See receiver specification for details. bit[0] = 1 if differential corrections
    are available.  Bit[7..6] carries map matching status:

  ```
  00: none
  01: valid but not used, i.e. map matching data was received, but was too old
  10: valid and used, map matching data was applied
  11: valid and used, map matching data was applied. In case of sensor
      unavailability map matching data enables dead reckoning. This requires
      map matched latitude/longitude or heading data
  ```
  */
  fix-status -> int:
    return uint8_ 6

  /**
  Additional status information.

  See receiver specification for details.  Contains power-saving mode and
    spoofing detection information.  Requires PROTVER >= 18.00.
  */
  flags2 -> int:
    return uint8_ 7

  /**
  Time to first fix in milliseconds.

  Take care when deciding what to do with this value. It is not a live indicator
  of current signal quality, and the value is not kept up to date or changed
  when the fix is lost.  It is not a countdown timer for the next expected fix.
  It is simply a historical value about the most recent acquisition event.
  */
  time-to-first-fix -> int:
    return uint32_ 8

  /** Milliseconds since startup or reset. (msss) */
  ms-since-startup -> int:
    return uint32_ 12

/**
The UBX-NAV-SAT message.

Satellite information.
*/
class NavSat extends Message:
  /** The UBX-NAV-SAT message ID. */
  static ID ::= 0x35

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  constructor.private_ payload/ByteArray:
    super.private_ Message.NAV ID payload

  id-string_ -> string:
    return "SAT"

  /** The GPS interval time of week of the navigation epoch. */
  itow -> int:
    return uint32_ 0

  /** Message version. */
  version -> int:
    return uint8_ 4

  /** Number of satellites in the message. */
  num-svs -> int:
    return uint8_ 5

  /** Number of satellites in the message. */
  satellite-count -> int:
    return num-svs

  /**
  The satellite data in the package for the given $index.

  The $index must satisfy 0 <= $index < $num-svs.
  */
  satellite-data index -> SatelliteData:
    if not 0 <= index < num-svs: throw "INVALID ARGUMENT"
    return SatelliteData index payload --src-id=ID

/**
Satellite data for a single satellite.

Satellite data can be provided via UBX-NAV-SAT and/or UBX-NAV-SVINFO messages
  (See $NavSat and $NavSvInfo).  This class is a container for satellite
  properties.  (Satellites are referred to in documentation as 'Space Vehicles'
  or 'SV', and the terms are used interchangably.)  It stores/parses properties
  common to both UBX-NAV-SVINFO and UBX-NAV-SAT message types.  Messages are
  approximately the same length in both cases, but have different information
  and layout depending on which message was the source.
*/
class SatelliteData:
  /**
  The source of this Satellite entry.

  Content and format of fields like $flags depend on the message source.
  */
  source/int

  /** The index of this data in the original message. */
  index/int

  /** GNSS identifier. */
  gnss-id/int := 0

  /** GNSS identifier. (Legacy: same field as GNSS identifier.)*/
  channel/int := 0

  /** Satellite identifier. */
  sv-id/int

  /** Carrier to noise ratio. */
  cno/int

  /** Elevation. */
  elev/int

  /** Azimuth. */
  azim/int

  /** Pseudorange residual. */
  pr-res/float

  /**
  Space Vehicle health indicator.

  For compatibility: 0=unknown; 1=healthy; 2=unhealthy.  UBX-NAV-SVINFO would
  normally have 0=healthy and 1=unhealthy, but these values have been shifted to
  match results from UBX-NAV-SAT.
  */
  health/int

  /**
  Flags.

  Includes $quality, $orbit-source, $alm-avail, and $ano-avail.  See
    receiver specification for details.
  */
  flags/int

  /**
  Signal quality indicator.

  ```
  Signal quality values:
  - 0: no signal
  - 1: searching signal
  - 2: signal acquired
  - 3: signal detected but unusable
  - 4: code locked and time synchronized
  - 5, 6, 7: code and carrier locked and time synchronized

  Note: Since IMES signals are not time synchronized, a channel tracking an IMES
    signal can never reach a quality indicator value of higher than 3.
  ```
  */
  quality/int

  /**
  Orbit source.

  ```
  Field Definitions (M8)
  - 0: no orbit information is available for this SV
  - 1: ephemeris is used
  - 2: almanac is used
  - 3: AssistNow Offline orbit is used
  - 4: AssistNow Autonomous orbit is used
  - 5, 6, 7: other orbit information is used
  ```
  */
  orbit-source/int

  /**
  Whether orbit information available.

  In 6M, this is true/false. In M8, this is true/false, plus information in the
    other fields about which variants are available.
  */
  orbit-info-avail/bool

  /** Almanac available for this satellite. */
  alm-avail/int := 0

  /** Ephemeris available for this satellite. */
  eph-avail/int := 0

  /** AssistNow Offline data is available for this SV */
  ano-avail/int := 0

  /** AssistNow Autonomous data is available for this SV. */
  aop-avail/int := 0

  /** Differential Correction Data is available for this satellite. */
  diff-corr/bool

  /** Differential Correction Data is available for this satellite. */
  sv-used/bool

  /** Indicates that a carrier smoothed pseudorange used. */
  smoothed/bool

  /**
  Constructs the satellite data for the given message $payload and data.
    Parses entire UBX-NAV-SAT and UBX-NAV-SVINFO sourced Space Vehicles.
  */
  constructor .index payload/ByteArray --src-id/int:

    source = src-id

    // Defaults defined here to help keep them visible.
    orbit-info-avail = false
    health = 0
    diff-corr = false
    sv-used = false
    orbit-source = 0
    offset := 0

    if src-id == NavSat.ID:
      quality-mask        := 0b00000000_00000111
      sv-used-mask        := 0b00000000_00001000
      health-mask         := 0b00000000_00110000
      diff-corr-mask      := 0b00000000_01000000
      smoothed-mask       := 0b00000000_10000000
      orbit-source-mask   := 0b00000111_00000000
      eph-avail-mask      := 0b00001000_00000000
      alm-avail-mask      := 0b00010000_00000000
      ano-avail-mask      := 0b00100000_00000000
      aop-avail-mask      := 0b01000000_00000000

      offset = index * 12
      gnss-id = LITTLE-ENDIAN.uint8 payload (offset + 8)
      sv-id = LITTLE-ENDIAN.uint8 payload (offset + 9)
      cno = LITTLE-ENDIAN.uint8 payload (offset + 10)
      elev = LITTLE-ENDIAN.int8 payload (offset + 11)
      azim = LITTLE-ENDIAN.int16 payload (offset + 12)
      pr-res = (LITTLE-ENDIAN.int16 payload (offset + 14)) / 10.0 // Scale 0.1.
      flags = LITTLE-ENDIAN.uint32 payload (offset + 16)

      quality      = (flags & quality-mask) >> quality-mask.count-trailing-zeros
      health       = (flags & health-mask) >> health-mask.count-trailing-zeros
      orbit-source = (flags & orbit-source-mask) >> orbit-source-mask.count-trailing-zeros
      alm-avail    = (flags & alm-avail-mask) >> alm-avail-mask.count-trailing-zeros
      eph-avail    = (flags & eph-avail-mask) >> eph-avail-mask.count-trailing-zeros
      ano-avail    = (flags & ano-avail-mask) >> ano-avail-mask.count-trailing-zeros
      aop-avail    = (flags & alm-avail-mask) >> alm-avail-mask.count-trailing-zeros
      diff-corr    = ((flags & diff-corr-mask) >> diff-corr-mask.count-trailing-zeros) != 0
      sv-used      = ((flags & sv-used-mask) >> sv-used-mask.count-trailing-zeros) != 0
      smoothed     = ((flags & smoothed-mask) >> smoothed-mask.count-trailing-zeros) != 0

      orbit-info-avail = (eph-avail != 0) or (alm-avail != 0) or (ano-avail != 0) or (aop-avail != 0)

    else if src-id == NavSvInfo.ID:
      // For quality register.
      quality-mask     := 0b00001111

      // For flags bitfield.
      sv-used-mask     := 0b00000001
      diff-corr-mask   := 0b00000010
      orbit-avail-mask := 0b00000100
      orbit-eph-mask   := 0b00001000
      unhealthy-mask   := 0b00010000
      orbit-alm-mask   := 0b00100000
      orbit-aop-mask   := 0b01000000
      smoothed-mask    := 0b10000000

      offset = index * 12
      channel = LITTLE-ENDIAN.uint8 payload (offset + 8)
      sv-id = LITTLE-ENDIAN.uint8 payload (offset + 9)
      flags = LITTLE-ENDIAN.uint8 payload (offset + 10)
      quality = (LITTLE-ENDIAN.uint8 payload (offset + 11)) & quality-mask
      cno = LITTLE-ENDIAN.uint8 payload (offset + 12)
      elev = LITTLE-ENDIAN.int8 payload (offset + 13)
      azim = LITTLE-ENDIAN.int16 payload (offset + 14)
      pr-res = (LITTLE-ENDIAN.int32 payload (offset + 16)).to-float / 100 // Scaled in cm.

      // Directly usable
      diff-corr        = ((flags & diff-corr-mask) >> diff-corr-mask.count-trailing-zeros) != 0
      sv-used          = ((flags & sv-used-mask) >> sv-used-mask.count-trailing-zeros) != 0
      orbit-info-avail = ((flags & orbit-avail-mask) >> orbit-avail-mask.count-trailing-zeros) != 0
      smoothed         = ((flags & smoothed-mask) >> smoothed-mask.count-trailing-zeros) != 0

      // In the case of NavSvInfo messages, there are only two possible statuses.
      // In the case of NavSat, there are 3 possibilities. This binary output is
      // moved (+1) to convert its outputs to match NavSat definitions.
      unhealthy-raw  := (flags & unhealthy-mask) >> unhealthy-mask.count-trailing-zeros
      health = unhealthy-raw + 1

      // Translated to return outputs as close to the M8 definition as possible
      if ((flags & orbit-eph-mask) >> orbit-eph-mask.count-trailing-zeros) == 1:
        orbit-source = 1
      else if ((flags & orbit-alm-mask) >> orbit-alm-mask.count-trailing-zeros) == 1:
        orbit-source = 2
      else if ((flags & orbit-aop-mask) >> orbit-aop-mask.count-trailing-zeros) == 1:
        orbit-source = 4

    else:
      throw "Unknown Space Vehicle Definition Source"

  /** See $super. */
  stringify -> string:
    codes := ""      //gnss-id = LITTLE-ENDIAN.uint8 payload (offset + 8)

    if alm-avail == 1: codes += "A"
    if ano-avail == 1: codes += "N"

    // TODO(kasper): Make this output a whole lot prettier and easier to parse.
    //          ian: Added class/id type string from $super to assist with
    //               tests.  Would be cool to standardise them somehow...?
    return "$(super.stringify): $index|$gnss-id|$sv-id|$cno|$quality|$orbit-source|$codes"

/**
The UBX-MON-VER message.

Handles receiver/software/hardware version information.
*/
class MonVer extends Message:
  /** The UBX-MON-VER message ID. */
  static ID ::= 0x04

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /** Construct a poll-request UBX-MON-VER. */
  constructor.poll:
    super.private_ Message.MON ID #[]

  /** Construct from an incoming payload. */
  constructor.private_ payload/ByteArray:
    super.private_ Message.MON ID payload

  /** See $super. */
  id-string_ -> string:
    return "VER"

  /** Software version string. */
  // Null terminated with fixed field size of 30 bytes.
  sw-version -> string:
    return convert-string_ 0 30

  /** Hardware version string. */
  // Null terminated with fixed field size of 10 bytes.
  hw-version -> string:
    return convert-string_ 30 10

  /** Whether an extension row exists containing string $str. */
  has-extension str/string -> bool:
    return extensions-raw.any: it.contains str

  /**
  The entire line of the extension with the given $str.

  Null if this message doesn't have the extension (see $has-extension).
  */
  extension str/string -> string?:
    extensions-raw.do:
      if it.contains str: return it
    return null

  /**
  A list of extension strings.

  If provided by the firmware version on the device, this function obtains its
    list of 30 byte entries, converted to strings.
  */
  extensions-raw -> List:
    raw-extensions := []
    offset := 40
    eq-pos := ?
    while offset + 30 <= payload.size:
      raw-extensions.add (convert-string_ offset 30)
      offset += 30
    return raw-extensions


  /** Helper: read a '\0'-terminated string from a fixed-size field. */
  convert-string_ start length -> string:
    // Find first NUL within [start .. start+length).
    end := start
    limit := start + length
    while (end < limit) and (uint8_ end) != 0:
      end++

    // Slice bytes [start .. end) and convert to a Toit string.
    return (payload[start..end]).to-string

  /** See $super. */
  stringify -> string:
    return "$(super.stringify): $sw-version|$hw-version"

/**
The UBX-NAV-POSLLH message.

Geodetic position solution.  Works on u-blox 6 and M8.
*/
class NavPosLlh extends Message:
  static ID ::= 0x02

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  static DEGREES-SCALING-FACTOR_ ::= 1e7

  constructor.private_ payload/ByteArray:
    super.private_ Message.NAV ID payload

  id-string_ -> string:
    return "POSLLH"

  /** GPS time of week of the navigation epoch. */
  itow -> int:
    return uint32_ 0

  /** Raw Longitude value returned by the device (Degrees: / 1e7). */
  longitude-raw -> int:
    return int32_ 4

  /** Raw Latitude value returned by the device (Degrees: / 1e7). */
  latitude-raw    -> int:
    return int32_ 8

  /** Height above ellipsoid. */
  height-mm  -> int:
    return int32_ 12

  /** Height above mean sea level. */
  height-msl-mm   -> int:
    return int32_ 16

  /** Horizontal measurement accuracy estimate. */
  horizontal-accuracy-mm   -> int:
    return uint32_ 20

  /** Vertical measurement accuracy estimate. */
  vertical-accuracy-mm   -> int:
    return uint32_ 24

  /** Longitude value converted to degrees (as float). */
  longitude-deg -> float:
    return longitude-raw / DEGREES-SCALING-FACTOR_

  /** Latitude value converted to degrees (as float). */
  latitude-deg -> float:
    return latitude-raw / DEGREES-SCALING-FACTOR_

  stringify -> string:
    return  "$(super.stringify): [Latitude:$(latitude-deg),Longtidude:$(longitude-deg)]"


/**
The UBX-NAV-SVINFO message.

"Space Vehicle INFOrmation" message.  Is legacy, present on u-blox 6 and kept
  on M8 for backward compatibility.
*/
class NavSvInfo extends Message:
  static ID ::= 0x30

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  constructor.private_ payload/ByteArray:
    super.private_ Message.NAV ID payload

  id-string_ -> string:
    return "SVINFO"

  /** The GPS interval time of week of the navigation epoch. (ms). */
  itow -> int:
    return uint32_ 0

  /** Number of channels. */
  num-ch -> int:
    return uint8_ 4

  /** Global flags bitmask.

  ```
  Mask 0b00000111 contains a number representing chip hardware generation:
   - 0: Antaris, Antaris 4
   - 1: u-blox 5
   - 2: u-blox 6
   - 3: u-blox 7
   - 4: u-blox 8 / u-blox M8
  ```
  */
  global-flags -> int:
    return uint8_ 5

  /**
  How many satellites in the message.

  Function returns $num-ch. Is included to help this 'legacy' class become
    functionally similar with UBX-NAV-SAT.
  */
  satellite-count -> int:
    return num-ch

  /**
  The satellite data in the package for the given $index.

  The $index must satisfy 0 <= $index < $num-ch.
  */
  satellite-data index -> SatelliteData:
    if not 0 <= index < num-ch: throw "INVALID ARGUMENT"
    return SatelliteData index payload --src-id=ID


/**
The UBX-NAV-PVT message.

Navigation, position, velocity, and time solution.
*/
class NavPvt extends Message:
  /** The UBX-NAV-PVT message ID. */
  static ID ::= 0x07

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  /** Unknown GNSS fix. */
  static NO-FIX ::= 0
  /** Dead reckoning only. */
  static DEAD-RECKONING-ONLY ::= 1
  /** 2D fix. */
  static FIX-2D ::= 2
  /** 3D fix. */
  static FIX-3D ::= 3
  /** GPS and dead reckoning. */
  static GPS-DEAD-FIX ::= 4
  /** Time only fix. */
  static TIME-ONLY ::= 5

  /** Constructs a poll UBX-NAV-PVT message. */
  constructor.poll:
    super.private_ Message.NAV ID #[]

  constructor.private_ payload/ByteArray:
    super.private_ Message.NAV ID payload

  id-string_ -> string:
    return "PVT"

  /** Whether this is a GNSS fix. */
  is-gnss-fix -> bool:
    return (flags & 0b00000001) != 0

  /** The time in UTC. */
  utc-time -> Time:
    return Time.utc year month day h m s --ns=ns

  /** The GPS interval time of week of the navigation epoch. */
  itow -> int:
    return uint32_ 0

  /** The year (UTC). */
  year -> int:
    return uint16_ 4

  /**
  The month (UTC).
  In the range [1..12].
  */
  month -> int:
    return uint8_ 6

  /**
  The day (UTC).
  In the range [1..31].
  */
  day -> int:
    return uint8_ 7

  /**
  The hours (UTC).
  In the range [0..23].
  */
  h -> int:
    return uint8_ 8

  /**
  The minutes (UTC).
  In the range [0..59].
  */
  m -> int:
    return uint8_ 9

  /**
  The seconds (UTC).
  In the range [0..60].
  */
  s -> int:
    return uint8_ 10

  /**
  Validity flag.
  See receiver specification for details.
  */
  valid -> int:
    return uint8_ 11

  /** Time accuracy estimate in nanoseconds */
  time-acc -> int:
    return uint32_ 12

  /**
  Fraction of second in nano seconds.
  The fraction may be negative.
  */
  ns -> int:
    return int32_ 16

  /**
  The type of fix.
  One of $NO-FIX, $DEAD-RECKONING-ONLY, $FIX-2D, $FIX-3D, $GPS-DEAD-FIX, $TIME-ONLY.
  */
  fix-type -> int:
    return uint8_ 20

  /**
  Fix status flags.
  See receiver specification for details.
  */
  flags -> int:
    return uint8_ 21

  /**
  Additional fix status flags.
  See receiver specification for details.
  */
  flags2 -> int:
    return uint8_ 22

  /** Number of satellites used for fix. */
  num-sv -> int:
    return uint8_ 23

  /** Longitude. */
  lon -> int:
    return int32_ 24

  /** Latitude. */
  lat -> int:
    return int32_ 28

  /** Height above ellipsoid in millimeter. */
  height -> int:
    return int32_ 32

  /** Height above mean sea level in millimeter. */
  height-msl -> int:
    return int32_ 36

  /** Horizontal accuracy in millimeter. */
  horizontal-acc -> int:
    return uint32_ 40

  /** Vertical accuracy in millimeter. */
  vertical-acc -> int:
    return uint32_ 44

  /** NED north velocity in millimeters per second. */
  north-vel -> int:
    return int32_ 48

  /** NED east velocity in millimeters per second. */
  east-vel -> int:
    return int32_ 52

  /** NED down velocity in millimeters per second. */
  down-vel -> int:
    return int32_ 56

  /** Ground speed (2D) in millimeters per second. */
  ground-speed -> int:
    return int32_ 60

  /** Heading of motion (2D). */
  heading-of-motion -> int:
    return int32_ 64

  /** Speed accuracy in millimeters per second. */
  speed-acc -> int:
    return uint32_ 68

  /** Heading accuracy. */
  heading-acc -> int:
    return uint32_ 72

  /**
  Position DOP.

  Position 'Dilution of Position' scale.  Scale 0.01.
  */
  position-dop -> float:
    return (uint16_ 76) / 100.0

  /**
  Additional flags.

  See receiver specification for details.
  */
  flags3 -> int:
    return uint32_ 78

  /**
  The heading of the vehicle.

  See receiver specification for details.
  */
  heading-vehicle -> int:
    return int32_ 84

  /**
  Magnetic declination.
  See receiver specification for details.
  */
  magnetic-declination -> int:
    return int16_ 88

  /**
  Accuracy of magnetic declination.
  See receiver specification for details.
  */
  magnetic-acc -> int:
    return uint16_ 90


/**
The UBX-NAV-SOL message.

Legacy Navigation solution, in ECEF (Earth-Centered, Earth-Fixed cartesian
  coordinates).  This message is included for backwards compatibility.  Whilst
  it is available on M8 and later, UBX-NAV-PVT messages are preferred).
*/
class NavSol extends Message:
  static ID ::= 0x06

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  static FLAGS-GPS-FIX-OK_              ::= 0b00000001 // e.g. is within DOP & ACC Masks.
  static FLAGS-DGPS-USED-MASK_          ::= 0b00000010
  static FLAGS-WEEK-VALID-MASK_         ::= 0b00000100
  static FLAGS-TIME-OF-WEEK-VALID-MASK_ ::= 0b00001000

  /** Unknown GNSS fix. */
  static NO-FIX ::= 0
  /** Dead reckoning only. */
  static DEAD-RECKONING-ONLY ::= 1
  /** 2D fix. */
  static FIX-2D ::= 2
  /** 3D fix. */
  static FIX-3D ::= 3
  /** GPS and dead reckoning. */
  static GPS-DEAD-FIX ::= 4
  /** Time only fix. */
  static TIME-ONLY ::= 5

  /** Constructs a poll UBX-NAV-SOL message. */
  constructor.poll:
    super.private_ Message.NAV ID #[]

  constructor.private_ payload/ByteArray:
    super.private_ Message.NAV ID payload

  id-string_ -> string:
    return "SOL"

  /** Whether this is a GNSS fix. */
  is-gnss-fix -> bool:
    return (flags & FLAGS-GPS-FIX-OK_) != 0

  /** The GPS interval time of week of the navigation epoch. */
  itow -> int:
    return uint32_ 0

  /**
  The fractional GPS interval time of week (in ns) of the navigation epoch.

  Range in ns: -500000..+500000.
  */
  ftow -> int:
    return int32_ 4

  /**
  The GPS Week number.

  This is the week number since Jan 6 1980.  This value is not always valid.  A
    potentially non-zero value can be obtained if it has taken a long time to
    get a fix.  Test for $has-valid-week before using this value.
  */
  week -> int:
    return int16_ 8

  /**
  Whether GPS Week number is valid. (UBX field: WKNSET.)

  See $week.  Time values should not be used until this returns true.
  */
  has-valid-week -> bool:
    return ((flags & FLAGS-WEEK-VALID-MASK_) >> FLAGS-WEEK-VALID-MASK_.count-trailing-zeros) != 0

  /**
  Whether GPS Time of Week number is valid. (UBX field: TOWSET.)
  */
  valid-time-of-week -> bool:
    return ((flags & FLAGS-TIME-OF-WEEK-VALID-MASK_) >> FLAGS-TIME-OF-WEEK-VALID-MASK_.count-trailing-zeros) != 0

  //The precise GPS time of week in seconds is:
  //(iTOW * 1e-3) + (fTOW * 1e-9)

  /**
  Whether DGPS is used.  (UBX field: diffSoln)
  */
  dgps-used -> bool:
    return ((flags & FLAGS-DGPS-USED-MASK_) >> FLAGS-DGPS-USED-MASK_.count-trailing-zeros) != 0

  /**
  The type of fix.

  One of $NO-FIX, $DEAD-RECKONING-ONLY, $FIX-2D, $FIX-3D, $GPS-DEAD-FIX, $TIME-ONLY.
  */
  fix-type -> int:
    return uint8_ 10

  /**
  Fix status flags.

  See receiver specification for details.
  */
  flags -> int:
    return uint8_ 11

  /**
  Number of satellites used for fix.
  */
  num-sv -> int:
    return uint8_ 47

  /**
  Position DOP.

  Position 'Dilution of Position' scale.  Scale 0.01.
  */
  position-dop -> float:
    return (uint16_ 44).to-float / 100

  /** ECEF X coordinate. */
  ecef-x-cm -> int: return int32_ 12      // I4 cm.

  /** ECEF Y coordinate. */
  ecef-y-cm -> int: return int32_ 16      // I4 cm.

  /** ECEF Z coordinate. */
  ecef-z-cm -> int: return int32_ 20      // I4 cm.

  /** 3D Position Accuracy Estimate. */
  p-acc-cm  -> int: return uint32_ 24     // U4 cm.

  /** ECEF X velocity in cm/s. */
  ecef-vx-cms -> int: return int32_ 28      // I4 cm/s.

  /** ECEF Y velocity in cm/s. */
  ecef-vy-cms -> int: return int32_ 32      // I4 cm/s.

  /** ECEF Z velocity in cm/s. */
  ecef-vz-cms -> int: return int32_ 36      // I4 cm/s.

  /** Speed Accuracy Estimate in cm/s. */
  s-acc-cms  -> int: return uint32_ 40      // U4 cm/s.

  /** Reserved 1. */
  reserved1 -> int: return uint8_ 46      // U1.

  /** Reserved 2. */
  reserved2 -> int: return uint32_ 48      // U4 (M8 doc shows U1[4]; same 4 bytes).

/**
The UBX-NAV-TIMEUTC message.

UTC time solution.  Functions on 6M and later devices.
*/
class NavTimeUtc extends Message:
  static ID ::= 0x21

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  static TIME-OF-WEEK-VALID-MASK_ ::= 0b00000001
  static WEEK-VALID-MASK_         ::= 0b00000010
  static UTC-VALID-MASK_          ::= 0b00000100

  /** Constructs a poll UBX-NAV-TIMEUTC message. */
  constructor.poll:
    super.private_ Message.NAV ID #[]

  constructor.private_ payload/ByteArray:
    super.private_ Message.NAV ID payload

  id-string_ -> string: return "TIMEUTC"

  /** The GPS interval time of week of the navigation epoch. */
  itow -> int:
    return uint32_ 0

  /** The time in UTC. */
  utc-time -> Time:
    return Time.utc year month day h m s --ns=ns

  /** UTC Time accuracy estimate, in nanoseconds. */
  time-accuracy-est -> int:
    return uint32_ 4

  /** UTC time, nanoseconds only. */
  ns -> int:
    return int32_ 8

  /** UTC time, year only. */
  year -> int:
    return uint16_ 12

  /** UTC time, month only. */
  month -> int:
    return uint8_ 14

  /** UTC time, calendar day only. */
  day -> int:
    return uint8_ 15

  /** UTC time, hours only. */
  h -> int:
    return uint8_ 16

  /** UTC time, minutes only. */
  m -> int:
    return uint8_ 17

  /**
  UTC Seconds.

  Normally 00..59, but leap seconds can produce between 59 to 61 seconds.  The
    uBlox manual states "u-blox receivers are designed to handle leap seconds in
    their UTC output and consequently users processing UTC times from either
    NMEA and UBX messages should be prepared to handle minutes that are either
    59 or 61 seconds long." (Section 9.7 "Leap Seconds" - ublox 8 Datasheet, pp
    27.)
  */
  s -> int:
    return uint8_ 18

  /**
  Validity of time flags.

  M8+: upper bits carry UTC standard.
  */
  valid-flags-raw -> int:
    return uint8_ 19

  /**
  Returns if GPS Week number is Valid. (UBX field: ValidWKN)
  */
  valid-week -> bool:
    return ((valid-flags-raw & WEEK-VALID-MASK_) >> WEEK-VALID-MASK_.count-trailing-zeros) != 0

  /**
  Returns if GPS Time of Week number is Valid. (UBX field: ValidTOW)
  */
  valid-time-of-week -> bool:
    return ((valid-flags-raw & TIME-OF-WEEK-VALID-MASK_) >> TIME-OF-WEEK-VALID-MASK_.count-trailing-zeros) != 0

  /**
  Returns if UTC time is valid. (UBX field: ValidUTC - If the leap seconds are known.)
  */
  valid-utc -> bool:
    return ((valid-flags-raw & UTC-VALID-MASK_) >> UTC-VALID-MASK_.count-trailing-zeros) != 0

  /**
  Returns UTC standard code.

  Returns 0 on Legacy. Common values:
  ```
  - 0: Information not available.
  - 1: Communications Research Labratory (CRL), Tokyo, Japan.
  - 2: National Institute of Standards and Technology (NIST).
  - 3: U.S. Naval Observatory (USNO).
  - 4: International Bureau of Weights and Measures (BIPM).
  - 5: European laboratories.
  - 6: Former Soviet Union (SU).
  - 7: National Time Service Center (NTSC), China.
  - 8: National Physics Laboratory India (NPLI).
  - 15: Unknown.
  ```
  */
  utc-standard -> int:
    return (valid-flags-raw >> 4) & 0x0F



/**
The UBX-CFG-TP5 message.

Used to configure the pulse signal on the TIMEPULSE/PPS pin, used for time
  synchronisation.  The message controls parameters like the pulse's period
  and duty cycle.

Parameters and flags are different starting from Protocol version 16.
*/
/*
Payload (32 bytes):
  0  : tpIdx (U1)       // 0=TIMEPULSE, 1=TIMEPULSE2 (if available)
  1  : version (U1)     // 1
  2..3 : reserved
  4..5 : antCableDelay (I2, ns)
  6..7 : rfGroupDelay  (I2, ns)
  8..11 : freqPeriod (U4)         // Hz if !isLength; period in us if isLength
  12..15: freqPeriodLock (U4)
  16..19: pulseLenRatio (U4)      // duty × 1e-9 if isLength=0; length in ns if isLength=1
  20..23: pulseLenRatioLock (U4)
  24..27: userConfigDelay (I4, ns)
  28..31: flags (U4)
Key flag bits (common):
  bit0: active (1=on)
  bit1: lockGnssFreq
  bit2: lockedOtherSet
  bit5: isFreq (else period)
  bit6: isLength (else ratio)
  bit10: alignToTow
  bit11: polarity (1=active high)
  bit14: timeGridUtc (vs. GNSS time)  [chip-specific]
*/
class CfgTp5 extends Message:
  static ID ::= 0x31

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  // Index
  static TP-IDX-0 ::= 0
  static TP-IDX-1 ::= 1

  // Flags helpers
  static FLAG-ACTIVE       ::= 0b00000001
  static FLAG-IS-FREQ      ::= 0b00100000
  static FLAG-IS-LENGTH    ::= 0b01000000
  static FLAG-ALIGN-TOW    ::= 0b00000100_00000000
  static FLAG-POLARITY-HI  ::= 0b00001000_00000000
  static FLAG-UTC-GRID     ::= 0b01000000_00000000

  /** Poll the TP5 configuration for tpIdx (0 or 1). */
  constructor.poll --tp-idx/int=TP-IDX-0:
    new-payload := ByteArray 2
    super.private_ Message.CFG ID new-payload
    put-uint8_ 0 tp-idx
    put-uint8_ 1 1  // Version.

  /** Construct an instance with bytes from a retrieved message. */
  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  /**
  Set TP5, starting with common defaults:
  - active, align to TOW, UTC grid off by default
  - frequency mode at 1 Hz, 50% duty, active-high
  */
  constructor.set
      --tp-idx/int=TP-IDX-0
      --ant-cable-ns/int=0
      --rf-group-ns/int=0
      --freq-hz/int=1
      --duty-permille/int=500
      --use-utc/bool=false
      --active/bool=true
      --polarity-high/bool=true:

    new-payload := ByteArray 32
    super.private_ Message.CFG ID new-payload

    put-uint8_ 0 tp-idx
    put-uint8_ 1 1  // Version.
    put-uint16_ 2 0
    put-int16_ 4 ant-cable-ns
    put-int16_ 6 rf-group-ns

    // Frequency mode: set freqPeriod=freq, isFreq=1; pulseLenRatio = duty * 1e-9.
    put-uint32_ 8 freq-hz
    put-uint32_ 12 freq-hz

    duty-ratio-nano := duty-permille * 1_000_000  // permille -> nanos of 1e9.
    put-uint32_ 16 duty-ratio-nano
    put-uint32_ 20 duty-ratio-nano
    put-int32_ 24 0

    flags := 0
    if active: flags |= FLAG-ACTIVE
    flags |= FLAG-IS-FREQ // frequency mode
    // we used ratio (not length), so FLAG-IS-LENGTH stays 0
    flags |= FLAG-ALIGN-TOW
    if polarity-high: flags |= FLAG-POLARITY-HI
    if use-utc: flags |= FLAG-UTC-GRID
    put-uint32_ 28 flags

  id-string_ -> string:
    return "TP5"

  /**
  Time pulse selection.

  CfgTp5.TP-IDX-0=TIMEPULSE, CfgTp5.TP-IDX-1=TIMEPULSE2
  */
  tp-idx -> int:
    return uint8_ 0

  /**
  Configuration flags.

  Parameters and flags are different starting from Protocol version 16.
  */
  flags -> int:
    return uint32_ 28

  freq -> int:
    return uint32_ 8

  duty-nano -> int:
    return uint32_ 16

/**
The UBX-CFG-NAV5 message.

Classic navigation engine settings (legacy but still widely used).
*/
/*
Payload (36 bytes):
  0..1  mask (U2)             // which fields to apply
  2     dynModel (U1)         // 0=portable, 2=stationary, 3=pede, 4=auto, 6=sea, 7=air1g, 8=air2g, 9=air4g
  3     fixMode (U1)          // 1=2D only, 2=3D only, 3=auto 2D/3D
  4..7  fixedAlt (I4, cm)     // for 2D mode if used
  8..11 fixedAltVar (U4, cm^2)
  12    minElev (I1, deg)
  13    drLimit (U1)          // dead reckoning limit (s)
  14..15 pDop (U2, 0.1)
  16..17 tDop (U2, 0.1)
  18..19 pAcc (U2, m)
  20..21 tAcc (U2, m)
  22    staticHoldThresh (U1, cm/s)
  23    dgnssTimeout (U1, s)
  24    cnoThreshNumSVs (U1)
  25    cnoThresh (U1, dBHz)
  26..27 reserved1
  28..29 staticHoldMaxDist (U2, m)
  30    utcStandard (U1)
  31..35 reserved2
*/
class CfgNav5 extends Message:
  static ID ::= 0x24

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  // Mask bits (subset).
  static DYN-MASK_      ::= 0b00000000_00000001
  static FIXMODE-MASK_  ::= 0b00000000_00000010
  static OUTLYING-MASK_ ::= 0b00000000_00000100
  static ALT-MASK_      ::= 0b00000000_00001000
  static DGPS-MASK_     ::= 0b00000000_00010000
  static TDOP-MASK_     ::= 0b00000000_00100000
  static PDOP-MASK_     ::= 0b00000000_01000000
  static PACC-MASK_     ::= 0b00000000_10000000
  static TACC-MASK_     ::= 0b00000001_00000000
  static STATIC-MASK_   ::= 0b00000010_00000000
  static UTC-MASK_      ::= 0b00000100_00000000

  // Dynamic models (subset).
  static DYN-PORTABLE   ::= 0
  static DYN-STATIONARY ::= 2
  static DYN-PEDESTRIAN ::= 3
  static DYN-AUTOMOTIVE ::= 4
  static DYN-SEA        ::= 6
  static DYN-AIR1G      ::= 7
  static DYN-AIR2G      ::= 8
  static DYN-AIR4G      ::= 9

  // Fix mode.
  static FIX-2D   ::= 1
  static FIX-3D   ::= 2
  static FIX-AUTO ::= 3

  static PACK-MODELS ::= {
    DYN-PORTABLE: "PORTABLE",
    DYN-STATIONARY: "STATIONARY",
    DYN-PEDESTRIAN: "PEDESTRIAN",
    DYN-AUTOMOTIVE: "AUTOMOTIVE",
    DYN-SEA: "SEA",
    DYN-AIR1G: "AIR1G",
    DYN-AIR2G: "AIR2G",
    DYN-AIR4G: "AIR4G"
  }


  /** Poll current NAV5. */
  constructor.poll:
    super.private_ Message.CFG ID #[]

  /** Construct an instance with bytes from a retrieved message. */
  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  /** Minimal setter: set dyn model + auto 2D/3D, leave others default. */
  constructor.set-basic
      --dyn/int=DYN-AUTOMOTIVE
      --fix/int=FIX-AUTO:

    // Sensible defaults / zeros elsewhere.
    new-payload := ByteArray 36
    super.private_ Message.CFG ID new-payload
    put-uint16_ 0 (DYN-MASK_ | FIXMODE-MASK_)
    put-uint8_ 2 dyn
    put-uint8_ 3 fix


  /** Full setter for advanced control (pass null to skip a field & mask). */
  constructor.set-advanced
      --dyn/int?=null
      --fix/int?=null
      --fixed-alt-cm/int?=null
      --fixed-alt-var-cm2/int?=null
      --min-elev-deg/int?=null
      --dr-limit-s/int?=null
      --p-dop-x10/int?=null
      --t-dop-x10/int?=null
      --p-acc-m/int?=null
      --t-acc-m/int?=null
      --static-hold-thresh-cmps/int?=null
      --dgnss-timeout-s/int?=null
      --cno-thresh-num-sv/int?=null
      --cno-thresh-dbHz/int?=null
      --static-hold-max-dist-m/int?=null
      --utc-standard/int?=null:
    new-payload := ByteArray 36
    super.private_ Message.CFG ID new-payload

    mask := 0
    if dyn:
      mask |= DYN-MASK_
      put-uint8_ 2 dyn
    if fix:
      mask |= FIXMODE-MASK_
      put-uint8_ 3 fix
    if fixed-alt-cm:
      mask |= ALT-MASK_
      put-int32_ 4 fixed-alt-cm
    if fixed-alt-var-cm2:
      mask |= ALT-MASK_
      put-uint32_ 8 fixed-alt-var-cm2
    if min-elev-deg:
      mask |= OUTLYING-MASK_
      put-int8_ 12 min-elev-deg
    if dr-limit-s:
      mask |= OUTLYING-MASK_
      put-uint8_ 13 dr-limit-s
    if p-dop-x10:
      mask |= PDOP-MASK_
      put-uint16_ 14 p-dop-x10
    if t-dop-x10:
      mask |= TDOP-MASK_
      put-uint16_ 16 t-dop-x10
    if p-acc-m:
      mask |= PACC-MASK_
      put-uint16_ 18 p-acc-m
    if t-acc-m:
      mask |= TACC-MASK_
      put-uint16_ 20 t-acc-m
    if static-hold-thresh-cmps:
      mask |= STATIC-MASK_
      put-uint8_ 22 static-hold-thresh-cmps
    if dgnss-timeout-s:
      mask |= DGPS-MASK_
      put-uint8_ 23 dgnss-timeout-s
    if cno-thresh-num-sv:
      mask |= OUTLYING-MASK_
      put-uint8_ 24 cno-thresh-num-sv
    if cno-thresh-dbHz:
      mask |= OUTLYING-MASK_
      put-uint8_ 25 cno-thresh-dbHz
    if static-hold-max-dist-m:
      mask |= STATIC-MASK_
      put-uint16_ 28 static-hold-max-dist-m
    if utc-standard:
      mask |= UTC-MASK_
      put-uint8_ 30 utc-standard

    put-uint16_ 0 mask


  id-string_ -> string:
    return "NAV5"

  dyn-model -> int:
    return uint8_ 2

  dyn-model-text -> string:
    return PACK-MODELS[dyn-model]

  fix-mode -> int:
    return uint8_ 3

  mask -> int:
    return uint16_ 0

/**
The UBX-CFG-GNSS message.

Configuring constellations/signals.  Note: Signal bitmasks inside flags are
  chip-family specific (M8 vs M9/M10).  Keeping signals-mask=0 lets firmware
  choose defaults, or bits can be set as needed for advanced use.

Each block is a map with four keys, each with:
```
  block["gnssId"]:   gnssId (1 byte)   - 0=GPS, 1=SBAS, 2=Galileo, 3=BeiDou, 5=QZSS, 6=GLONASS, etc.
  block["resTrkCh"]: resTrkCh (1 byte) - reserved tracking channels.
  block["maxTrkCh"]: maxTrkCh (1 byte) - max tracking channels to use.
  block["flags"]:    4 byte value      - bit0 enable; higher bits = signal bitmask**.
```
**'Signal Bitmask' bits/masks/meanings are dependent on the chipset in use.  See
  the manual for your chipset for the UBX-CFG-GNSS signal bitmask definitions.

Multiple blocks can be created for each `gnssId` type.  Use the convenience
  builder $create-config-block for these.

Common `gnssId` values are given by the constants `CfgGnss.GNSS-GPS`,
  `$CfgGnss.GNSS-SBAS`, `$CfgGnss.GNSS-GALILEO`, `$CfgGnss.GNSS-BEIDOU`,
  `$CfgGnss.GNSS-QZSS`, and `$CfgGnss.GNSS-GLONASS`
*/
class CfgGnss extends Message:
  static ID ::= 0x3E

  /**
  The minimum protocol version for the message type.

  Devices must support at least this protocol version to use the message.
  */
  static MIN-PROTVER/string := "15.0"

  /**
  The maximum protocol version for the message type.

  Devices supporting protocol version newer than this may not be able to
    work with the message type.
  */
  static MAX-PROTVER/string := ""

  // Common gnssId values.
  static GNSS-GPS      ::= 0
  static GNSS-SBAS     ::= 1
  static GNSS-GALILEO  ::= 2
  static GNSS-BEIDOU   ::= 3
  static GNSS-QZSS     ::= 5
  static GNSS-GLONASS  ::= 6

  // Block field numbers.
  static BLOCK-GNSSID_    ::= 0
  static BLOCK-RESTRKCH_  ::= 1
  static BLOCK-MAXTRKCH_  ::= 2
  static BLOCK-RESERVED1_ ::= 3
  static BLOCK-FLAGS_     ::= 4

  // Flags helpers.
  static FLAG-ENABLE ::= 1

  /** Construct a poll message to get current GNSS configuration. */
  constructor.poll:
    // Empty payload poll (some firmwares accept either empty or msgVer=0).
    super.private_ Message.CFG ID #[]

  /** Construct an instance with bytes from a retrieved message. */
  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  /** Build from a list of 8-byte blocks. numTrkChHw/Use are advisory. */
  constructor.set
      --msg-ver/int=0
      --num-trk-ch-hw/int=0
      --num-trk-ch-use/int=0
      --blocks/List=[]:
    new-payload := ByteArray (4 + 8 * blocks.size)
    super.private_ Message.CFG ID new-payload

    put-uint8_ 0 msg-ver
    put-uint8_ 1 num-trk-ch-hw
    put-uint8_ 2 num-trk-ch-use
    put-uint8_ 3 blocks.size

    blocks.size.repeat: | i/int |
      block := blocks[i]  // Expect map with fields: "gnssId", "resTrkCh", "maxTrkCh", "flags"
      assert: block.size = 5
      base := 4 + 8 * i
      put-uint8_ (base + BLOCK-GNSSID_) block["gnssId"]
      put-uint8_ (base + BLOCK-RESTRKCH_) block["resTrkCh"]
      put-uint8_ (base + BLOCK-MAXTRKCH_) block["maxTrkCh"]
      put-uint8_ (base + BLOCK-RESERVED1_) 0
      put-uint32_ (base + BLOCK-FLAGS_) block["flags"]

  id-string_ -> string:
    return "GNSS"

  /**
  Convenience builder for a configuration block.

  One block is one `gnssId`, with a set of 3 properties applying to it.  (One
    `gnssId` is one of 0=GPS, 1=SBAS, 2=Galileo, 3=BeiDou, 5=QZSS, 6=GLONASS,
    etc.).  More than one block can be provided in a single message.

  `enable` is bit 1 of the flags field.  The content of the `flags` field is
    different depending on the hardware in question.
  */
  static create-config-block -> Map
      gnss-id/int
      --enable/bool?=null
      --res-trk/int=0
      --max-trk/int=0
      --flags/int=0:
    if enable:
      flags = (enable ? FLAG-ENABLE : 0) | flags
    block/Map := {"gnssId": gnss-id, "resTrkCh": res-trk, "maxTrkCh": max-trk, "flags": flags}
    return block

  /** Message version for this set of config blocks.  */
  msg-ver -> int:
    return uint8_ 0

  /** Number of config blocks in this message.  */
  num-config-blocks -> int:
    return uint8_ 3

  /** The `gnssId` for the i'th config block. */
  config-block-gnss-id i/int -> int:
    assert: 0 < i <= num-config-blocks
    return uint8_ (4 + 8*i)

  /** The flags for the i'th config block. */
  config-block-flags i/int -> int:
    return uint32_ (4 + 8*i + 4)

  /**
  The entire config block (map) for the i'th config block.

  A config block can be retrieved using this function for modification, and
    sending back.
  */
  config-block i/int -> Map:
    assert: 0 < i <= num-config-blocks
    base := (4 + 8*i)
    block := {:}
    block["gnssId"] = uint8_ (base + BLOCK-GNSSID_)
    block["resTrkCh"] = uint8_ (base + BLOCK-RESTRKCH_)
    block["maxTrkCh"] = uint8_ (base + BLOCK-MAXTRKCH_)
    block["flags"] = uint32_ (base + BLOCK-FLAGS_)
    return block



/**
The UBX-CFG-VALGET message.

Requests one or more configuration keys; device responds with UBX-CFG-VALGET
  response payload containing key-value pairs.

Requests could give NAKs for several reasons, such as a key being unknown to the
  receiver FW, if the layer field specifies an invalid layer to get the value
  from, or if the keys array specifies more than 64 key IDs.
*/
/*
Two request formats:

Poll request format (v0):
  U1 version (0)
  U1 layer
  U2 reserved
  optional repeated:
    U4 keyId(s)

Poll request format (v1):
  (Response format is typically v1 on newer receivers:)
  U1 version (1)
  U1 layer
  U2 reserved
  repeated:
    U4 keyId
    value bytes (size implied by key type)
*/
class CfgValGet extends Message:
  static CLASS ::= 0x06
  static ID    ::= 0x8B

  /** The "Current Configuration". Immediate effect. See $layer. */
  static LAYER-RAM     ::= 0x01
  /** "Battery Backed RAM".  Effective on restart. See $layer. */
  static LAYER-BBR     ::= 0x02
  /** Stored in flash (if available) and effective on restart. See $layer. */
  static LAYER-FLASH   ::= 0x04
  /** Layer contains hard coded default values.  Non-writable. See $layer. */
  static LAYER-DEFAULT ::= 0x07

  // Max allowable requested key IDs in a single message.
  static MAX-KEY-IDS_ ::= 64

  constructor.poll --version/int=0 --layer/int=LAYER-DEFAULT --keys/List=[]:
    // Empty payload poll (some firmwares accept either empty or msgVer=0).
    super.private_ Message.CFG ID (ByteArray 4)

    // Version, layer, and Position.
    put-uint8_ 0 version
    put-uint8_ 1 layer
    put-uint16_ 2 0

    // Copy in the keys.
    //b := ByteArray
    //for k in keys:
    //  b.add_uint32 k

  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  version -> int:
    return uint8_ 0

  /**
  The layer (source) from which the configuration items should be retrieved.

  In Ublox, several 'configuration layers' exist. They are separate sources of
    Configuration Items. Some of the layers are read-only and others are
    modifiable. Layers are organized in terms of priority. Values in a high-
    priority layer will replace values stored in low-priority layer. On startup
    of the receiver all configuration layers are read and the items within each
    layer are stacked up in order to create the Current Configuration, which is
    used by the receiver at run-time.

  They are called layers in that they are 'stacked'.   (Stacking of the
    configuration items from the different layers is detailed in the manual.)
    To obtain the 'current configuration' for a defined item, the receiver
    software goes through the layers above and stacks all the found items on
    top.  Some items may not be present in every layer.  The result is the RAM
    Layer filled with all configuration items, and their given configuration
    values coming from the highest priority layer.

  One of $LAYER-RAM, $LAYER-BBR, $LAYER-FLASH, or $LAYER-DEFAULT.
  */
  layer -> int:
    return uint8_ 1

  /**
  Paging value if >64 response key/value pairs.

  Whilst this response message type is limited to a maximum of $MAX-KEY-IDS_
    (64) key-value pairs, if there are more than 64 possible responses the
    'position' field can specify that the response message should skip this
    number of key-value pairs before constructing the message. This allows a
    large set of values to be retrieved, 64 at a time.  If the response contains
    less than 64 key-value pairs then all values have been reported -
    Otherwise, there may be more to read.
  */
  position -> int:
    return uint16_ 2

  /**
  Parse a VALGET response payload into a Map of key/value pairs.

  This version of the code will return the number of bytes defined by the key.
    (The returned map data is formatted as a byte array of 1, 2, or 4 bytes, as
    determined by the key's size.)
  */
  payload-to-map_ -> Map:
    output := {:}
    if payload.size < 4: return output

    reader := io.Reader payload
    reader.skip 4
    while (payload.size - reader.processed) >= 4:
      key-raw := reader.little-endian.read-uint32
      key := CfgGroupItem.from-value_ key-raw
      size := key.size-bytes

      if size <= (payload.size - reader.processed):
        // Todo: get output values and convert them to their native formats.
        value-raw := reader.read-bytes size
        output[key] = value-raw
      else:
        throw "size bigger than remaining bytes"

    return output

  /**
  Parse a supplied List into the required ByteArray form for polling.
  */
  list-to-payload_ input-map/Map -> ByteArray:

    return ByteArray 0


/**
The UBX-CFG-VALSET message.

Sets one or more configuration keys with a value.  Device responds with either
  UBX-ACK-ACK or UBX-ACK-NAK.

Requests could give NAKs for several reasons, such as a key being unknown to the
  receiver FW, if the layer field specifies an invalid layer to get the value
  from, or if the keys array specifies more than 64 key IDs.

When using transactions, either all or none of the configuration values will be
  set.
*/
class CfgValSet extends Message:
  static CLASS ::= 0x06
  static ID    ::= 0x8A

  /** The "Current Configuration". Immediate effect. See $layer. */
  static LAYER-RAM     ::= 0x01
  /** "Battery Backed RAM".  Effective on restart. See $layer. */
  static LAYER-BBR     ::= 0x02
  /** Stored in flash (if available) and effective on restart. See $layer. */
  static LAYER-FLASH   ::= 0x04
  /** Layer contains hard coded default values.  Non-writable. See $layer. */
  static LAYER-DEFAULT ::= 0x07

  // Max allowable requested key IDs in a single message.
  static MAX-KEY-IDS_ ::= 64

  /** Transaction processed immediately (default). */
  static TRANSACTIONLESS ::= 0
  /** Begin a new (or REstart an old) transaction. */
  static START           ::= 1
  /** Add more to the current transaction. */
  static CONTINUE        ::= 2
  /** Commit/process the compiled transaction. */
  static COMMIT          ::= 3
  static TRANSACTION-MASK_ ::= 0b00000011

  constructor.poll --version/int=0 --layer=LAYER_RAM --map/Map={:}
      --transaction-state/int=TRANSACTIONLESS:
    super.private_ Message.CFG ID (ByteArray 4)
    assert: 0x0 <= version <= 0x1
    assert: 0x0 < map.size <= MAX-KEY-IDS_

    // Calculate transaction bits
    transaction := TRANSACTIONLESS
    if version > 0:
      transaction = (payload[2] & ~TRANSACTION-MASK_) | (transaction-state & TRANSACTION-MASK_)

    // Version and layer. payload[2..3] is reserved if no transaction.
    put-uint8_ 0 version
    put-uint8_ 1 layer
    put-uint8_ 2 transaction
    put-uint8_ 3 0

    // Convert the supplied map to data.
    append_ keys

  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  version -> int:
    return uint8_ 0

  layer -> int:
    return uint8_ 1

  transaction-state -> int:
    return payload[2] & TRANSACTION-MASK_



/**
The UBX-CFG-VALDEL message.

Deletes keys from one or more layers (resets to default).

Supports transactional usage.  If version is 0x1, the key deletions can be
  stacked up without applying them immediately.  When complete they can be
  applied atomically - as in either all applied, or all not applied - eg, if one
  fails, they are all rolled back.

When using transactions the following transaction states apply:
  0 — Apply immediately, cancel any previous open transaction.
  1 - Begin (or restart) a transaction.
  2 - Continue building the current transaction.
  3 - Commit the current transaction.

Responds with ACK/NAK.  However: ACK does not mean 'applied'. ACK-ACK means
  "Message was syntactically valid and accepted".  It does not guarantee that
  keys existed, values were supported, or that the transaction was committed
  (unless action=3).

Especially with transactions: TX_BEGIN, TX_CONTINUE: ACK just means "queued".
  Only TX_COMMIT actually applies changes.
*/
/*
Two Versions:
  Format (v0):
    U1 version (0)
    U1 layers (bitmask)
    U2 reserved
    repeated:
      U4 keyId
  Format v1 (With Transactions):
    U1 version (1)
    U1 layers (bitmask)
    X1 transaction
    U1 reserved
    repeated:
      U4 keyId
*/
class CfgValDel extends Message:
  static CLASS ::= 0x06
  static ID    ::= 0x8C

  /** The "Current Configuration". Immediate effect. See $layer. */
  static LAYER-RAM     ::= 0x01
  /** "Battery Backed RAM".  Effective on restart. See $layer. */
  static LAYER-BBR     ::= 0x02
  /** Stored in flash (if available) and effective on restart. See $layer. */
  static LAYER-FLASH   ::= 0x04
  /** Layer contains hard coded default values.  Non-writable. See $layer. */
  static LAYER-DEFAULT ::= 0x07

  // Max allowable requested key IDs in a single message.
  static MAX-KEY-IDS_ ::= 64

  /** Transaction processed immediately (default). */
  static TRANSACTIONLESS ::= 0
  /** Begin a new (or REstart an old) transaction. */
  static START           ::= 1
  /** Add more to the current transaction. */
  static CONTINUE        ::= 2
  /** Commit/process the compiled transaction. */
  static COMMIT          ::= 3
  static TRANSACTION-MASK_ ::= 0b00000011

  constructor.from-byte-array --version/int=0 --layer=LAYER_RAM --key-array/ByteArray=#[]
      --transaction-state/int=TRANSACTIONLESS:
    super.private_ Message.CFG ID (ByteArray 4)
    assert: 0x0 <= version <= 0x1

    // Calculate transaction bits
    transaction := TRANSACTIONLESS
    if version > 0:
      transaction = (payload[2] & ~TRANSACTION-MASK_) | (transaction-state & TRANSACTION-MASK_)

    // Version and layer. payload[2..3] is reserved if no transaction.
    put-uint8_ 0 version
    put-uint8_ 1 layer
    put-uint8_ 2 transaction
    put-uint8_ 3 0
    append_ key-array

  constructor.private_ payload/ByteArray:
    super.private_ Message.CFG ID payload

  static delete --version/int=0 --layer=LAYER_RAM --key-list=[] --transaction-state/int=TRANSACTIONLESS -> CfgValDel:
    assert: 0x0 < key-list.size <= MAX-KEY-IDS_
    key-ba := #[]
    key-list.do: | key |
      if CfgGroupItem.is-valid key:
        new-key := CfgGroupItem.from-value_ key
        key-ba += new-key.to-byte-array
      else:
        throw "Invalid key $key"

    return CfgValDel.from-byte-array
       --version=version
       --layer=layer
       --key-array=key-ba
       --transaction-state=transaction-state

  version -> int:
    return uint8_ 0

  layer -> int:
    return uint8_ 1

  transaction-state -> int:
    return payload[2] & TRANSACTION-MASK_


/**
Class for handling CFG-GROUP-ITEM.

CFG-GROUP-ITEM are configuration items for use with $CfgValGet, $CfgValSet, &
  $CfgValDel.  The structure is a 32-bit value unique Key ID.  It uniquely
  identifies a particular configuration item. The numeric representation of the
  Key ID uses the lower-case hexadecimal format, such as 0x20c400a1. An easier,
  more readable text representation uses the form CFG-GROUP-ITEM. This is also
  referred to as the (Configuration) Key Name.

Class only handles parsing the identifier, not the data.

*/
class CfgGroupItem:
  payload_/int := 0

  static size-mask_  := 0b01110000_00000000_00000000_00000000
  static group-mask_ := 0b00000000_11111111_00000000_00000000
  static id-mask_    := 0b00000000_00000000_00001111_11111111

  constructor.from-value_ .payload_/int:

  constructor.from-byte-array_ payload/ByteArray:
    // Convert the supplied 4 byte ByteArray to uint32.
    assert: payload.size == 4
    reader := io.Reader payload
    payload_ = reader.little-endian.read-int32

  constructor --size/int --group/int --id/int:
    assert: 0x01 <= size <= 0x05
    assert: 0x01 <= group <= 0xfe
    assert: 0x001 <= id <= 0xffe
    replace-payload_ size size-mask_
    replace-payload_ group group-mask_
    replace-payload_ id id-mask_

  /**
  The key's storage size identifier.  (Not the actual storage size.)
  ```
  0x01 = one bit. (The actual storage used is one byte, but only uses LSB.)
  0x02 = one byte.
  0x03 = two bytes.
  0x04 = four bytes.
  ```
  */
  size-raw -> int:
    return read-payload_ size-mask_

  /**
  Variant of $size-raw returning the actual bytes.

  Useful when parsing $CfgValGet messages.
  */
  size-bytes -> int:
    if size-raw == 0x01: return 1
    if size-raw == 0x02: return 1
    if size-raw == 0x03: return 2
    else: return 4

  /** Configuration group identifier. */
  group -> int:
    return read-payload_ group-mask_

  /** The configuration item ID (within the configuration group). */
  id -> int:
    return read-payload_ id-mask_

  /** Hash code for use as an identifier in a Map. */
  hash-code -> int:
    return payload_

  /** Sets a $value, masked by $mask, in the class $payload_. */
  replace-payload_ value/int mask/int -> none:
    payload_ = replace_ payload_ value mask

  /** Reads the $mask, from the class $payload_. */
  read-payload_ mask/int -> int:
    return (payload_ >> mask.count-trailing-zeros) & mask

  /** Returns value as a byte array for other functions to use. */
  to-byte-array -> ByteArray:
    return (to-bytes32 payload_)

  /** Returns value as an integer for other functions to use. */
  to-int -> int:
    return payload_

  /** Turns a 32 bit value into a 4xbyte byte array */
  static to-bytes32 value/int -> ByteArray:
    assert: 0 <= value <= 0xFFFF_FFFF
    output := ByteArray 4
    LITTLE-ENDIAN.put-uint16 output 0 value
    return output

  /** Determines if the value is valid. */
  /* Does this by ensuring the value is not bigger than
     01110000_11111111_00001111_11111111 (0x70FF0FFF) and by checking that
     zeroing all mask bits equals zero. */
  static is-valid id/int -> bool:
    if id > 0x70FF0FFF: return false
    if id.population-count > 23: return false
    working := id
    working = replace_ working 0 size-mask_
    working = replace_ working 0 group-mask_
    working = replace_ working 0 id-mask_
    if working != 0: return false
    return true

  /** Sets a $value, in a $mask, in an integer $payload. */
  static replace_ payload/int value/int mask/int -> int:
    return (payload & ~(mask << mask.count-trailing-zeros)) | ((value & mask) << mask.count-trailing-zeros)
