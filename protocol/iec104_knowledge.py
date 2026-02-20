"""
IEC 60870-5-104 Protocol Knowledge Base.

Encodes the protocol specification: valid TypeID/COT combinations,
command/monitor direction classification, and protocol constants.

References:
- IEC 60870-5-101/104 standard
- Beckhoff interoperability tables
- Cisco Talos IEC-104 detection rules (SIDs 41053-41077)
- ESET Industroyer2 analysis
"""

from __future__ import annotations

from enum import IntEnum


# ---------------------------------------------------------------------------
# TypeID classification (from IEC 60870-5-101, clause 7.2)
# ---------------------------------------------------------------------------

class TypeIDGroup(IntEnum):
    """Broad TypeID classification per protocol spec."""
    MONITOR_PROCESS = 1      # 1-44: Process information in monitor direction
    CONTROL_PROCESS = 2      # 45-69: Process information in control direction
    SYSTEM_MONITOR = 3       # 70-99: System information in monitor direction
    SYSTEM_CONTROL = 4       # 100-109: System information in control direction
    PARAMETER = 5            # 110-119: Parameter in control direction
    FILE_TRANSFER = 6        # 120-127: File transfer


# Monitor direction: process information (TypeID 1-44)
MONITOR_TYPEIDS: dict[int, str] = {
    1: "M_SP_NA_1",   # Single-point information
    2: "M_SP_TA_1",   # Single-point with time tag
    3: "M_DP_NA_1",   # Double-point information
    4: "M_DP_TA_1",   # Double-point with time tag
    5: "M_ST_NA_1",   # Step position information
    6: "M_ST_TA_1",   # Step position with time tag
    7: "M_BO_NA_1",   # Bitstring of 32 bits
    8: "M_BO_TA_1",   # Bitstring with time tag
    9: "M_ME_NA_1",   # Measured value, normalized
    10: "M_ME_TA_1",  # Measured value, normalized with time tag
    11: "M_ME_NB_1",  # Measured value, scaled
    12: "M_ME_TB_1",  # Measured value, scaled with time tag
    13: "M_ME_NC_1",  # Measured value, short floating point
    14: "M_ME_TC_1",  # Measured value, short float with time tag
    15: "M_IT_NA_1",  # Integrated totals
    16: "M_IT_TA_1",  # Integrated totals with time tag
    17: "M_EP_TA_1",  # Event of protection equipment with time tag
    18: "M_EP_TB_1",  # Packed start events with time tag
    19: "M_EP_TC_1",  # Packed output circuit info with time tag
    20: "M_PS_NA_1",  # Packed single-point with status change detection
    21: "M_ME_ND_1",  # Measured value, normalized without quality
    # CP56Time2a variants (30-40)
    30: "M_SP_TB_1",  # Single-point with CP56Time2a
    31: "M_DP_TB_1",  # Double-point with CP56Time2a
    32: "M_ST_TB_1",  # Step position with CP56Time2a
    33: "M_BO_TB_1",  # Bitstring with CP56Time2a
    34: "M_ME_TD_1",  # Measured value, normalized with CP56Time2a
    35: "M_ME_TE_1",  # Measured value, scaled with CP56Time2a
    36: "M_ME_TF_1",  # Measured value, short float with CP56Time2a
    37: "M_IT_TB_1",  # Integrated totals with CP56Time2a
    38: "M_EP_TD_1",  # Event of protection with CP56Time2a
    39: "M_EP_TE_1",  # Packed start events with CP56Time2a
    40: "M_EP_TF_1",  # Packed output circuit with CP56Time2a
}

# Control direction: process commands (TypeID 45-69)
COMMAND_TYPEIDS: dict[int, str] = {
    45: "C_SC_NA_1",   # Single command
    46: "C_DC_NA_1",   # Double command
    47: "C_RC_NA_1",   # Regulating step command
    48: "C_SE_NA_1",   # Set-point, normalized
    49: "C_SE_NB_1",   # Set-point, scaled
    50: "C_SE_NC_1",   # Set-point, short floating point
    51: "C_BO_NA_1",   # Bitstring of 32 bits command
    # CP56Time2a variants (58-64)
    58: "C_SC_TA_1",   # Single command with CP56Time2a
    59: "C_DC_TA_1",   # Double command with CP56Time2a
    60: "C_RC_TA_1",   # Regulating step command with CP56Time2a
    61: "C_SE_TA_1",   # Set-point, normalized with CP56Time2a
    62: "C_SE_TB_1",   # Set-point, scaled with CP56Time2a
    63: "C_SE_TC_1",   # Set-point, short float with CP56Time2a
    64: "C_BO_TA_1",   # Bitstring command with CP56Time2a
}

# System information in monitor direction (TypeID 70)
SYSTEM_MONITOR_TYPEIDS: dict[int, str] = {
    70: "M_EI_NA_1",   # End of initialization
}

# System information in control direction (TypeID 100-107)
SYSTEM_CONTROL_TYPEIDS: dict[int, str] = {
    100: "C_IC_NA_1",  # Interrogation command
    101: "C_CI_NA_1",  # Counter interrogation command
    102: "C_RD_NA_1",  # Read command
    103: "C_CS_NA_1",  # Clock synchronization command
    104: "C_TS_NA_1",  # Test command
    105: "C_RP_NA_1",  # Reset process command
    106: "C_CD_NA_1",  # Delay acquisition command
    107: "C_TS_TA_1",  # Test command with CP56Time2a
}

# Parameter (TypeID 110-113)
PARAMETER_TYPEIDS: dict[int, str] = {
    110: "P_ME_NA_1",  # Parameter of measured value, normalized
    111: "P_ME_NB_1",  # Parameter of measured value, scaled
    112: "P_ME_NC_1",  # Parameter of measured value, short float
    113: "P_AC_NA_1",  # Parameter activation
}

# File transfer (TypeID 120-127)
FILE_TRANSFER_TYPEIDS: dict[int, str] = {
    120: "F_FR_NA_1",  # File ready
    121: "F_SR_NA_1",  # Section ready
    122: "F_SC_NA_1",  # Call directory/section/file
    123: "F_LS_NA_1",  # Last section/segment
    124: "F_AF_NA_1",  # ACK file/section
    125: "F_SG_NA_1",  # Segment
    126: "F_DR_TA_1",  # Directory
    127: "F_SC_NB_1",  # QueryLog (request archive file)
}

ALL_VALID_TYPEIDS: set[int] = (
    set(MONITOR_TYPEIDS)
    | set(COMMAND_TYPEIDS)
    | set(SYSTEM_MONITOR_TYPEIDS)
    | set(SYSTEM_CONTROL_TYPEIDS)
    | set(PARAMETER_TYPEIDS)
    | set(FILE_TRANSFER_TYPEIDS)
)

TYPEID_NAMES: dict[int, str] = {
    **MONITOR_TYPEIDS,
    **COMMAND_TYPEIDS,
    **SYSTEM_MONITOR_TYPEIDS,
    **SYSTEM_CONTROL_TYPEIDS,
    **PARAMETER_TYPEIDS,
    **FILE_TRANSFER_TYPEIDS,
}


def classify_typeid(type_id: int) -> TypeIDGroup | None:
    """Classify a TypeID into its protocol group."""
    if 1 <= type_id <= 44:
        return TypeIDGroup.MONITOR_PROCESS
    if 45 <= type_id <= 69:
        return TypeIDGroup.CONTROL_PROCESS
    if 70 <= type_id <= 99:
        return TypeIDGroup.SYSTEM_MONITOR
    if 100 <= type_id <= 109:
        return TypeIDGroup.SYSTEM_CONTROL
    if 110 <= type_id <= 119:
        return TypeIDGroup.PARAMETER
    if 120 <= type_id <= 127:
        return TypeIDGroup.FILE_TRANSFER
    return None


# ---------------------------------------------------------------------------
# Cause of Transmission (COT) codes (IEC 60870-5-101, clause 7.2.3)
# ---------------------------------------------------------------------------

COT_CODES: dict[int, str] = {
    0: "not_used",
    1: "periodic_cyclic",
    2: "background_scan",
    3: "spontaneous",
    4: "initialized",
    5: "request",
    6: "activation",
    7: "activation_confirm",
    8: "deactivation",
    9: "deactivation_confirm",
    10: "activation_termination",
    11: "return_info_remote_cmd",
    12: "return_info_local_cmd",
    13: "file_transfer",
    # 14-19: reserved for future compatible definitions
    20: "interrogated_by_station",
    21: "interrogated_by_group_1",
    22: "interrogated_by_group_2",
    23: "interrogated_by_group_3",
    24: "interrogated_by_group_4",
    25: "interrogated_by_group_5",
    26: "interrogated_by_group_6",
    27: "interrogated_by_group_7",
    28: "interrogated_by_group_8",
    29: "interrogated_by_group_9",
    30: "interrogated_by_group_10",
    31: "interrogated_by_group_11",
    32: "interrogated_by_group_12",
    33: "interrogated_by_group_13",
    34: "interrogated_by_group_14",
    35: "interrogated_by_group_15",
    36: "interrogated_by_group_16",
    37: "counter_interrogated_by_station",
    38: "counter_interrogated_by_group_1",
    39: "counter_interrogated_by_group_2",
    40: "counter_interrogated_by_group_3",
    41: "counter_interrogated_by_group_4",
    # 42-43: reserved
    44: "unknown_type_identification",
    45: "unknown_cause_of_transmission",
    46: "unknown_common_address",
    47: "unknown_ioa",
}

# COTs that are valid (non-reserved, non-error)
STANDARD_COTS: set[int] = set(range(1, 14)) | set(range(20, 42))
RESERVED_COTS: set[int] = {0, 14, 15, 16, 17, 18, 19, 42, 43}
ERROR_COTS: set[int] = {44, 45, 46, 47}
PRIVATE_COT_RANGE: tuple[int, int] = (48, 63)  # 48-63 for special use

# Zeek string→numeric COT mapping (Zeek IEC-104 parser outputs strings)
ZEEK_COT_STRING_MAP: dict[str, int] = {
    "Percyc": 1, "per/cyc": 1, "periodic": 1,
    "Back": 2, "back": 2, "background": 2,
    "Spont": 3, "spont": 3, "spontaneous": 3,
    "Init": 4, "init": 4, "initialized": 4,
    "Req": 5, "req": 5, "request": 5,
    "Act": 6, "act": 6, "activation": 6,
    "ActCon": 7, "actcon": 7, "activation_confirm": 7,
    "Deact": 8, "deact": 8, "deactivation": 8,
    "DeactCon": 9, "deactcon": 9, "deactivation_confirm": 9,
    "ActTerm": 10, "actterm": 10, "activation_termination": 10,
    "Retrem": 11, "retrem": 11,
    "Retloc": 12, "retloc": 12,
    "File": 13, "file": 13,
    "Inrogen": 20, "inrogen": 20, "interrogated_by_station": 20,
    "Inro1": 21, "Inro2": 22, "Inro3": 23, "Inro4": 24,
    "Inro5": 25, "Inro6": 26, "Inro7": 27, "Inro8": 28,
    "Inro9": 29, "Inro10": 30, "Inro11": 31, "Inro12": 32,
    "Inro13": 33, "Inro14": 34, "Inro15": 35, "Inro16": 36,
    "Reqcogen": 37, "reqcogen": 37,
    "Reqco1": 38, "Reqco2": 39, "Reqco3": 40, "Reqco4": 41,
}


# ---------------------------------------------------------------------------
# Valid TypeID × COT matrix (from IEC 60870-5-101, Table 14)
# ---------------------------------------------------------------------------

# Monitor process information: valid COTs per TypeID
_MONITOR_COTS_BASIC = {1, 2, 3, 5, 11, 12, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36}
_MONITOR_COTS_TIME = {3, 5, 11, 12}  # Time-tagged types: typically spontaneous + request
_INTEGRATED_TOTALS_COTS = {3, 37, 38, 39, 40, 41}
_PROTECTION_COTS = {3}  # Protection events are spontaneous only

# Command process information: valid COTs
_COMMAND_COTS = {6, 7, 8, 9, 10, 44, 45, 46, 47}

# System information COTs
_INIT_COTS = {4}  # M_EI_NA_1: initialized only
_INTERROGATION_COTS = {6, 7, 8, 9, 10}
_READ_COTS = {5}
_CLOCK_SYNC_COTS = {3, 6, 7}
_TEST_COTS = {6, 7}
_RESET_COTS = {6, 7}
_PARAMETER_COTS = {6, 7, 9, 10, 20}

VALID_TYPEID_COT: dict[int, set[int]] = {}

# Populate monitor TypeIDs
for tid in [1, 3, 5, 7, 9, 11, 13, 20, 21]:
    VALID_TYPEID_COT[tid] = _MONITOR_COTS_BASIC.copy()
for tid in [2, 4, 6, 8, 10, 12, 14]:
    VALID_TYPEID_COT[tid] = _MONITOR_COTS_TIME.copy()
for tid in [30, 31, 32, 33, 34, 35, 36]:
    VALID_TYPEID_COT[tid] = _MONITOR_COTS_TIME.copy()
for tid in [15, 16, 37]:
    VALID_TYPEID_COT[tid] = _INTEGRATED_TOTALS_COTS.copy()
for tid in [17, 18, 19, 38, 39, 40]:
    VALID_TYPEID_COT[tid] = _PROTECTION_COTS.copy()

# Populate command TypeIDs
for tid in list(COMMAND_TYPEIDS.keys()):
    VALID_TYPEID_COT[tid] = _COMMAND_COTS.copy()

# System TypeIDs
VALID_TYPEID_COT[70] = _INIT_COTS
VALID_TYPEID_COT[100] = _INTERROGATION_COTS  # C_IC_NA_1
VALID_TYPEID_COT[101] = _INTERROGATION_COTS  # C_CI_NA_1
VALID_TYPEID_COT[102] = _READ_COTS           # C_RD_NA_1
VALID_TYPEID_COT[103] = _CLOCK_SYNC_COTS     # C_CS_NA_1
VALID_TYPEID_COT[104] = _TEST_COTS           # C_TS_NA_1
VALID_TYPEID_COT[105] = _RESET_COTS          # C_RP_NA_1
VALID_TYPEID_COT[106] = {6, 7}               # C_CD_NA_1
VALID_TYPEID_COT[107] = _TEST_COTS           # C_TS_TA_1

# Parameter TypeIDs
for tid in [110, 111, 112]:
    VALID_TYPEID_COT[tid] = _PARAMETER_COTS.copy()
VALID_TYPEID_COT[113] = {6, 7, 8, 9, 10}

# File transfer TypeIDs
for tid in list(FILE_TRANSFER_TYPEIDS.keys()):
    VALID_TYPEID_COT[tid] = {13}


def is_valid_typeid_cot(type_id: int, cot: int) -> bool:
    """Check if a TypeID+COT combination is valid per the protocol spec."""
    valid_cots = VALID_TYPEID_COT.get(type_id)
    if valid_cots is None:
        return False  # Unknown TypeID
    return cot in valid_cots


def is_command_typeid(type_id: int) -> bool:
    """Check if a TypeID is a command (control direction)."""
    return type_id in COMMAND_TYPEIDS


def is_monitor_typeid(type_id: int) -> bool:
    """Check if a TypeID is a monitor (monitoring direction)."""
    return type_id in MONITOR_TYPEIDS


def get_typeid_name(type_id: int) -> str:
    """Get human-readable name for a TypeID."""
    return TYPEID_NAMES.get(type_id, f"UNKNOWN_{type_id}")


def parse_cot(cot_value: str | int) -> int | None:
    """Parse a COT value from Zeek string or numeric form."""
    if isinstance(cot_value, int):
        return cot_value
    if isinstance(cot_value, float):
        return int(cot_value) if not (cot_value != cot_value) else None  # NaN check
    cot_str = str(cot_value).strip()
    if cot_str.isdigit():
        return int(cot_str)
    return ZEEK_COT_STRING_MAP.get(cot_str)


# ---------------------------------------------------------------------------
# Known attack signatures from real-world incidents
# ---------------------------------------------------------------------------

INDUSTROYER2_INDICATORS = {
    "description": "Industroyer2 IEC-104 attack patterns (Ukraine 2022)",
    "command_typeids": {45, 46},  # C_SC_NA_1 and C_DC_NA_1
    "typical_cot": 6,  # Activation
    "timing_pattern_sec": 3.0,  # Fixed 3-second inter-command delay
    "targets_multiple_stations": True,
    "ignores_responses": True,
}

# Standard port for IEC-104
IEC104_STANDARD_PORT = 2404
