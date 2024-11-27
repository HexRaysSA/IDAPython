"""
summary: ida_struct.get_innermost_member altenative.

description:
    The goal of this script is to provide/test an alternative
    to ida_struct.get_innermost_member.

level: intermediate.
"""
import ida_typeinf
import ida_idaapi

def get_innermost_member(sid, offset):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(sid) and tif.is_udt():
        (mtif, idx, _) = tif.get_innermost_udm(offset * 8)
        udt = ida_typeinf.udt_type_data_t()
        if not idx == -1:
            if tif.get_udt_details(udt):
                return mtif, udt[idx]
    return None

struct_str = """struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};"""

ida_typeinf.del_named_type(None, "pcap_hdr_s", ida_typeinf.NTF_TYPE)
ida_typeinf.idc_parse_types(struct_str, 0)
tif = ida_typeinf.tinfo_t()
if not tif.get_named_type(None, "pcap_hdr_s"):
    print("Unable to retrieve pcap_hdr_s structure")

sid = tif.get_tid()

if sid != ida_idaapi.BADADDR:
    tuple = get_innermost_member(sid, 5)
    if tuple is not None:
        tif, udm = tuple
        print(f"get_innermost_member returned udm {udm.name}")
    else:
        print("get_innermost_member returned None :()")
