"""
summary: Programatically create structures.

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we create a structure using the "parsing" method.

level: beginner
"""
import ida_typeinf

# Create a struct with parsing.
struct_str = """
typedef int int32_t;
typedef unsigned int uint32_t;

struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};
"""

main_struct_name = "pcap_hdr_s"

# Delete the structure in case it already exist.
ida_typeinf.del_named_type(None, main_struct_name, ida_typeinf.NTF_TYPE)

# Parse & register all types present in the text above
ida_typeinf.idc_parse_types(struct_str, 0)

tif = ida_typeinf.get_idati().get_named_type(main_struct_name)
if tif is None:
    raise Exeption("Failed to retrieve %s" % main_struct_name)
print("Got: %s" % tif._print())
