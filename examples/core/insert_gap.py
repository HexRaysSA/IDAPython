"""
summary: Programatically insert a gap of specified size at specified
    offset.

description:
    The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * Create a function that takes three arguments: a structure name,
    an offset in bytes and a size in byte.
    * In this function we first retrieve the type info object of the structure,
    get the udt details, find the idx of the member at the specified offset,
    create a gap "member" using udm_t__make_gap(), insert it into the udt object,
    create the udt inside the tif object and finally save the type information.
    * To exercise this script just change the name of the structure to the one
    that suites you.
"""
import ida_typeinf
import ida_kernwin

def insert_gap(struct_name: str, offset: int, size: int):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struct_name):
        print(f"Unable to get {struct_name} structure.")
        return False

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        print(f"Unable to retrieve details from {struct_name}.")
        return False

    udm = ida_typeinf.udm_t()
    udm.offset = offset * 8
    idx = udt.find_member(udm, ida_typeinf.STRMEM_OFFSET)
    if idx < 0:
        print(f"Unable to find index of member at offset {offset:x}.")
        return False

    udm = ida_typeinf.udm_t()
    if not ida_typeinf.udm_t__make_gap(udm, offset, size):
        print(f"Unable to create a gap @ offset {offset:x} of size {size:x}.")
        return False

    udt.insert(udt[idx] , udm)

    if not tif.create_udt(udt):
        print(f"Unable to create the tinfo_t UDT object.")
        return False

    err = ida_typeinf.save_tinfo(tif, None, tif.get_ordinal(), struct_name, ida_typeinf.NTF_TYPE | ida_typeinf.NTF_REPLACE)
    if err != ida_typeinf.TERR_OK:
        print(f"save_tinfo() failed with code {err:x}.")
        return False

    return True

if not insert_gap("_TraceLoggingMetadata_t", 8, 6):
    print("Failed to insert gaps.")
else:
    print("Done.")
