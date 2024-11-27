"""
summary: Programatically list a user selected enumeration.

description: 
    The goal of this script is to demaonstrate how to
    programatically list members of an enumeration. For
    this we:
    * ask the user to enter the of an enumeration
    * verify that the entered name is indeed aan enumeration
    * get the enumeration details object
    * enumerate the members.

level: beginner
"""
import ida_kernwin
import ida_typeinf

name = ida_kernwin.ask_str("Dummy enum", 0, "Enter an enum name:")
if name is not None:
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name, ida_typeinf.BTF_ENUM, True, False):
        print(f"'{name}' is not an enum")
    elif tif.is_typedef():
        print(f"'{name}' is not a (non typedefed) enum.")
    else:
        edt = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(edt):
            bitfield = ""
            if edt.is_bf():
                bitfield = "(bitfield)"
            print(f"Listing the '{name}' {bitfield} enum {edt.size()} field names:")
            for idx, edm in enumerate(edt):
                print(f"Field {idx}: {edm.name} = 0x{edm.value:x}")
        else:
            print(f"Unable to get udt details for enum '{name}'")
