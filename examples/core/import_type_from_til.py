"""
summary: Progarmatically load a til and a type.

description:
   The goal of this script is to demonstrate some usage of the type API.
    In this script, we:
    * ask the user for a specific til to be lodaed
    * if successfully loaded ask the user for a type name to be imported.
    * append the type to the local types.

level: intermediate.
"""
import ida_netnode
import ida_typeinf
import ida_kernwin

def main():
    til_name = ida_kernwin.ask_str("Dummy til name", 0, "Enter a til filename:")
    if not til_name:
        print("No til name provided.")
        return

    ret = ida_typeinf.add_til(til_name, ida_typeinf.ADDTIL_DEFAULT)
    if ret == ida_typeinf.TIL_ADD_OK or ret == ida_typeinf.TIL_ADD_ALREADY:
        type_name = ida_kernwin.ask_str("Dummy type name", 0, "Enter a type name")
        if type_name:
            tid = ida_netnode.BADNODE
            tif = ida_typeinf.tinfo_t()
            if tif.get_named_type(None, type_name):
                tid = tif.force_tid()
            if tid == ida_netnode.BADNODE:
                print(f"{type_name} type import failed.")
            else:
                print(f"{type_name} type has been imported.")
        else:
            print(f"No type name provided.")
    else:
        print(f"{til_name} not added.")


main()
