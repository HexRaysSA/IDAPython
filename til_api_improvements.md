
# udm_t(name: str, type, offset: int = -1) : udm_t

    # Create a structure/union member, with the specified name
    # and type.
    #
    # The size will be computed automatically.
    #
    # @param name a valid member name. Must not be empty.
    # @param type the member type. the type can be specified one of the following ways:
    #              - type_t if the type is simple (integral/floating/bool);
    #              - tinfo_t a more complex type, like a pointer, array, etc;
    #              - string as a C type declaration.
    # @param offset the member offset in bits. It is the caller's responsibility
    #              to specify correct offsets.
    # if an input argument is incorrect, the constructor may raise an exception

# tinfo_t.find_udm_by_name(name: str) : (idx, udm_t) | (-1, None)

    # Retrieve a structure/union member (and its index) with the
    # specified name in the specified tinfo_t object.
    #
    # @param name Member name. Must not be empty.
    # @returns a tuple (int, udm_t), or (-1, None) if member not found.

* CL#156578 - first attempt, w/o the index

# tinfo_t.add_udm(name: str, type: tinfo_t | type_t | str, offset: int = -1) : udm_t

    # Add a new member to a structure/union type, with the specified name and type.
    #
    # The size will be computed automatically.
    # The new member must not overlap with the existing members.
    # if an input argument is incorrect, the constructor may raise an exception
    #
    # @param name Member name. Must not be empty.
    # @param type Member type. Can be specified one of the following ways:
    #              - type_t if the type is simple (integral/floating/bool);
    #              - tinfo_t a more complex type, like a pointer, array, etc;
    #              - string as a C type declaration.
    # @param offset  Member offset in bits. If specified as -1, the new member
    #                is added at the end of the structure/union.
    # @returns member object

