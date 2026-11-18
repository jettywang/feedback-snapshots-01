# -------------------------------------------------------------------------------
# elftools: ehabi/constants.py
#
# Constants for the ARM exception handler ABI.
#
# This code is in the public domain
# -------------------------------------------------------------------------------

EHABI_INDEX_ENTRY_SIZE: int = 8

# PREL31 is a 31-bit signed offset in which bit 31 is always zero. The sign
# bit is therefore bit 30, not bit 26.
PREL31_VALUE_MASK: int = 0x7fffffff
PREL31_SIGN_BIT: int = 0x40000000
PREL31_SIGN_EXTEND: int = 0xffffffff80000000

# Word 1 of an .ARM.exidx entry equal to EXIDX_CANTUNWIND means that the
# function cannot be unwound.
EXIDX_CANTUNWIND: int = 1
