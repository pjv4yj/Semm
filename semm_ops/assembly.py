"""
This module contains the Assembler class, which is used for reassembling
assembly into byte code for Antivirus and YARA classification
"""

from keystone import *
from semm_ops.logging.logger import logger

class Assembler:

    def __init__(self, arch=KS_ARCH_X86, mode=KS_MODE_32):

        """
        Arguments:
            arch: Architecture to provide to Keystone for Assembly
            mode: Mode to provide to Keystone for Assembly

        Attributes:
            arch: Variable storing argument, arch
            mode: Variable storing argument, mode
        """

        self.arch = arch
        self.mode = mode


    def reassemble(self, assembly: str):

        """
        This function takes in a string of assembly code,
        and converts it to the equivalent byte code for classification by
        Antivirus software.

        Arguments:
            assembly(str): String containing assembly to convert to bytecode

        Returns:
            byte_str(str): String containing bytecode that represents assembly code provided to function
        """

        ks = Ks(self.arch, self.mode) # Define Keystone Assembler

        ARM_BYTECODE, _ = ks.asm(assembly) # Generate Assembly Bytecode

        # Create Byte String for classification
        byte_str = ""
        for num in ARM_BYTECODE:
            byte_str = byte_str + f'{num:x}'

        return byte_str


    def get_assembly_code(self, operation_list: list):

        """
        Arguments:
            operation_list(list): Python List of tuples containing each instruction's mnemonic and op_str

        Returns:
            full_string(str): A full string of new line separated assembly commands
        """

        full_string = ""

        num_ops = 0

        for operation in operation_list: # Iterating through each operation in list

            op_str = operation[1]
            mnemonic = str(operation[0])

            code_string = mnemonic + " " + op_str # full assembly instruction

            if num_ops == len(operation_list) - 1:
                full_string = full_string + code_string
            else:
                full_string = full_string + code_string + "\n"

            num_ops += 1

        return full_string
