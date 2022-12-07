"""
This module contains the Disassembler class, which is used for disassembling
a PE file and returning an instruction list from the file.
"""

from capstone import *
from capstone.x86 import *
import pefile
from semm_ops.logging.logger import logger

class Disassembler:

    def __init__(self, arch=CS_ARCH_X86, mode=CS_MODE_32):

        """
        Diassembler class for taking a PE File as input and disassembling
        its instruction code.

        Arguments:
            arch: Architecture to provide to Captsone for disassembly
            mode: Mode to provide to Captsone for disassembly

        Attributes:
            arch: Variable storing argument, arch
            mode: Variable storing argument, mode
        """

        self.arch = arch
        self.mode = mode

    def fine_disassemble(self, pe, num_bytes=300):

        """
        Method for disassembling instruction code for a specified number of bytes

        Arguments:
            pe(PE): PE python file object representing EXE File
            num_bytes(int): Number of bytes of instruction code to return

        Returns:
            operation_arr(list): List of all x86 instructions in the file within num_bytes
        """

        operation_arr = []

        entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        entrypoint_address = entrypoint+pe.OPTIONAL_HEADER.ImageBase

        binary_code = pe.get_memory_mapped_image()[entrypoint:entrypoint+num_bytes]

        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)

        disassembler.skipdata = True
        disassembler.detail = True

        for instruction in disassembler.disasm(binary_code, entrypoint_address):
            operation_arr.append([instruction.mnemonic, instruction.op_str])

        return operation_arr

    def get_instruction_list(self, file, num_bytes=300):

        """
        This function converts the file into a python PE file,
        and uses the self.fine_disassemble() method to disassemble
        and return an instruction list.

        Arguments:
            file(str): Filepath to EXE file to disassemble (such as '/Users/pjv/Desktop/sample.exe')
        Returns:
            operation_arr(list): List returned by method, fine_disassemble()
        """

        try:
            exe = pefile.PE(file)
        except:
            logger.info("EXE file is not able to be parsed by python pefile library. Please choose another file.")
            exit()
        operation_arr_res = self.fine_disassemble(exe,num_bytes)
        operation_arr = []

        for operation in operation_arr_res:
            if operation[0] != "insb":
                operation_arr.append(operation)

        logger.info("Disassembly Complete, returning result")
        return operation_arr
