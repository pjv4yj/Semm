from capstone import *
from capstone.x86 import *
import pefile
from semm_ops.logging.logger import logger


class Disassembler:

    def __init__(self, arch=CS_ARCH_X86, mode=CS_MODE_32):

        """
        Disassembler class built from reference found here:
        https://isleem.medium.com/create-your-own-disassembler-in-python-pefile-capstone-754f863b2e1c
        by Islem Bouzenia

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
        Arguments:
            file(str): Filepath to EXE file to disassemble (such as '/Users/pjv/Desktop/sample.exe')

        Returns:
            operation_arr(list): List returned by method, fine_disassemble()
        """

        exe = pefile.PE(file)
        operation_arr_res = self.fine_disassemble(exe,num_bytes)
        operation_arr = []

        for operation in operation_arr_res:
            if operation[0] != "insb":
                operation_arr.append(operation)

        logger.info("Disassembly Complete, returning result")
        return operation_arr
