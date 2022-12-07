"""
This module contains the Transform class and is used for transforming disassembled bytecode
to create functionally equiavlent permutations.
"""

import json
import random
from semm_ops.registers import get_register_permutations
from semm_ops.assembly import Assembler
import re
from semm_ops.logging.logger import logger

class Transform:

    def __init__(self, operation_arr):

        """
        This class is used for transforming the operation_arr to create
        permutations of the assembly code that are functionally equivalent.
        """

        self.operation_arr = operation_arr


    def transform_registers(self):

        """
        This method transforms the operation_arr using every possible
        register combination and returns a permutated hex bytecode for each.
        """

        permutations = get_register_permutations()
        byte_codes = []
        assembler = Assembler()

        i = 0
        for perm in permutations:

            operation_arr = self.operation_arr.copy()

            for operation in operation_arr:
                rep = dict((re.escape(k), v) for k, v in perm.items())
                pattern = re.compile("|".join(perm.keys()))
                operation[1] = pattern.sub(lambda m: perm[re.escape(m.group(0))], operation[1])

            try:
                assembly_code = assembler.get_assembly_code(operation_arr)
                byte_code = assembler.reassemble(assembly_code)
                byte_codes.append(byte_code)
            except:
                logger.error("Permutation of operation_arr was not able to be parsed and converted to bytecode")


        return byte_codes
