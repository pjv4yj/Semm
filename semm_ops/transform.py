"""
"""

import json
import random
from semm_ops.registers import get_register_permutations
from semm_ops.assembly import Assembler
import re
import copy

class Transform:

    def __init__(self, operation_arr):

        """
        """

        self.operation_arr = operation_arr


    def transform_registers(self):

        """
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

            assembly_code = assembler.get_assembly_code(operation_arr)
            byte_code = assembler.reassemble(assembly_code)
            byte_codes.append(byte_code)
            #except:
                #print("Error")
                #continue

        return byte_codes
