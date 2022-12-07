"""
"""

import json
import random
from semm_ops.registers import get_register_permutations
from semm_ops.assembly import Assembler
import re

class Transform:

    def __init__(self, operation_arr):

        """
        """

        self.operation_arr = operation_arr


    def transform_registers(self):

        """
        """

        permutations = get_register_permutations()
        a = Assembler()

        i = 0
        for perm in permutations:

            operation_arr = self.operation_arr.copy()

            for operation in operation_arr:
                rep = dict((re.escape(k), v) for k, v in perm.items())
                pattern = re.compile("|".join(perm.keys()))
                operation[1] = pattern.sub(lambda m: perm[re.escape(m.group(0))], operation[1])

            full_string = a.get_assembly_code(operation_arr)
            try:
                byte_str = a.reassemble(full_string)
                print(byte_str)
            except:
                print("Error")
                continue
