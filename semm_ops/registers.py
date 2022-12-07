import itertools

def get_register_permutations():

    """
    This function generates every register permutation for x86 registers
    """

    permutations = []

    registers = ["a","b","c","d"]

    register_iterations = list(itertools.permutations(registers))

    for perm in register_iterations:

        permutation = {}
        i = 0
        for register in perm:
            match register:
                case "a":
                    if i == 0:
                        permutation["eax"] = "eax"
                        permutation["ax"] = "ax"
                        permutation["ah"] = "ah"
                        permutation["al"] = "al"
                    elif i == 1:
                        permutation["ebx"] = "eax"
                        permutation["bx"] = "ax"
                        permutation["bh"] = "ah"
                        permutation["bl"] = "al"
                    elif i == 2:
                        permutation["ecx"] = "eax"
                        permutation["cx"] = "ax"
                        permutation["ch"] = "ah"
                        permutation["cl"] = "al"
                    else:
                        permutation["edx"] = "eax"
                        permutation["dx"] = "ax"
                        permutation["dh"] = "ah"
                        permutation["dl"] = "al"
                case "b":
                    if i == 0:
                        permutation["eax"] = "ebx"
                        permutation["ax"] = "bx"
                        permutation["ah"] = "bh"
                        permutation["al"] = "bl"
                    elif i == 1:
                        permutation["ebx"] = "ebx"
                        permutation["bx"] = "bx"
                        permutation["bh"] = "bh"
                        permutation["bl"] = "bl"
                    elif i == 2:
                        permutation["ecx"] = "ebx"
                        permutation["cx"] = "bx"
                        permutation["ch"] = "bh"
                        permutation["cl"] = "bl"
                    else:
                        permutation["edx"] = "ebx"
                        permutation["dx"] = "bx"
                        permutation["dh"] = "bh"
                        permutation["dl"] = "bl"
                case "c":
                    if i == 0:
                        permutation["eax"] = "ecx"
                        permutation["ax"] = "cx"
                        permutation["ah"] = "ch"
                        permutation["al"] = "cl"
                    elif i == 1:
                        permutation["ebx"] = "ecx"
                        permutation["bx"] = "cx"
                        permutation["bh"] = "ch"
                        permutation["bl"] = "cl"
                    elif i == 2:
                        permutation["ecx"] = "ecx"
                        permutation["cx"] = "cx"
                        permutation["ch"] = "ch"
                        permutation["cl"] = "cl"
                    else:
                        permutation["edx"] = "ecx"
                        permutation["dx"] = "cx"
                        permutation["dh"] = "ch"
                        permutation["dl"] = "cl"
                case "d":
                    if i == 0:
                        permutation["eax"] = "edx"
                        permutation["ax"] = "dx"
                        permutation["ah"] = "dh"
                        permutation["al"] = "dl"
                    elif i == 1:
                        permutation["ebx"] = "edx"
                        permutation["bx"] = "dx"
                        permutation["bh"] = "dh"
                        permutation["bl"] = "dl"
                    elif i == 2:
                        permutation["ecx"] = "edx"
                        permutation["cx"] = "dx"
                        permutation["ch"] = "dh"
                        permutation["cl"] = "dl"
                    else:
                        permutation["edx"] = "edx"
                        permutation["dx"] = "dx"
                        permutation["dh"] = "dh"
                        permutation["dl"] = "dl"
                case _:
                    pass

            i += 1

        permutations.append(permutation)

    return permutations
