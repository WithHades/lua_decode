import struct
from enum import Enum

SIZE_C = 9
SIZE_B = 9
SIZE_Bx = SIZE_C + SIZE_B
SIZE_A = 8
SIZE_Ax = SIZE_C + SIZE_B + SIZE_A

SIZE_OP = 6

POS_OP = 0
POS_A = POS_OP + SIZE_OP
POS_C = POS_A + SIZE_A
POS_B = POS_C + SIZE_C
POS_Bx = POS_C
POS_Ax = POS_A

MAXARG_Bx = (1 << SIZE_Bx) - 1
MAXARG_sBx = MAXARG_Bx >> 1

BITRK = (1 << (SIZE_B - 1))


class opCode(Enum):
    OP_MOVE = 0
    OP_LOADK = 1
    OP_LOADBOOL = 2
    OP_LOADNIL = 3
    OP_GETUPVAL = 4
    OP_GETGLOBAL = 5
    OP_GETTABLE = 6
    OP_SETGLOBAL = 7
    OP_SETUPVAL = 8
    OP_SETTABLE = 9
    OP_NEWTABLE = 10
    OP_SELF = 11
    OP_ADD = 12
    OP_SUB = 13
    OP_MUL = 14
    OP_DIV = 15
    OP_MOD = 16
    OP_POW = 17
    OP_UNM = 18
    OP_NOT = 19
    OP_LEN = 20
    OP_CONCAT = 21
    OP_JMP = 22
    OP_EQ = 23
    OP_LT = 24
    OP_LE = 25
    OP_TEST = 26
    OP_TESTSET = 27
    OP_CALL = 28
    OP_TAILCALL = 29
    OP_RETURN = 30
    OP_FORLOOP = 31
    OP_FORPREP = 32
    OP_TFORLOOP = 33
    OP_SETLIST = 34
    OP_CLOSE = 35
    OP_CLOSURE = 36
    OP_VARARG = 37


class LUA_DATATYPE(Enum):
    LUA_TNONE = -1
    LUA_TNIL = 0
    LUA_TBOOLEAN = 1
    LUA_TLIGHTUSERDATA = 2
    LUA_TNUMBER = 3
    LUA_TSTRING = 4
    LUA_TTABLE = 5
    LUA_TFUNCTION = 6
    LUA_TUSERDATA = 7
    LUA_TTHREAD = 8


def GETARG_A(inst):
    return (inst >> POS_A) & ((~((~0) << SIZE_A)) << 0)


def GETARG_B(inst):
    return (inst >> POS_B) & ((~((~0) << SIZE_B)) << 0)


def GETARG_C(inst):
    return (inst >> POS_C) & ((~((~0) << SIZE_C)) << 0)


def GETARG_Ax(inst):
    return (inst >> POS_Ax) & ((~((~0) << SIZE_Ax)) << 0)


def GETARG_Bx(inst):
    return (inst >> POS_Bx) & ((~((~0) << SIZE_Bx)) << 0)


def GETARG_sBx(inst):
    return GETARG_Bx(inst) - MAXARG_sBx


def getOpCode(inst):
    return (inst >> POS_OP) & ((~((~0) << SIZE_OP)) << 0)


def ISK(r):
    return r & BITRK


def INDEX(r):
    return r & ~BITRK


def CC(r):
    return 'K' if ISK(r) else 'R'


def CV(r):
    return INDEX(r) if ISK(r) else r


def decode(bytes):
    index = 0

    # decode lua_header
    global_header = bytes[index:index + 12]
    index += 12

    signature, version, format, endian, size_int, size_size_t, size_Instruction, size_lua_Number, lua_num_valid = struct.unpack(
        "4sBBBBBBBB", global_header)

    if not signature == b'\x1B\x4C\x75\x61':
        print('It\'s may not a luac file!')
        return

    if not version == 0x51:
        print('It\'s not 0x51 version!')
        return

    if not format == 0:
        print('It\'s not official file, decoding the file may makes errors!')
        return

    # decision the byteorder
    if endian == 1:
        byteorder = 'little'
    else:
        byteorder = 'big'

    len_source = int.from_bytes(bytes[index:index + 4], byteorder=byteorder)
    index += 4
    if len_source > 0:
        source = str(bytes[index:index + len_source], encoding='gbk')
        index += len_source
        print('source:', source)

    protoHeader = bytes[index:index + 12]
    index += 12
    linedefined, lastlinedefined, nups, numparams, is_vararg, maxstacksize = struct.unpack("IIBBBB", protoHeader)
    print("linedefined:", linedefined)
    print("nups:", nups)
    print("is_vararg:", is_vararg)
    print("maxstacksize:", maxstacksize)

    sizecode = int.from_bytes(bytes[index:index + 4], byteorder=byteorder)
    index += 4

    # save the index of code
    code_index = index

    # Skip the code's segment and translate the rest first
    index += 4 * sizecode

    # decode the constants
    sizek = int.from_bytes(bytes[index:index + 4], byteorder=byteorder)
    index += 4
    constants = []
    for i in range(sizek):
        constant_type = int.from_bytes(bytes[index:index + 1], byteorder=byteorder)
        index += 1
        if constant_type == LUA_DATATYPE.LUA_TNIL.value:
            constants.append('tnil')
        elif constant_type == LUA_DATATYPE.LUA_TBOOLEAN.value:
            bool_val = int.from_bytes(bytes[index:index + 1], byteorder=byteorder)
            index += 1
            constants.append('FALSE' if bool_val == 0 else 'TRUE')
        elif constant_type == LUA_DATATYPE.LUA_TNUMBER.value:
            number = int.from_bytes(bytes[index:index + 8], byteorder=byteorder)
            index += 8
            constants.append(number)
        elif constant_type == LUA_DATATYPE.LUA_TSTRING.value:
            str_size = int.from_bytes(bytes[index:index + 4], byteorder=byteorder)
            index += 4
            constants.append(str(bytes[index:index + str_size - 1], encoding='gbk'))
            index += str_size
        else:
            assert False, 'other constants!'

    def RK(r):
        if ISK(r):
            value = '\"{}\"'.format(constants[INDEX(r)])
        else:
            value = 'R{}'.format(r)
        return value

    # decode the code's segment
    codes_line = []
    index = code_index
    for i in range(1, sizecode + 1):
        inst = int.from_bytes(bytes[index:index + 4], byteorder=byteorder)
        index += 4

        op_code = opCode(getOpCode(inst))

        a = GETARG_A(inst)
        b = GETARG_B(inst)
        c = GETARG_C(inst)
        bc = GETARG_Bx(inst)
        sbc = GETARG_sBx(inst)

        if op_code == opCode.OP_MOVE:
            codes_line.append('{}\t[-]:{}\tR{},R{}\t; R{} := R{}'.format(i, op_code.name[3:], a, b, a, b))

        elif op_code == opCode.OP_LOADK:
            if type(constants[bc]) == str:
                codes_line.append(
                    '{}\t[-]:{}\tR{},K{}\t; R{} := \"{}\"'.format(i, op_code.name[3:], a, bc, a, constants[bc]))
            else:
                codes_line.append(
                    '{}\t[-]:{}\tR{},K{}\t; R{} := {}'.format(i, op_code.name[3:], a, bc, a, constants[bc]))

        elif op_code == opCode.OP_LOADBOOL:
            if c:
                codes_line.append(
                    '{}\t[-]:{}\tR{},{},R{}\t; R{} := {}; goto [{}]'.format(i, op_code.name[3:], a, b, c, a,
                                                                            'TRUE' if b else 'FALSE', i + 2))
            else:
                codes_line.append('{}\t[-]:{}\tR{},{},R{}\t; R{} := {}'.format(i, op_code.name[3:], a, b, c, a,
                                                                               'TRUE' if b else 'FALSE'))

        elif op_code == opCode.OP_LOADNIL:
            if a + b > a:
                codes_line.append('{}\t[-]:{}\tR{},{}\t; R{} to R{} := nil'.format(i, op_code.name[3:], a, b, a, a + b))
            else:
                codes_line.append('{}\t[-]:{}\tR{},{}\t; R{} := nil'.format(i, op_code.name[3:], a, b, a))

        elif op_code == opCode.OP_GETUPVAL:
            codes_line.append('{}\t[-]:{}\tR{},U{}\t; R{} := U{}'.format(i, op_code.name[3:], a, b, a, b))

        elif op_code == opCode.OP_GETGLOBAL:
            codes_line.append('{}\t[-]:{}\tR{},K{}\t; R{} := {}'.format(i, op_code.name[3:], a, bc, a, constants[bc]))

        elif op_code == opCode.OP_GETTABLE:
            codes_line.append(
                '{}\t[-]:{}\tR{},R{},{}{}\t; R{} := R{}[{}]'.format(i, op_code.name[3:], a, b, CC(c), CV(c), a,
                                                                    b, RK(c)))

        elif op_code == opCode.OP_SETGLOBAL:
            codes_line.append('{}\t[-]:{}\tR{},K{}\t; {} := R{}'.format(i, op_code.name[3:], a, bc, constants[bc], a))

        elif op_code == opCode.OP_SETUPVAL:
            codes_line.append('{}\t[-]:{}\tR{},U{}\t; U{} := R{}'.format(i, op_code.name[3:], a, b, b, a))

        elif op_code == opCode.OP_SETTABLE:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{}[{}] := {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c), CV(c),
                                                                    a, RK(b), RK(c)))

        elif op_code == opCode.OP_NEWTABLE:
            codes_line.append(
                '{}\t[-]:{}\tR{},{},{}\t; R{} := {{}}(size = {},{})'.format(i, op_code.name[3:], a, b, c, a, b, c))

        elif op_code == opCode.OP_SELF:
            codes_line.append(
                '{}\t[-]:{}\tR{},R{},{}{}\t; R{} := R{}; R{} := R{}[{}]'.format(i, op_code.name[3:], a, b, CC(c), CV(c),
                                                                                a + 1,
                                                                                b, a, b, RK(c)))

        elif op_code == opCode.OP_ADD:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{} := {} + {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c),
                                                                     CV(c), a, RK(b), RK(c)))

        elif op_code == opCode.OP_SUB:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{} := {} - {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c),
                                                                     CV(c), a, RK(b), RK(c)))

        elif op_code == opCode.OP_MUL:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{} := {} * {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c),
                                                                     CV(c), a, RK(b), RK(c)))

        elif op_code == opCode.OP_DIV:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{} := {} / {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c),
                                                                     CV(c), a, RK(b), RK(c)))

        elif op_code == opCode.OP_POW:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{} := {} % {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c),
                                                                     CV(c), a, RK(b), RK(c)))

        elif op_code == opCode.OP_MOD:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}{},{}{}\t; R{} := {} ^ {}'.format(i, op_code.name[3:], a, CC(b), CV(b), CC(c),
                                                                     CV(c), a, RK(b), RK(c)))

        elif op_code == opCode.OP_UNM:
            codes_line.append('{}\t[-]:{}\tR{},R{}\t; R{} := ~R{}'.format(i, op_code.name[3:], a, b, a, b))

        elif op_code == opCode.OP_NOT:
            codes_line.append('{}\t[-]:{}\tR{},R{}\t; R{} := not R{}'.format(i, op_code.name[3:], a, b, a, b))

        elif op_code == opCode.OP_LEN:
            codes_line.append('{}\t[-]:{}\tR{},R{}\t; R{} := length of R{}'.format(i, op_code.name[3:], a, b, a, b))

        elif op_code == opCode.OP_CONCAT:
            codes_line.append(
                '{}\t[-]:{}\tR{},R{},R{}\t; R{} := concat(R{} to R{})'.format(i, op_code.name[3:], a, b, c, a, b, c))

        elif op_code == opCode.OP_JMP:
            codes_line.append(
                '{}\t[-]:{}\t{}\t; PC += {}(goto [{}])'.format(i, op_code.name[3:], sbc, sbc, i + sbc + 1))

        elif op_code == opCode.OP_EQ:
            codes_line.append(
                '{}\t[-]:{}\t{},{}{},{}{}\t; if {} {} {} then goto [{}]'.format(i, op_code.name[3:],
                                                                                a, CC(b), CV(b), CC(c), CV(c), RK(b),
                                                                                '~=' if a else '==',
                                                                                RK(c), i + 2))

        elif op_code == opCode.OP_LT:
            codes_line.append(
                '{}\t[-]:{}\t{},{}{},{}{}\t; if {} {} {} then goto [{}]'.format(i, op_code.name[3:],
                                                                                a, CC(b), CV(b), CC(c), CV(c), RK(b),
                                                                                '>=' if a else '<',
                                                                                RK(c), i + 2))

        elif op_code == opCode.OP_LE:
            codes_line.append(
                '{}\t[-]:{}\t{},{}{},{}{}\t; if {} {} {} then goto [{}]'.format(i, op_code.name[3:],
                                                                                a, CC(b), CV(b), CC(c), CV(c), RK(b),
                                                                                '>' if a else '<=',
                                                                                RK(c), i + 2))

        elif op_code == opCode.OP_TEST:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}\t; if {}R{} then goto [{}]'.format(i, op_code.name[3:], a, c, '' if c else 'not ',
                                                                       a, i + 2))

        elif op_code == opCode.OP_TESTSET:
            codes_line.append(
                '{}\t[-]:{}\tR{},R{},{}\t; if {}R{} then R{} := R{} else goto [{}]'.format(i, op_code.name[3:], a, b, c,
                                                                                           'not ' if c else '', b, a, b,
                                                                                           i + 2))

        elif op_code == opCode.OP_CALL:

            if c > 2:
                temp_c = 'R{} to R{} := '.format(a, a + c - 2)
            elif c == 2:
                temp_c = 'R{} := '.format(a)
            elif c == 1:
                temp_c = ''
            else:
                temp_c = 'R{} to top'.format(a)

            if b > 2:
                temp_b = 'R{} to R{}'.format(a + 1, a + b - 1)
            elif b == 2:
                temp_b = 'R{}'.format(a + 1)
            elif b == 1:
                temp_b = ''
            else:
                temp_b = 'R{} to top'.format(a + 1)

            codes_line.append('{}\t[-]:{}\tR{},{},{}\t; {}R{}({})'.format(i, op_code.name[3:], a, b, c, temp_c, a, temp_b))

        elif op_code == opCode.OP_TAILCALL:
            if b > 2:
                temp_b = 'R{} to R{}'.format(a + 1, a + b - 1)
            elif b == 2:
                temp_b = 'R{}'.format(a + 1)
            elif b == 1:
                temp_b = ''
            else:
                temp_b = 'R{} to top'.format(a + 1)
            codes_line.append('{}\t[-]:{}\tR{},{},{}\t; R{}({})'.format(i, op_code.name[3:], a, b, c,  a, temp_b))

        elif op_code == opCode.OP_RETURN:
            if b > 2:
                temp_b = 'R{} to R{}'.format(a, a + b - 2)
            elif b == 2:
                temp_b = 'R{}'.format(a)
            elif b == 1:
                temp_b = ''
            else:
                temp_b = 'R{} to top'.format(a)
            codes_line.append('{}\t[-]:{}\tR{},{}\t; return {}'.format(i, op_code.name[3:], a, b, temp_b))

        elif op_code == opCode.OP_FORLOOP:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}\t; R{} += R{}; if R{} <= R{} then {{ goto [{}]; R{}=R{} }}'.format(i,
                    op_code.name[3:], a, sbc, a, a + 2, a, a + 1, i + sbc, a + 3, a))

        elif op_code == opCode.OP_FORPREP:
            codes_line.append(
                '{}\t[-]:{}\tR{},{}\t; R{} -= R{}; goto [{}]'.format(i,op_code.name[3:], a, sbc, a, a + 2, i + sbc))

        elif op_code == opCode.OP_TFORLOOP:

            if c > 1:
                temp_c = 'R{} to R{}'.format(a + 3, a + c + 2)
            elif c == 1:
                temp_c = 'R{}'.format(a + 3)
            else:
                assert c <= 0, "error c <= 0"

            codes_line.append(
                '{}\t[-]:{}\tR{},{}\t; {} := R{}(R{}, R{}); if R{} ~= nil then R{} = R{} else goto [{}]'.format(i,
                    op_code.name[3:], a, c, temp_c, a, a + 1, a + 2, a + 3, a + 2, a + 3, i + 2))

        elif op_code == opCode.OP_SETLIST:
            # R(A)[(C - 1) * FPF + i] := R(A + i), 1 <= i <= B
            codes_line.append(
                '{}\t[-]:{}\t R{},{},{}\t; R{}[{}] to R{}[{}] := R{} to R{}'.format(i, op_code.name[3:], a, b, c, a,
                                                                                    (c - 1) * 50 + 1, a,
                                                                                    (c - 1) * 50 + b,
                                                                                    a + 1, a + b))

        elif op_code == opCode.OP_CLOSE:
            codes_line.append(
                '{}\t[-]:{}\t \t; close all variables in the stack up to (>=) R{}'.format(i, op_code.name[3:], a))

        elif op_code == opCode.OP_CLOSURE:
            codes_line.append('{}\t[-]:{}\t R{},{}\t; R{} := closure(Function #{})'.format(i, op_code.name[3:], a, bc, a, bc))

        elif op_code == opCode.OP_VARARG:
            if b > 2:
                temp = 'R{} to R{} := ...'.format(a, a + b - 2)
            elif b == 2:
                temp = 'R{} := ...'.format(a)
            else:
                temp = 'R{} to top := ...'.format(a)
            codes_line.append('{}\t[-]:{}\t R{},{}\t; {}'.format(i, op_code.name[3:], a, b, temp))

    str_code = ''
    for code_line in codes_line:
        str_code += code_line + "\n"
    print(str_code)


if __name__ == '__main__':
    # print(GETARG_A(8388736))

    with open("D:/workplace/frida/lua编辑调试者1.3.2.1/luac.out", mode='rb') as file:
        data = file.read()
    decode(data)
