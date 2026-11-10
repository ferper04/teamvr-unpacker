"""Minimal disassembler for RemObjects Pascal Script (IFPS) bytecode as stored in Inno Setup's
CompiledCodeText (format version 23, per uPSRuntime.pas). Read-only; nothing is executed."""
import re
import struct

BT = {1: 'U8', 2: 'S8', 3: 'U16', 4: 'S16', 5: 'U32', 6: 'S32', 7: 'Single', 8: 'Double', 9: 'Extended',
      10: 'String', 11: 'Record', 12: 'Array', 13: 'Pointer', 14: 'PChar', 15: 'ResPtr', 16: 'Variant', 17: 'S64',
      18: 'Char', 19: 'WideString', 20: 'WideChar', 21: 'ProcPtr', 22: 'StaticArray', 23: 'Set', 24: 'Currency',
      25: 'Class', 26: 'Interface', 27: 'NotifVariant', 28: 'UnicodeString', 129: 'Enum', 130: 'Type',
      131: 'ExtClass'}
CALC = '+ - * / mod shl shr and or xor'.split()
CMP = ['>=', '<=', '>', '<', '<>', '=', 'in', 'is']


class IFPS:
    def __init__(self, data):
        self.d = data
        self.p = 0
        if self.raw(4) != b'IFPS':
            raise ValueError('not IFPS bytecode')
        (self.ver, self.ntypes, self.nprocs, self.nvars, self.mainproc, _imptab) = [self.u32() for _ in range(6)]
        self.types, self.procs, self.gvars = [], [], []
        self._parse_tables()

    def u8(self):
        v = self.d[self.p]; self.p += 1; return v

    def u32(self):
        v = struct.unpack_from('<I', self.d, self.p)[0]; self.p += 4; return v

    def s32(self):
        v = struct.unpack_from('<i', self.d, self.p)[0]; self.p += 4; return v

    def raw(self, n):
        v = self.d[self.p:self.p + n]; self.p += n; return v

    def _parse_tables(self):
        for _ in range(self.ntypes):
            b = self.u8(); bt = b & 0x7F; info = ''
            if bt in (25, 21):
                info = self.raw(self.u32()).decode('latin1')
            elif bt == 26:
                self.raw(16)
            elif bt == 23:
                info = 'bits=%d' % self.u32()
            elif bt == 22:
                info = 'of %d size %d' % (self.u32(), self.u32())
                if self.ver > 22:
                    self.u32()
            elif bt == 12:
                info = 'of %d' % self.u32()
            elif bt == 11:
                fc = self.u32(); info = 'fields ' + ','.join(str(self.u32()) for _ in range(fc))
            name = self.raw(self.u32()).decode('latin1') if b & 0x80 else ''
            if self.ver >= 21 and self.u32() != 0:
                raise ValueError('type attributes not supported')
            self.types.append((bt, name, info))
        for i in range(self.nprocs):
            fl = self.u8()
            if fl & 1:
                nm = self.raw(self.u8()).decode('latin1', 'replace'); decl = ''
                if fl & 3 == 3:
                    decl = self.raw(self.u32()).decode('latin1', 'replace')
                self.procs.append(dict(kind='ext', name=nm, decl=decl))
            else:
                off, ln = self.u32(), self.u32(); nm = decl = ''
                if fl & 2:
                    nm = self.raw(self.u32()).decode('latin1'); decl = self.raw(self.u32()).decode('latin1')
                self.procs.append(dict(kind='int', name=nm or 'proc%d' % i, decl=decl, off=off, len=ln))
            if fl & 4 and self.u32() != 0:
                raise ValueError('proc attributes not supported')
        for _ in range(self.nvars):
            t = self.u32(); fl = self.u8()
            self.gvars.append((t, self.raw(self.u32()).decode('latin1') if fl & 1 else ''))

    def imports(self):
        """External functions/methods the script can call (its whole reach outside the VM)."""
        out = []
        for p in self.procs:
            if p['kind'] != 'ext':
                continue
            if p['name']:
                out.append(p['name'])
                continue
            toks = [t for t in re.split(r'[\x00-\x1f]+', p['decl']) if t.strip()]
            if toks and toks[0].startswith('dll:'):
                out.append(' '.join(toks[:2]))          # dll:<file>:<library>  <function>
            elif toks:
                out.append(toks[0].strip())             # class:TCLASS|MEMBER|
        return out

    def _const(self, t):
        bt = self.types[t][0]
        if bt in (1, 2, 18): return repr(self.raw(1))
        if bt in (3, 4): return str(struct.unpack('<h' if bt == 4 else '<H', self.raw(2))[0])
        if bt == 20: return repr(self.raw(2).decode('utf-16le'))
        if bt in (5, 6, 129): return str(struct.unpack('<i' if bt == 6 else '<I', self.raw(4))[0])
        if bt == 7: return str(struct.unpack('<f', self.raw(4))[0])
        if bt == 8: return str(struct.unpack('<d', self.raw(8))[0])
        if bt == 9: self.raw(10); return '<extended>'
        if bt in (17, 24): return str(struct.unpack('<q', self.raw(8))[0])
        if bt in (10, 14): return repr(self.raw(self.u32()).decode('latin1'))
        if bt in (19, 28): n = self.u32(); return 'u' + repr(self.raw(n * 2).decode('utf-16le'))
        if bt == 21: return 'proc#%d' % self.u32()
        if bt == 23: return 'set:' + self.raw((int(self.types[t][2].split('=')[1]) + 7) // 8).hex()
        raise ValueError('constant of base type %d' % bt)

    def _var(self):
        k = self.u8()
        ref = lambda x: 'G%d' % x if x < 0x40000000 else 'S%+d' % (x - 0x60000000)
        if k == 0: return ref(self.u32())
        if k == 1: return self._const(self.u32())
        if k == 2: a = self.u32(); b = self.u32(); return '%s[%d]' % (ref(a), b)
        if k == 3: a = self.u32(); b = self.u32(); return '%s[%s]' % (ref(a), ref(b))
        raise ValueError('operand kind %d' % k)

    def disassemble(self):
        lines = ['; IFPS version %d, %d types, %d procs, %d globals' % (self.ver, self.ntypes, self.nprocs, self.nvars)]
        for i, p in enumerate(self.procs):
            if p['kind'] == 'ext':
                lines.append('import %3d  %s %s' % (i, p['name'], p['decl']))
        for i, (t, n) in enumerate(self.gvars):
            lines.append('global G%d : type %d %s' % (i, t, n))
        for i, pr in enumerate(self.procs):
            if pr['kind'] != 'int':
                continue
            lines.append('\nproc %d %s %s   ; @%#x len %d' % (i, pr['name'], pr['decl'], pr['off'], pr['len']))
            self.p = pr['off']; end = pr['off'] + pr['len']
            while self.p < end:
                a = self.p - pr['off']
                op = self.u8()
                try:
                    if op == 0: s = 'assign %s := %s' % (self._var(), self._var())
                    elif op == 1: o = self.u8(); s = 'calc %s %s= %s' % (self._var(), CALC[o], self._var())
                    elif op == 2: s = 'push %s' % self._var()
                    elif op == 3: s = 'pushvar %s' % self._var()
                    elif op == 4: s = 'pop'
                    elif op == 5: n = self.u32(); s = 'call %d %s' % (n, self.procs[n]['name'])
                    elif op == 6: o = self.s32(); s = 'goto %04x' % (self.p - pr['off'] + o)
                    elif op == 7: o = self.s32(); v = self._var(); s = 'if %s goto %04x' % (v, self.p - pr['off'] + o)
                    elif op == 8: o = self.s32(); v = self._var(); s = 'ifnot %s goto %04x' % (v, self.p - pr['off'] + o)
                    elif op == 9: s = 'ret'
                    elif op == 10: s = 'settype %s %d' % (self._var(), self.u32())
                    elif op == 11:
                        t = self.u32(); s = 'pushtype %d (%s)' % (t, BT.get(self.types[t][0]))
                    elif op == 12: o = self.u8(); s = 'cmp %s := %s %s %s' % (self._var(), self._var(), CMP[o], self._var())
                    elif op == 13: s = 'callvar %s' % self._var()
                    elif op == 14: s = 'setptr %s -> %s' % (self._var(), self._var())
                    elif op == 15: s = 'not %s' % self._var()
                    elif op == 16: s = 'neg %s' % self._var()
                    elif op == 17: v = self._var(); s = 'setflag %s not=%d' % (v, self.u8())
                    elif op == 18: o = self.s32(); s = 'flaggoto %04x' % (self.p - pr['off'] + o)
                    elif op == 19: s = 'try %s' % [self.u32() for _ in range(4)]
                    elif op == 20: s = 'endtry %d' % self.u8()
                    elif op == 22: s = 'setcopyptr %s %s' % (self._var(), self._var())
                    elif op == 23: s = 'inc %s' % self._var()
                    elif op == 24: s = 'dec %s' % self._var()
                    else:
                        lines.append('%04x ??? opcode %d' % (a, op)); break
                except (ValueError, IndexError, struct.error) as e:
                    lines.append('%04x <decode error: %s>' % (a, e)); break
                lines.append('%04x %s' % (a, s))
        return '\n'.join(lines) + '\n'
