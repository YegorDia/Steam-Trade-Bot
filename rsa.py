from __future__ import division

import json

BI_RC = [None for a in range(200)]
rr = ord("0")
DB = 26
F2 = 0
F1 = 26
DM = 67108863
FV = 4503599627370496
DV = 67108864
BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz"
import random

for a in range(10):
    BI_RC[rr] = a
    rr += 1
rr = ord("a")
for a in range(10, 36):
    BI_RC[rr] = a
    rr += 1
rr = ord("A")
for a in range(10, 36):
    BI_RC[rr] = a
    rr += 1


def int_at(s, i):
    c = BI_RC[ord(str(s[i]))]
    if not c:
        return 0
    return c


def clamp(wynik):
    c = wynik['s'] & DM
    while wynik['t'] > 0 and wynik[wynik['t'] - 1] == c:
        wynik['t'] -= 1


def big_integer_one():
    return {0: 1, 't': 1, 's': 0}


def BigInteger(s, b):
    wynik = {}
    if b == 256:
        k = 8
    else:
        k = 4
    i = len(s)
    mi = False
    t = 0
    sh = 0
    while i > 0:
        i -= 1
        if k == 8:
            x = s[i] & 0xff
        else:
            x = int_at(s, i)
        if x < 0:
            if (s[i] == "-"):
                mi = True
                continue
        mi = False
        if sh == 0:
            wynik[t] = x
            t += 1
        elif sh + k > DB:
            wynik[t - 1] |= (x & ((1 << (DB - sh)) - 1)) << sh
            wynik[t] = (x >> (DB - sh))
            t += 1
        else:
            wynik[t - 1] |= x << sh
        sh += k
        if sh >= DB:
            sh -= DB
    if k == 8 and (s[0] & 0x80) != 0:
        wynik['s'] = -1
        if sh > 0:
            wynik[t - 1] |= ((1 << (DB - sh)) - 1) << sh
    wynik.update({'t': t, 's': 0})

    clamp(wynik)
    return wynik


def nbits(x):
    r = 1
    for z in [16, 8, 4, 2, 1]:
        t = x >> z
        if t != 0:
            x = t
            r += z
    return r


from collections import OrderedDict


def pkcs(data, keysize):
    i = len(data) - 1
    buffer = {}
    while i >= 0 and keysize > 0:
        # print keysize
        buffer[keysize] = ord(data[i])
        keysize -= 1
        i -= 1
    # print OrderedDict(sorted(buffer.items()))
    buffer[keysize] = 0
    keysize -= 1
    # rnd = random.uniform(1, 0)
    # print rnd
    # rnd = 0.282741585797
    while keysize > 2:
        buffer[keysize] = int(random.uniform(1, 0) * 254) + 1
        # print "buffer[keysize]: %s"%(buffer[keysize])
        # buffer[keysize] = int(0.424234324*254) + 1
        keysize -= 1

    buffer[keysize] = 2
    keysize -= 1
    buffer[keysize] = 0
    keysize -= 1
    # print [buffer[key] for key in sorted(buffer.keys())]
    # print buffer
    return BigInteger(buffer.values(), 256)


def bnBitLength(module):
    return 26 * (module['t'] - 1) + nbits(module[module['t'] - 1] ^ (module['s'] & DM))
    # return nbits(module[module['t']-1]^(module['s']&DM))
    return 26 * (module['t'] - 1)


def am1(this, i, x, w, j, c, n):
    ten = False
    # if j == 60:
    # p( this)
    # p( w)
    # print n,j
    # if n == 79 and j == 48:
    # ten = True
    if ten:
        # print "tutaj"
        # print i,x,j,c,n
        # print w[60]
        # p(w)
        pass
    while 1:
        n -= 1
        if n < 0:
            break
        v = x * this[i] + w[j] + c
        # if ten:
        # print j
        # print x,this[i],w[j],c
        # if ten:
        # print v,'-v'
        # pass
        # if j == 60 and ten:
        # print x,this[i],w[j],c,v
        i += 1
        # c = int(Decimal(v)/Decimal(0x4000000))
        c = int(v / 0x4000000)

        # if ten:
        # print Decimal(v)/Decimal(0x4000000)
        # print v/0x4000000
        # print c,'-c'
        w[j] = v & 0x3ffffff
        if ten:
            pass
            # print j
            # print w[j]
        j += 1
        # if temp_j == 47:
        # if ten:
        # print w[60]
        # print c,'=',j
    return c


def bnpInvDigit(this):
    DV = 67108864
    if this['t'] < 1: return 0
    x = this[0]
    if ((x & 1) == 0): return 0
    y = x & 3
    y = (y * (2 - (x & 0xf) * y)) & 0xf
    y = (y * (2 - (x & 0xff) * y)) & 0xff
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff
    y = (y * (2 - x * y % DV)) % DV
    return DV - y if (y > 0) else -y


def dlShiftTo(data, t, r):
    n = t
    for i in range(data['t'] - 1, -1, -1):
        r[i + n] = data[i]

    for i in range(n - 1, -1, -1):
        r[i] = 0
    r['t'] = data['t'] + n
    r['s'] = data['s']


def copyTo(this, r):
    for i in range(this['t'] - 1, -1, -1):
        r[i] = this[i]
    r['t'] = this['t']
    r['s'] = this['s']


def lShiftTo(this, n, r):
    bs = n % DB
    cbs = DB - bs
    bm = (1 << cbs) - 1
    ds = int(n / DB)
    c = 0
    for i in range(this['t'] - 1, -1, -1):
        r[i + ds + 1] = (this[i] >> cbs) | c
        c = (this[i] & bm) << bs
    for i in range(ds - 1, -1, -1):
        r[i] = 0
    r[ds] = c
    r['t'] = this['t'] + ds + 1
    r['s'] = this['s']
    clamp(r)


def compareTo(this, a):
    r = this['s'] - a['s']
    if r != 0: return r
    i = this['t']
    r = i - a['t']
    if (r != 0): return r
    while i >= 0:
        i -= 1
        r = this[i] - a[i]
        if r != 0:
            return r
    return 0


def subTo(this, a, r):
    i = 0
    c = 0
    m = min(a['t'], this['t'])
    while i < m:
        c += this[i] - a[i]
        r[i] = c & DM
        i += 1
        c >>= DB
    if a['t'] < this['t']:
        c -= a['s']
        while (i < this['t']):
            c += this[i]
            r[i] = c & DM
            i += 1
            c >>= DB
        c += this['s']
    else:
        c += this['s']
        while i < a['t']:
            c -= a[i]
            r[i] = c & DM
            i += 1
            c >>= DB
        c -= a['s']
    r['s'] = -1 if (c < 0) else 0
    if c < -1:
        r[i] = DV + c
        i += 1
    elif c > 0:
        r[i] = c
        i += 1
    r['t'] = i
    clamp(r)


def drShiftTo(this, n, r):
    for i in range(n, this['t']):
        r[i - n] = this[i]
    r['t'] = max(this['t'] - n, 0)
    r['s'] = this['s']


def rShiftTo(this, n, r):
    r['s'] = this['s']
    ds = int(n / DB)
    if ds >= this['t']:
        r['t'] = 0
        return
    bs = n % DB
    cbs = DB - bs
    bm = (1 << bs) - 1
    r[0] = this[ds] >> bs
    for i in range(ds + 1, this['t']):
        r[i - ds - 1] |= (this[i] & bm) << cbs
        r[i - ds] = this[i] >> bs

    if bs > 0:
        r[this['t'] - ds - 1] |= (this['s'] & bm) << cbs
    r['t'] = this['t'] - ds
    clamp(r)


def divRemTo(this, m, q, r):
    # print m
    if m['s'] > 0:
        raise NotImplementedError('Abs funkcja nie zaimplementowana dla s > 0')
    else:
        pm = m
    if pm['t'] <= 0: return
    if this['s'] > 0:
        raise NotImplementedError('Abs funkcja nie zaimplementowana dla s > 0')
    else:
        pt = this
    if pt['t'] < pm['t']:
        if q is not None: raise NotImplementedError("jsbn line 397 bnpDivRemTo function")
        if r is not None:
            copyTo(this, r)
        return
    if not r: r = {}
    y = {}
    ts = this['s']
    ms = m['s']
    nsh = DB - nbits(pm[pm['t'] - 1])

    if nsh > 0:
        lShiftTo(pm, nsh, y)
        lShiftTo(pt, nsh, r)
    else:
        copyTo(pm, y)
        copyTo(pt, r)
    ys = y['t']
    y0 = y[ys - 1]
    if y0 == 0: return
    yt = y0 * (1 << F1) + ( y[ys - 2] >> F2 if (ys > 1) else 0)
    d1 = FV / float(yt)
    # d1 = 1.1273041469513516
    d2 = (1 << F1) / float(yt)
    e = 1 << F2
    i = r['t']
    j = i - ys
    t = q if q else {}
    dlShiftTo(y, j, t)
    if compareTo(r, t) >= 0:
        r[r[t]] = 1
        t += 1
        r.subTo(t, r)
    dlShiftTo(big_integer_one(), ys, t)
    subTo(t, y, y)
    while y['t'] < ys:
        y[y['t']] = 0
        y['t'] += 1
    while 1:
        j -= 1
        if j < 0:
            break
        try:
            test = r[i] == y0
        except KeyError:
            print "key eror: %s" % (i)
            test = None
        i -= 1
        qd = DM if (test) else int(r[i] * d1 + (r[i - 1] + e) * d2)
        r[i] += am1(y, 0, qd, r, j, 0, ys)
        if r[i] < qd:
            print True
            dlShiftTo(y, j, t)
            subTo(r, t, r)
            while r[i] < qd:
                qd -= 1
                subTo(r, t, r)
    if q:
        drShiftTo(r, ys, q)
        if ts != ms:
            subTo(big_integer_one, q, q)
    r['t'] = ys
    clamp(r)
    if nsh > 0:
        rShiftTo(r, nsh, r)
    if ts < 0:
        subTo(big_integer_one, r, r)


def squareTo(this, r):
    x = this
    # p(x)
    i = r['t'] = 2 * x['t']
    while 1:
        i -= 1
        if i < 0:
            break
        r[i] = 0
    # p( r)
    # p(x)
    for i in range(x['t'] - 1):
        # print r[60],'firsts','-',i
        c = am1(x, i, x[i], r, 2 * i, 0, 1)

        if i == 30:
            # print x['t']-i-1
            pass
            # p(r)
            # print r[0],r[20],r[40],r[60],r.get(120,'')
        # print r[60],'scoend','-',i
        # print 'tu'
        # print r[i+x['t']],i+x['t'], '-bie'
        r[i + x['t']] += am1(x, i + 1, 2 * x[i], r, 2 * i + 1, c, x['t'] - i - 1)
        if r[i + x['t']] >= DV:
            print 'tu'
            r[i + x.t] -= DV
            r[i + x.t + 1] = 1

        if i == 0:
            pass
            # p(x)
            # print r[0],r[20],r[40],r[60],r.get(120,'')
            # print r[60],'third','-',i
            # print r[i+x['t']],i+x['t'], '-aft'
    # p(r)
    # print r[0],r[60],r.get(120,'')
    i += 1
    if r['t'] > 0:
        # print am1(x,i,x[i],r,2*i,0,1)
        # print (i,x[i],r,i)
        r[r['t'] - 1] += am1(x, i, x[i], r, 2 * i, 0, 1)
    r['s'] = 0
    clamp(r)


def reduce(this, x):
    # print 't'

    while x['t'] <= this['mt2']:
        x[x['t']] = 0
        x['t'] += 1
    for i in range(this['t']):
        # print i
        j = x[i] & 0x7fff
        # print j,'=',i
        u0 = (j * this['mpl'] + (((j * this['mph'] + (x[i] >> 15) * this['mpl']) & this['um']) << 15)) & DM
        # print u0,'=',i
        j = i + this['t']
        # print this['t']
        # if i == 50:
        # p(x)
        # print u0,i,this['t'],'--',i
        x[j] += am1(this, 0, u0, x, i, 0, this['t'])
        # print x[127],x[128], i
        while x[j] >= DV:
            # print 'here'
            # print DV
            x[j] -= DV
            j += 1
            x[j] += 1
    # p(x)
    clamp(x)
    drShiftTo(x, this['t'], x)
    if compareTo(x, this) >= 0:
        subTo(x, this, x)


def sqrTo(this, x, r):
    squareTo(x, r)
    # print 'sure?','*'*30
    reduce(this, r)
    # p(r)


def multiplyTo(this, a, r):
    x = this
    y = a
    i = x['t']
    r['t'] = i + y['t']
    while i > 0:
        i -= 1
        r[i] = 0
    for i in range(y['t']):
        r[i + x['t']] = am1(x, 0, y[i], r, i, 0, x['t'])
    r['s'] = 0
    clamp(r)
    if this['s'] != a['s']:
        subTo(big_integer_one, r, r)
        raise NotImplementedError("BigIntiger.ZERO not implemented")


def mulTo(this, x, y, r):
    multiplyTo(x, y, r)
    reduce(this, r)


def revert(this, x):
    r = {}
    copyTo(x, r)
    reduce(this, r)
    return r


def int2char(n):
    return BI_RM[n]


def toString(this, b):
    if this['s'] < 0:
        raise NotImplementedError("print negate not implemented")
    k = 4
    km = (1 << k) - 1
    m = False
    r = ""
    i = this['t']
    p = DB - (i * DB) % k
    control = 0
    if i - 1 > 0:
        i -= 1
        d = this[i] >> p
        if p < DB and d > 0:
            m = True
            r = int2char(d)
        while i >= 0:
            if p < k:
                d = (this[i] & ((1 << p) - 1)) << (k - p)
                p += DB - k
                i -= 1
                d |= this[i] >> (p)
            else:
                p -= k
                d = (this[i] >> (p)) & km
                if p <= 0:
                    p += DB
                    i -= 1
            if d > 0:
                m = True
            if m:
                r += int2char(d)
    return r


def p(a):
    print json.dumps(a, indent=2, sort_keys=True)


def encode(password, publickey_mod, publickey_exp):
    modulus = BigInteger(publickey_mod, 16)
    exponent = BigInteger(publickey_exp, 16)
    data = pkcs(password, (bnBitLength(modulus) + 7) >> 3)

    modulus_new = modulus.copy()
    modulus_new['mp'] = bnpInvDigit(modulus)
    modulus_new['mpl'] = modulus_new['mp'] & 0x7fff
    modulus_new['mph'] = modulus_new['mp'] >> 15
    modulus_new['um'] = (1 << (DB - 15)) - 1
    modulus_new['mt2'] = 2 * modulus_new['t']
    # modulus_new - z
    # data - this
    #exponent - e
    r = {}
    dlShiftTo(data, modulus_new['t'], r)
    divRemTo(r, modulus, None, r)
    #### okej!
    #r - g
    this = data
    x = data
    if x['s'] < 0 and compareTo(r, big_integer_one) > 0:
        this.m.subTo(r, r)
    g = r.copy()
    r = {}
    r2 = {}
    i = nbits(exponent[0]) - 1
    copyTo(g, r)
    # p( r)
    z = modulus_new
    # print i
    # p(z)
    # print i
    while 1:
        i -= 1
        if i < 0:
            break
            # print i,'*'*55
            # if i == 12:
            # print r2[157]
        sqrTo(z, r, r2)
        # p(r2)
        # if i == 13:
        # return
        # print i
        # print r2[157]
        # print r[10]
        # p( r2)
        # break
        if exponent[0] & (1 << i) > 0:
            # p( r2)
            mulTo(z, r2, g, r)
        else:
            t = r
            r = r2
            r2 = t
    # p(r2)
    data = revert(z, r)
    input = toString(data, 16)
    # print input
    hex = "0123456789abcdef"
    output = ''
    dl = len(input)
    input = iter(input)
    for a in input:
        try:
            output += unichr(((hex.index(a) << 4) & 0xf0) | (hex.index(next(input)) & 0xf))
        except StopIteration:
            output += unichr(((hex.index(a) << 4) & 0xf0) | (0 & 0xf))
    input = output
    # print input
    output = ''
    # import base64
    # print base64.b64encode(input)
    base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

    input = iter(input)
    for a in input:
        chr1 = ord(a)
        try:
            chr2 = ord(next(input))
        except:
            chr2 = None
        try:
            chr3 = ord(next(input))
        except:
            chr3 = None
        enc1 = chr1 >> 2
        enc2 = ((chr1 & 3) << 4) | ((chr2 if chr2 else 0) >> 4)
        enc3 = (((chr2 if chr2 else 0) & 15) << 2) | ((chr3 if chr3 else 0) >> 6)
        enc4 = (chr3 if chr3 else 0) & 63
        if chr2 is None:
            # print chr2
            enc3 = enc4 = 64
        if chr3 is None:
            enc4 = 64
        tmp = (base64[enc1] if len(base64) > enc1 else '') + (base64[enc2] if len(base64) > enc2 else '') + (
            base64[enc3] if len(base64) > enc3 else '') + (base64[enc4] if len(base64) > enc4 else '')
        # if len(output) + len(tmp) >= 210:
        # print tmp
        # print enc3
        # print enc4
        output += tmp
    return output  
