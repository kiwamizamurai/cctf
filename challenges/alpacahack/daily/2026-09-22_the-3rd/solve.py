#!/usr/bin/env python3
"""The 3rd - AlpacaHack Daily (crypto, ECC).
E: y^2 = x^3 + 2x + 3 over Zmod(p*q*r), p,q known, r secret. T = k*S with
k = int.from_bytes(flag), flag = b"Alpaca{" + 6 unknown bytes + b"}" (48-bit mid).
Reduce mod the known primes p,q: solve ECDLP on E(GF(p)) and E(GF(q)) to get
k mod ord(S_p) and k mod ord(S_q), CRT them, then recover the 6 middle bytes.
Pure Python: affine EC, BSGS for order + dlog, Pollard-rho factoring."""
from math import isqrt, gcd
import random

p = 577131489751
q = 604663433347
A, B = 2, 3
Sx, Sy = 47472880544948864957374958450616147, 15718905651315016723553161697283736
Tx, Ty = 299503460090901935082824843431273729, 5022588709750132765941314121276972

def curve(pr):
    class E:
        mod = pr
        @staticmethod
        def add(P, Q):
            if P is None: return Q
            if Q is None: return P
            x1,y1=P; x2,y2=Q
            if x1==x2 and (y1+y2)%pr==0: return None
            if P==Q:
                m=(3*x1*x1+A)*pow(2*y1,-1,pr)%pr
            else:
                m=(y2-y1)*pow(x2-x1,-1,pr)%pr
            x3=(m*m-x1-x2)%pr
            y3=(m*(x1-x3)-y1)%pr
            return (x3,y3)
        @staticmethod
        def mul(k,P):
            R=None
            while k>0:
                if k&1: R=E.add(R,P)
                P=E.add(P,P); k>>=1
            return R
    return E

def bsgs_dlog(E, P, Q, bound):
    """smallest x in [0,bound] with x*P==Q, or None."""
    m=isqrt(bound)+1
    tbl={}
    cur=None
    for j in range(m+1):
        tbl.setdefault(cur, j)
        cur=E.add(cur,P)
    mP=E.mul(m,P)
    negmP=None if mP is None else (mP[0], (-mP[1])%E.mod)
    gamma=Q
    for i in range(m+1):
        if gamma in tbl:
            return i*m+tbl[gamma]
        gamma=E.add(gamma,negmP)
    return None

def point_order(E, P, pr):
    """order of P using a multiple-of-order from Hasse interval, then factor."""
    L=2*isqrt(pr)+2
    # find e in [-L,L] with (pr+1+e)*P == O via BSGS on base (pr+1)*P
    base=E.mul(pr+1,P)
    # search e by bsgs: base + e*P == O  => e*P == -base
    negbase=None if base is None else (base[0],(-base[1])%pr)
    # solve e*P == negbase for e in [-L,L]; shift to [0,2L]
    shift=E.mul(L,P)
    target=E.add(negbase,shift)  # (e+L)*P == target, e+L in [0,2L]
    x=bsgs_dlog(E,P,target,2*L+1)
    assert x is not None, "order multiple not found"
    m=pr+1+(x-L)
    if m==0: m=point_order_fallback(E,P,pr)
    m=abs(m)
    # m is a multiple of ord(P); reduce
    for f in factorize(m):
        while m%f==0 and E.mul(m//f,P) is None:
            m//=f
    assert E.mul(m,P) is None
    return m

def point_order_fallback(E,P,pr):
    # brute via Hasse (rare)
    for m in range(pr+1-2*isqrt(pr)-1, pr+2+2*isqrt(pr)):
        if E.mul(m,P) is None: return m
    raise RuntimeError

def factorize(n):
    fs={}
    def rho(n):
        if n%2==0: return 2
        while True:
            c=random.randrange(1,n); x=random.randrange(2,n); y=x; d=1
            while d==1:
                x=(x*x+c)%n; y=(y*y+c)%n; y=(y*y+c)%n
                d=gcd(abs(x-y),n)
            if d!=n: return d
    def isprime(n):
        if n<2: return False
        for sp in (2,3,5,7,11,13,17,19,23,29,31,37):
            if n%sp==0: return n==sp
        d=n-1;s=0
        while d%2==0:d//=2;s+=1
        for a in (2,3,5,7,11,13,17,19,23,29,31,37):
            xx=pow(a,d,n)
            if xx in(1,n-1):continue
            for _ in range(s-1):
                xx=xx*xx%n
                if xx==n-1:break
            else:return False
        return True
    stack=[n]
    while stack:
        m=stack.pop()
        if m==1: continue
        if isprime(m):
            fs[m]=fs.get(m,0)+1; continue
        d=rho(m)
        stack.append(d); stack.append(m//d)
    return fs

def solve_mod(pr):
    E=curve(pr)
    S=(Sx%pr, Sy%pr); T=(Tx%pr, Ty%pr)
    ordS=point_order(E,S,pr)
    x=bsgs_dlog(E,S,T,ordS)
    assert x is not None and E.mul(x,S)==T
    return x, ordS

def crt(r1,m1,r2,m2):
    g=gcd(m1,m2); l=m1//g*m2
    assert (r2-r1)%g==0
    lcm=l
    x=(r1 + (r2-r1)//g*pow(m1//g,-1,m2//g)%(m2//g)*m1)%lcm
    return x, lcm

xp,op=solve_mod(p)
print("p done", xp, op, flush=True)
xq,oq=solve_mod(q)
print("q done", xq, oq, flush=True)
k, M = crt(xp,op,xq,oq)
print("k mod", M, "=", k, flush=True)

# flag = b"Alpaca{" + mid(6) + b"}" = C + 256*mid, mid in [0, 2**48).
# k == r0 (mod M) with r0=k,M computed above; M (~2**76) is even so 256 is not
# invertible mod M -> instead find the unique k = r0 + t*M inside the structural
# window [C, C + 256*2**48) with (k - C) divisible by 256.
pre, suf = b"Alpaca{", b"}"
C = int.from_bytes(pre + b"\x00" * 6 + suf, "big")
hi = C + 256 * (1 << 48)
t0 = (C - k) // M
flag = None
for t in range(t0 - 2, t0 + 3):
    kk = k + t * M
    if C <= kk < hi and (kk - C) % 256 == 0:
        mid = (kk - C) // 256
        flag = pre + mid.to_bytes(6, "big") + suf
        break
print(flag.decode() if flag else "[not found]")
