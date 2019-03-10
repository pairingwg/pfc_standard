---
coding: utf-8

title: Pairing-Friendly Curves
docname: draft-yonezawa-pairing-friendly-curves-01
date: 

ipr: trust200902
area: Networking
kw: Internet-Draft
category: exp

stand_alone: yes
pi: 
    toc: yes
    tocdepth: 4
    sortrefs: yes
    symrefs: no
    text-list-symbols: -o*+

author:
    -
        ins: S. Yonezawa
        name: Shoko Yonezawa
        org: Lepidum
        email: yonezawa@lepidum.co.jp
    -
        ins: S. Chikara
        name: Sakae Chikara
        org: NTT TechnoCross
        email: chikara.sakae@po.ntt-tx.co.jp
    -
        ins: T. Kobayashi
        name: Tetsutaro Kobayashi
        org: NTT
        email: kobayashi.tetsutaro@lab.ntt.co.jp
    -
        ins: T. Saito
        name: Tsunekazu Saito
        org: NTT
        email: saito.tsunekazu@lab.ntt.co.jp

normative:
    RFC2119:
    o-pairing: DOI.10.1109/TIT.2009.2034881
    BN05: DOI.10.1007/11693383_22
    BLS02: DOI.10.1007/3-540-36413-7_19
    KB16: DOI.10.1007/978-3-662-53018-4_20
    BD18: DOI.10.1007/s00145-018-9280-5
    MSS17: DOI.10.1007/978-3-319-61273-7_5
    Kiy: DOI.10.1007/978-3-319-61204-1_4

informative:
    RFC5091:
    RFC6508:
    RFC6539:
    RFC6509:
    SAKKE: 
        title: "Security of the mission critical service (Release 15)"
        author:
            org: 3GPP
        date: 2018
        seriesinfo:
            3GPP TS: 33.180 15.3.0
    ISOIEC11770-3: 
        title: ISO/IEC 11770-3:2015
        author:
            org: ISO/IEC
        date: 2015
        seriesinfo:
            ISO/IEC: "Information technology -- Security techniques -- Key management -- Part 3: Mechanisms using asymmetric techniques"
    Joux00: DOI.10.1007/10722028_23
    CCS07: DOI.10.1007/s10207-006-0011-9
    FSU10: DOI.10.1007/978-3-642-17455-1_12
    M-Pin: 
        target: https://www.miracl.com/miracl-labs/m-pin-a-multi-factor-zero-knowledge-authentication-protocol
        title: "M-Pin: A Multi-Factor Zero Knowledge Authentication Protocol"
        author:
            ins: "M. Scott"
        date: ""
    TPM:
        target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
        title: Trusted Platform Module Library Specification, Family \“2.0\”, Level 00, Revision 01.38
        author:
            org: Trusted Computing Group (TCG)
        date:
            year: 2016
            month: September
    FIDO:
        target: https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-ecdaa-algorithm-v2.0-rd-20180702.html
        title: FIDO ECDAA Algorithm - FIDO Alliance Review Draft 02
        author:
            ins: "R. Lindemann"
        date:
            year: 2018
            month: July
    W3C: 
        target: https://www.w3.org/TR/webauthn/
        title: "Web Authentication: An API for accessing Public Key Credentials Level 1 - W3C Candidate Recommendation"
        author: 
            ins: "D. Balfanz"
        author: 
            ins: "A. Czeskis"      
        author: 
            ins: "J. Hodges"
        author: 
            ins: "J. C. Jones"
        author: 
            ins: "M. B. Jones"
        author: 
            ins: "A. Kumar"
        author: 
            ins: "A. Liao"
        author: 
            ins: "R. Lindemann"
        author: 
            ins: "E. Lundberg"
        date:
            year: 2018
            month: July
    zcash:
        target: https://z.cash/technology/zksnarks.html
        title: What are zk-SNARKs?
        author:
            ins: "R. Lindemann"
        date:
            year: 2018
            month: July
    cloudflare: 
        target: https://blog.cloudflare.com/geo-key-manager-how-it-works/
        title: "Geo Key Manager: How It Works"
        author:
            ins: "N. Sullivan"
        date:
            year: 2017
            month: September
    DFINITY:
        target: https://dfinity.org/pdf-viewer/library/dfinity-consensus.pdf
        title: DFINITY Technology Overview Series Consensus System Rev. 1
        author:
            ins: "T. Hanke"
        author:
            ins: "M. Movahedi"
        author:
            ins: "D. Williams"
    ethereum:
        target: https://medium.com/prysmatic-labs/ethereum-2-0-development-update-17-prysmatic-labs-ed5bcf82ec00
        title: "Ethereum 2.0 Development Update #17 - Prysmatic Labs"
        author:
            ins: "R. Jordan"
        date:
            year: 2018
            month: November
    ECRYPT:
        title: Final Report on Main Computational Assumptions in Cryptography
        author:
            org: ECRYPT
        date:
            year: 2013
            month: January
    Pollard78: DOI.10.1090/S0025-5718-1978-0491431-9
    IndexCalculus: DOI.10.1007/978-1-4757-0602-4_1
    subgroup: DOI.10.1007/978-3-319-22174-8_14
    mcl:
        target: https://github.com/herumi/mcl
        title: mcl - A portable and fast pairing-based cryptography library
        author:
            ins: "S. Mitsunari"
        date: 2016
    BLS12-381:
        target: https://blog.z.cash/new-snark-curve/
        title: "BLS12-381: New zk-SNARK Elliptic Curve Construction"
        author:
            ins: "S. Bowe"
        date:
            year: 2017
            month: March
    ISOIEC15946-5:
        title: ISO/IEC 15946-5:2017
        author:
            org: ISO/IEC
        date: 2017
        seriesinfo:
            ISO/IEC: "Information technology -- Security techniques -- Cryptographic techniques based on elliptic curves -- Part 5: Elliptic curve generation"
    MIRACL:
        target: https://github.com/miracl/MIRACL
        title: MIRACL Cryptographic SDK
        author:
            org: MIRACL Ltd.
        date: 2018
    libsnark:
        target: https://github.com/zcash/libsnark
        title: "libsnark: a C++ library for zkSNARK proofs"
        author:
            org: SCIPR Lab
        date: 2012
    zkcrypto:
        target: https://github.com/zkcrypto/pairing
        title: "zkcrypto - Pairing-friendly elliptic curve library"
        author:
            org: zkcrypto
        date: 2017
    cloudflare-bn256:
        target: https://godoc.org/github.com/cloudflare/bn256
        title: package bn256
        author:
            org: Cloudflare
        date: ""
    go-bls:
        target: https://godoc.org/github.com/prysmaticlabs/go-bls
        title: "go-bls - Go wrapper for a BLS12-381 Signature Aggregation implementation in C++"
        author:
            org: Prysmatic Labs
        date: 2018
    PBC:
        target: https://crypto.stanford.edu/pbc/
        title: "PBC Library - The Pairing-Based Cryptography Library"
        author:
            ins: "B. Lynn"
        date: 2006
    relic:
        target: https://code.google.com/p/relic-toolkit/
        title: RELIC is an Efficient LIbrary for Cryptography
        author:
            ins: "D. F. Aranha"
        author:
            ins: "C. P. L. Gouv"
        date: 2013
    TEPLA:
        target: http://www.cipher.risk.tsukuba.ac.jp/tepla/index_e.html
        title: "TEPLA: University of Tsukuba Elliptic Curve and Pairing Library"
        author:
            org: University of Tsukuba
        date: 2013
    AMCL:
        target: https://github.com/apache/incubator-milagro-crypto
        title: The Apache Milagro Cryptographic Library (AMCL)
        author:
            org: The Apache Software Foundation
        date: 2016
    intel-ipp:
        target: https://software.intel.com/en-us/ipp-crypto-reference-arithmetic-of-the-group-of-elliptic-curve-points
        title: Developer Reference for Intel Integrated Performance Primitives Cryptography 2019
        author:
            org: Intel Corporation
        date: 2018
    bls48:
        target: https://github.com/mk-math-kyushu/bls48
        title: "bls48 - C++ library for Optimal Ate Pairing on BLS48"
        author:
            org: Kyushu University
        date: 2017
    IEEE-1363a-2004: DOI.10.1109/IEEESTD.2004.94612

--- abstract

This memo introduces pairing-friendly curves used for constructing pairing-based cryptography.
It describes recommended parameters for each security level and recent implementations of pairing-friendly curves.

--- middle

# Introduction

## Pairing-Based Cryptography

Elliptic curve cryptography is one of the important areas in recent cryptography. The cryptographic algorithms based on elliptic curve cryptography, such as ECDSA, is widely used in many applications.

Pairing-based cryptography, a variant of elliptic curve cryptography, is attracted the attention for its flexible and applicable functionality.
Pairing is a special map defined over elliptic curves.
As the importance of pairing grows, elliptic curves where pairing is efficiently computable are studied and the special curves called pairing-friendly curves are proposed.

Thanks to the characteristics of pairing, it can be applied to construct several cryptographic algorithms and protocols such as identity-based encryption (IBE), attribute-based encryption (ABE), authenticated key exchange (AKE), short signatures and so on. Several applications of pairing-based cryptography is now in practical use.

## Applications of Pairing-Based Cryptography

Several applications using pairing-based cryptography are standardized and implemented. We show example applications available in the real world.

IETF issues RFCs for pairing-based cryptography such as identity-based cryptography {{RFC5091}},  
Sakai-Kasahara Key Encryption (SAKKE) {{RFC6508}}, and Identity-Based Authenticated Key Exchange (IBAKE) {{RFC6539}}. 
SAKKE is applied to Multimedia Internet KEYing (MIKEY) {{RFC6509}} and used in 3GPP {{SAKKE}}.

Pairing-based key agreement protocols are standardized in ISO/IEC {{ISOIEC11770-3}}.
In {{ISOIEC11770-3}}, a key agreement scheme by Joux {{Joux00}}, identity-based key agreement schemes by Smart-Chen-Cheng {{CCS07}} and by Fujioka-Suzuki-Ustaoglu {{FSU10}} are specified.

MIRACL implements M-Pin, a multi-factor authentication protocol {{M-Pin}}.
M-Pin protocol includes a kind of zero-knowledge proof, where pairing is used for its construction.

Trusted Computing Group (TCG) specifies ECDAA (Elliptic Curve Direct Anonymous Attestation) in the specification of Trusted Platform Module (TPM) {{TPM}}. 
ECDAA is a protocol for proving the attestation held by a TPM to a verifier without revealing the attestation held by that TPM. Pairing is used for constructing ECDAA. FIDO Alliance {{FIDO}} and W3C {{W3C}} also published ECDAA algorithm similar to TCG.

Zcash implements their own zero-knowledge proof algorithm named zk-SNARKs (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge) {{zcash}}. zk-SNARKs is used for protecting privacy of transactions of Zcash. They use pairing for constructing zk-SNARKS.

Cloudflare introduced Geo Key Manager {{cloudflare}} to restrict distribution of customers' private keys to the subset of their data centers. To achieve this functionality, attribute-based encryption is used and pairing takes a role as a building block.

DFINITY utilized threshold signature scheme to generate the decentralized random beacons {{DFINITY}}. They constructed a BLS signature-based scheme, which is based on pairings.

In Ethereum 2.0, project Prysm applies signature aggregation for scalability benefits by leveraging DFINITY's random-beacon chain playground {{ethereum}}. Their codes are published on GitHub.

## Goal

The goal of this memo is to consider the security of pairing-friendly curves used in pairing-based cryptography and introduce secure parameters of pairing-frindly curves. Specifically, we explain the recent attack against pairing-friendly curves and how much the security of the curves is reduced.
We show how to evaluate the security of pairing-friendly curves and give the parameters for 100 bits of security, which is no longer secure, 128 and 256 bits of security.

## Requirements Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  
"MAY", and "OPTIONAL" in this document are to be interpreted as described in {{RFC2119}}.

# Preliiminaries

## Elliptic Curve

Let p > 3 be a prime and F\_p be a finite field.
The curve defined by the following equation E is called an elliptic curve.

       E : y^2 = x^3 + A * x + B,
       where A, B are in F\_p and satisfies 4 * A^3 + 27 * B^2 != 0 mod p.

Solutions (x, y) for an elliptic curve E, as well as the point at infinity, O\_E, 
are called F\_p-rational points.
If P and Q are two points on the curve E, we can define R = P + Q as the opposite point of the intersection between the curve E and the line that intersects P and Q. 
We can define P + O\_E = P = O\_E + P as well.
The additive group is constructed by the well-defined operation in the set of F\_p-rational points.
Similarly, a scalar multiplication S = \[a\]P for a positive integer a can be defined as an a-time addition of P.  

Typically, the cyclic additive group with a prime order r and the base point G in its group is used for the elliptic curve cryptography.
Furthermore, we define terminology used in this memo as follows.

O\_E: 
: the point at infinity over an elliptic curve E.

\#E(F\_p): 
: number of points on an elliptic curve E over F\_p.

h: 
: a cofactor such that h =  \#E(F\_p)/r.

k: 
: an embedding degree, a minimum integer such that r is a divisor of p^k - 1.

## Pairing {#pairing}

Pairing is a kind of the bilinear map defined over an elliptic curve.
Examples include Weil pairing, Tate pairing, optimal Ate pairing {{o-pairing}} and so on.
Especially, optimal Ate pairing is considered to be efficient to compute and mainly used for practical implementation.

Let E be an elliptic curve defined over the prime field F\_p.
Let G\_1 be a cyclic subgroup generated by a rational point on E with order r, and G\_2 be a cyclic subgroup generated by a twisted curve E' of E with order r.
Let G\_T be an order r subgroup of a field F\_p^k, where k is an embedded degree.
Pairing is defined as a bilinear map e: (G\_1, G\_2) -> G\_T
satisfying the following properties:

1. Bilinearity: for any S in G\_1, T in G\_2, a, b in Z\_r, we have the relation e(\[a\]S, \[b\]T) = e(S, T)^{a \* b}.
2. Non-degeneracy: for any T in G\_2, e(S, T) = 1 if and only if S = O\_E.
    Similarly, for any S in G\_1, e(S, T) = 1 if and only if T = O\_E.
3. Computability: for any S in G\_1 and T in G\_2, the bilinear map is efficiently computable.

## Barreto-Naehrig Curve {#BNdef}

A BN curve {{BN05}} is one of the instantiations of pairing-friendly curves proposed in 2005. A pairing over BN curves constructs optimal Ate pairings.

A BN curve is an elliptic curve E defined over a finite field F\_p, where p is more than or equal to 5, such that p and its order r are prime numbers parameterized by

       p = 36u^4 + 36u^3 + 24u^2 + 6u + 1
       r = 36u^4 + 36u^3 + 18u^2 + 6u + 1

for some well chosen integer u. The elliptic curve has an equation of the form E: y^2 = x^3 + b, where b is an element of multiplicative group of order p.

BN curves always have order 6 twists. If w is an element which is neither a square nor a cube in a finite field F\_p^2, the twisted curve E' of E is defined over a finite field F\_p^2 by the equation E': y^2 = x^3 + b' with b' = b/w or b' = bw. The embedded degree k is 12.

A pairing e is defined by taking G\_1 as a cyclic group composed by rational points on the elliptic curve E, G\_2 as a cyclic group composed by rational points on the elliptic curve E', and G\_T as a multiplicative group of order p^12.

## Barreto-Lynn-Scott Curve {#BLSdef}

A BLS curve {{BLS02}} is another instantiations of pairings proposed in 2002. Similar to BN curves, a pairing over BLS curves constructs optimal Ate pairings.

A BLS curve is an elliptic curve E defined over a finite field F\_p by an equation of the form E: y^2 = x^3 + b and has a twist of order 6 defined in the same way as BN curves. In contrast to BN curves, a BLS curve does not have a prime order but its order is divisible by a large parameterized prime r and the pairing will be defined on the r-torsions points.

BLS curves vary according to different embedding degrees. In this memo, we deal with BLS12 and BLS48 families with embedding degrees 12 and 48 with respect to r, respectively.

In BLS curves, parameterized p and r are given by the following equations:

       BLS12:
           p = (u - 1)^2 (u^4 - u^2 + 1)/3 + u
           r = u^4 - u^2 + 1
       BLS48:
           p = (u - 1)^2 (u^16 - u^8 + 1)/3 + u
           r = u^16 - u^8 + 1

for some well chosen integer u.

# Security of Pairing-Friendly Curves {#security_pfc}

## Evaluating the Security of Pairing-Friendly Curves

The security of pairing-friendly curves is evaluated by the hardness of the following discrete logarithm problems.

- The elliptic curve discrete logarithm problem (ECDLP) in G\_1 and G\_2
- The finite field discrete logarithm problem (FFDLP) in G\_T

There are other hard problems over pairing-friendly curves, which are used for proving the security of pairing-based cryptography. Such problems include computational bilinear Diffie-Hellman (CBDH) problem or bilinear Diffie-Hellman (BDH) Problem, decision bilinear Diffie-Hellman (DBDH) problem, gap DBDH problem, etc {{ECRYPT}}.
Almost all of these variants are reduced to the hardness of discrete logarithm problems described above and believed to be easier than the discrete logarithm problems.

There would be the case where the attacker solves these reduced problems to break the pairing-based cryptography. Since such attacks have not been discovered yet, we discuss the hardness of the discrete logarithm problems in this memo.

The security level of pairing-friendly curves is estimated by the computational cost of the most efficient algorithm to solve the above discrete logarithm problems. 
The well-known algorithms for solving the discrete logarithm problems includes Pollard's rho algorithm {{Pollard78}}, Index Calculus {{IndexCalculus}} and so on. 
In order to make index calculus algorithms more efficient, number field sieve (NFS) algorithms are utilized.

In addition, the special case where the cofactors of G\_1, G\_2 and G\_T are small should be taken care {{subgroup}}.
In such case, the discrete logarithm problem can be efficiently solved.
One has to choose parameters so that the cofactors of G\_1, G\_2 and G\_T contain no prime factors smaller than |G\_1|, |G\_2| and |G\_T|.

## Impact of the Recent Attack {#impact}

In 2016, Kim and Barbulescu proposed a new variant of the NFS algorithms, the extended number field sieve (exTNFS), which drastically reduces the complexity of solving FFDLP {{KB16}}.
Due to exTNFS, the security level of pairing-friendly curves asymptotically dropped down.
For instance, Barbulescu and Duquesne estimates that the security of the BN curves which was believed to provide 128 bits of security (BN256, for example) dropped down to approximately 100 bits {{BD18}}.

Some papers show the minimum bitlength of the parameters of pairing-friendly curves for each security level when applying exTNFS as an attacking method for FFDLP.
For 128 bits of security, Menezes, Sarkar and Singh estimated the minimum bitlength of p of BN curves after exTNFS as 383 bits, and that of BLS12 curves as 384 bits {{MSS17}}.
For 256 bits of security, Kiyomura et al. estimated the minimum bitlength of p^k of BLS48 curves as 27,410 bits, which implied 572 bits of p {{Kiy}}.

# Security Evaluation of Pairing-Friendly Curves {#secure_params}

We give security evaluation for pairing-friendly curves based on the evaluating method presented in {{security_pfc}}. We also introduce secure parameters of pairing-friendly curves for each security level.
The parameters introduced here are chosen with the consideration of security, efficiency and global acceptance.

For security, we introduce 100 bits, 128 bits and 256 bits of security.
We note that 100 bits of security is no longer secure
and recommend 128 bits and 256 bits of security for secure applications.
We follow TLS 1.3 which specifies the cipher suites with 128 bits and 256 bits of security as mandatory-to-implement for the choice of the security level.

Implementors of the applications have to choose the parameters with appropriate security level according to the security requirements of the applications.
For efficiency, we refer to the benchmark by mcl {{mcl}} for 128 bits of security, and by Kiyomura et al. {{Kiy}} for 256 bits of security and choose sufficiently efficient parameters.
For global acceptance, we give the implementations of pairing-friendly curves in {{impl}}.


## For 100 Bits of Security

Before exTNFS, BN curves with 256-bit size of underlying finite field (so-called BN256) were considered to have 128 bits of security. After exTNFS, however, the security level of BN curves with 256-bit size of underlying finite field fell into 100 bits.

Implementors who will newly develop the applications of pairing-based cryptography SHOULD NOT use BN256 as a pairing-friendly curve when their applications require 128 bits of security.
In case an application does not require higher security level and is sufficient to have 100 bits of security (i.e. IoT), implementors MAY use BN256.

## For 128 Bits of Security

A BN curve with 128 bits of security is shown in {{BD18}}, which we call BN462. BN462 is defined by a parameter u = 2^114 + 2^101 - 2^14 - 1 for the definition in {{BNdef}}. Defined by u, the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 - 4 and E': y^2 = x^3 - 4 \* (1 + i), where i is an element of an extension field F\_p^2, respectively. The size of p becomes 462-bit length. 

As the parameters for BN462, we give a characteristic p, an order r, a base point G = (x, y), a cofactor h of an elliptic curve E: y^2 = x^3 + b, 
and an order r', a base point G' = (x', y'), a cofactor h' of an elliptic curve E': y-2 = x^3 + b'.
In order to represent G' = (x', y') in an extension field, we adopt the representation convention in {{IEEE-1363a-2004}}, 
that is, for x' = x'\_1 * w + x'\_2 for an indeterminant w, we encode x' as x' = x'\_1 * p + x'\_2.

p:
: 0x240480360120023FFFFFFFFFF6FF0CF6B7D9BFCA0000000000D812908F41C8020FFFFFFFFFF6FF66FC6FF687F640000000002401B00840138013

r:
: 0x240480360120023FFFFFFFFFF6FF0CF6B7D9BFCA0000000000D812908EE1C201F7FFFFFFFFF6FF66FC7BF717F7C0000000002401B007E010800D

x:
: 0x21a6d67ef250191fadba34a0a30160b9ac9264b6f95f63b3edbec3cf4b2e689db1bbb4e69a416a0b1e79239c0372e5cd70113c98d91f36b6980d

y:
: 0x0118ea0460f7f7abb82b33676a7432a490eeda842cccfa7d788c659650426e6af77df11b8ae40eb80f475432c66600622ecaa8a5734d36fb03de

h:
: 1

b:
: 5

r':
: 0x240480360120023FFFFFFFFFF6FF0CF6B7D9BFCA0000000000D812908EE1C201F7FFFFFFFFF6FF66FC7BF717F7C0000000002401B007E010800D

x':
: 0x041b04cbe3413297c49d81297eed075947d86135c4abf0be9d5b64be02d6ae7834047ea4079cd30fe28a68ba0cb8f7b72836437dc75b2567ff2b98dbb93f68fac828d8221e4e1d89475e2d85f2063cbc4a74f6f66268b6e6da1162ee055365bb30283bde614a17f61a255d6882417164bc500498

y':
: 0x0104fa796cbc29890f9a37982c353da13b299391be45ddb1c15ca42abdf8bf502a5dd7ac0a3d351a859980e89be676d00e92c128714d6f3c6aba56ca6e0fc6a5468c12d42762b29d840f13ce5c3323ff016233ec7d76d4a812e25bbeb2c250243f2cbd2780527ec5ad208d7224334db3c1b4a49c

h':
: 0x240480360120023ffffffffff6ff0cf6b7d9bfca0000000000d812908fa1ce0227fffffffff6ff66fc63f5f7f4c0000000002401b008a0168019

b':
: -u + 2

A BLS12 curve with 128 bits of security shown in {{BD18}} is parameterized by u = -2^77 - 2^71 - 2^64 + 2^37 + 2^35 + 2^22 - 2^5, which we call BLS12-461.
Defined by u, the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 - 2 and E': y^2 = x^3 - 2 / (1 + i), respectively.
The size of p becomes 461-bit length. The curve BLS12-461 is subgroup-secure.

A BLS12 curve with 128 bits of security shown in {{BLS12-381}}, BLS12-381, is defined by a parameter u = -2^63 - 2^62 - 2^60 - 2^57 - 2^48 - 2^16 
and the size of p becomes 381-bit length. 
Defined by u, the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 + 4 and E': y^2 = x^3 + 4(i + 1), respectively.

We have to note that, according to {{MSS17}}, the bit length of p for BLS12 to achieve 128 bits of security is calculated as 384 bits and more, which BLS12-381 does not satisfy. Although the computational time is conservatively estimated by 2^110 when exTNFS is applied with index calculus, there is no currently published efficient method for such computational time. They state that BLS12-381 achieves 127-bit security level evaluated by the computational cost of Pollard's rho. Therefore, we regard BN462 as a \"conservative\" parameter, and BLS12-381 as an \"optimistic\" parameter.

We give the parameters for BLS12-381 as follows.

p:
: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

r:
: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

x:
: 0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB

y:
: 0x08B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1

h:
: 0x396C8C005555E1568C00AAAB0000AAAB

b:
: 4

r':
: 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

x':
: 0x204D9AC05FFBFEBAC60C8F3E4143831567C7063D38B05959C12EC063FD7B99AB4541ECEFAA3F0EC1A0A33DA0FF56D7B45B2CA9FF8ADBAC478790D52DC45216B3E272DCEA7571E7181B20335695608A30EA1F83E53A80D95AD3A0C1E7C4E76E2

y':
: 0x09CB66AFFF60C189DA2C655D4ECCAD15DBA53E8A3C89101ABA0838C17AD69CD096844BA7EC246EA99BE5C249AEA2F05C14385E9C53DF5FB63DDECFEF1067E735CC1776397138D4CB2CCDFBE45B5343EEADF663708AE1288AA4306DB8598A5EB

h':
: 0x5D543A95414E7F1091D50792876A202CD91DE4547085ABAA68A205B2E5A7DDFA628F1CB4D9E82EF21537E293A6691AE1616EC6E786F0C70CF1C38E31C7238E5

b':
: 4 \* (i + 1)

## For 256 Bits of Security

As shown in {{impact}}, it is unrealistic to achieve 256 bits of security by BN curves since the minimum size of p becomes too large to implement.
Hence, we consider BLS48 for 256 bits of security.

A BLS48 curve with 256 bits of security is shown in {{Kiy}}, which we call BLS48-581. 
It is defined by a parameter u = -1 + 2^7 - 2^10 - 2^30 - 2^32 and the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 + 1 and E': y^2 = x^3 - 1 / w, 
where w is an element of an extension field F\_p^8.
The size of p becomes 581-bit length.

We then give the parameters for BLS48-581.
Here, a base point (x', y') in an extension field of order 12 is represented as follows:
for x' = x'\_0 + x'\_1 \* i + x'\_2 \* i^2 + ... + x'\_{11} \* i^{11} and  y' = y'\_0 + y'\_1 \* i + y'\_2 \* i^2 + ... + y'\_{11} \* i^{11}, x' and y' are represented by

        x' = x'\_0 + x'\_1 \* p + x'\_2 \* p^2 + ... + x'\_{11} \* p^{11},
        y' = y'\_0 + y'\_1 \* p + y'\_2 \* p^2 + ... + y'\_{11} \* p^{11}.

p:
: 0x1280F73FF3476F313824E31D47012A0056E84F8D122131BB3BE6C0F1F3975444A48AE43AF6E082ACD9CD30394F4736DAF68367A5513170EE0A578FDF721A4A48AC3EDC154E6565912B

r:
: 0x2386f8a925e2885e233a9ccc1615c0d6c635387a3f0b3cbe003fad6bc972c2e6e741969d34c4c92016a85c7cd0562303c4ccbe599467c24da118a5fe6fcd671c01

x:
: 0x02af59b7ac340f2baf2b73df1e93f860de3f257e0e86868cf61abdbaedffb9f7544550546a9df6f9645847665d859236ebdbc57db368b11786cb74da5d3a1e6d8c3bce8732315af640

y:
: 0x0cefda44f6531f91f86b3a2d1fb398a488a553c9efeb8a52e991279dd41b720ef7bb7beffb98aee53e80f678584c3ef22f487f77c2876d1b2e35f37aef7b926b576dbb5de3e2587a70

h:
: 0x85555841aaaec4ac

b:
: 1

r':
: 0x2386f8a925e2885e233a9ccc1615c0d6c635387a3f0b3cbe003fad6bc972c2e6e741969d34c4c92016a85c7cd0562303c4ccbe599467c24da118a5fe6fcd671c01

x':
: 0x01690ae06061530e3164040ce6e7466974a0865edb6d5b825df11e5db6b724681c2b5a805af2c7c45f60300c3c4238a1f5f6d3b64429f5b655a4709a8bddf790ec477b5fb1ed4a0156dec43f7f6c401164da6b6f9af79b9fc2c0e09d2cd4b65900d2394b61aa3bb48c7c731a1468de0a17346e34e17d58d8707f845face35202bb9d64b5eff29cbfc85f5c6d601d794c8796c20e6781dffed336fc1ff6d3ae3193dec0060391acb6811f1fbde38027a0ef591e6b21c6e31c5f1fda66eb05582b6b0399c6a2459cb2abfd0d5d953447a92786e194b289588e63ef1b8b61ad354bed299b5a497c549d7a56a74879b7665a7042fbcaf1190d915f945fef6c0fcec14b4afc403f507747204d810c5700de16926309352f660f26a5529a2f74cb9d10440595dc25d6d12fcce84fc56557217bd4bc2d645ab4ca167fb812de7cacc3b9427fc78212985680b883bf7fee7eae01991eb7a52a0f4cbb01f5a8e3c16c41350dc62be2c19cbd2b98d9c9d2687cd811db7863779c97e9a15bd6967d5eb21f972d28ad9d437de412342524931998f280a9a9c799c33ff8f838ca35bddebbb79cdc2967946cc0f77995411692e18519243d5598bdb4623a11dc97ca388949f32c65db3fc6a47124bd5d063549e50b0f8b030d3a9830e1e3bef5cd4283939d33a28cfdc3df89640df257c0fc254477a9c8eff69b57cff042e6fd1ef3e293c57beca2cd61dc44838014c208eda095e10d5e89e705ff690704789596e419699650879771f58935d768cdc3b55150cca3693e2833b62df34f1e2491ef8c5824f8a80cd86e65193a

y':
: 0x00951682f010b08932b28b4a851ec79469f9437fc4f9cfa8ccdec25c3cc847890c65e1bcd2df994b835b71e49c0fc69e6d9ea5da9dbb020a9dfb2942dd022fa962fb0233de016c8c80e9387b0b28786785523e68eb7c008f81b99ee3b5d10a72e5321a09b74b39c58b75d09d73e4155b76dc11d8dd416b7fa63557fcddb0a955f6f5e0028d4af2150bfd757a898b548912e2c0c6e570449113fcee54cda9cb8bfd7f182825b371f06961b62ca441bfcb3d13ce6840432bf8bc4736003c64d695e984ddc2ef4aee1747044157fd2f9b81c43eed97d3452898996d24c66aad191dba634f3e04c89485e06f8308b8afaedf1c98b1a466deab2c1581f96b6f3c64d440f2a16a6275000cf38c09453b5b9dc8278eabe44292a154dc69faa74ad76ca847b786eb2fd686b9be509fe24b8293861cc35d76be88c2711704bfe118e4db1fad86c2a6424da6b3e5807258a2d166d3e0e43d15e3b6464fb99f382f57fd10499f8c8e11df718c98a049bd0e5d1301bc9e6ccd0f063b06eb06422afa469b5b529b8bba3d4c6f219affe4c57d7310a92119c98884c3b6c0bbcc113f6826b3ae70e3bbbaadab3ff8abf3b905c23138dfe385134807fcc1f9c19e68c0ec468213bc9f0387ca1f4ffe406fda92d6553cd4cfd50a2c895e85fe25409ffe8bb43b458f9befab4d59bee20e2f01de48c2affb03a97ceede87214e3bb90183303b672e50b87b36a61534034578db0195fd81a46beb55f75d20049d044c3fa5c3678c783db3120c2580359a7b33cac5ce21e4cecda9e2e2d6d2ff202ff43c1bb2d4b5e53dae010423ce

h':
: 0x170e915cb0a6b7406b8d94042317f811d6bc3fc6e211ada42e58ccfcb3ac076a7e4499d700a0c23dc4b0c078f92def8c87b7fe63e1eea270db353a4ef4d38b5998ad8f0d042ea24c8f02be1c0c83992fe5d7725227bb27123a949e0876c0a8ce0a67326db0e955dcb791b867f31d6bfa62fbdd5f44a00504df04e186fae033f1eb43c1b1a08b6e086eff03c8fee9ebdd1e191a8a4b0466c90b389987de5637d5dd13dab33196bd2e5afa6cd19cf0fc3fc7db7ece1f3fac742626b1b02fcee04043b2ea96492f6afa51739597c54bb78aa6b0b99319fef9d09f768831018ee6564c68d054c62f2e0b4549426fec24ab26957a669dba2a2b6945ce40c9aec6afdeda16c79e15546cd7771fa544d5364236690ea06832679562a68731420ae52d0d35a90b8d10b688e31b6aee45f45b7a5083c71732105852decc888f64839a4de33b99521f0984a418d20fc7b0609530e454f0696fa2a8075ac01cc8ae3869e8d0fe1f3788ffac4c01aa2720e431da333c83d9663bfb1fb7a1a7b90528482c6be7892299030bb51a51dc7e91e9156874416bf4c26f1ea7ec578058563960ef92bbbb8632d3a1b695f954af10e9a78e40acffc13b06540aae9da5287fc4429485d44e6289d8c0d6a3eb2ece35012452751839fb48bc14b515478e2ff412d930ac20307561f3a5c998e6bcbfebd97effc6433033a2361bfcdc4fc74ad379a16c6dea49c209b1

b':
: -1 / w

# Implementations of Pairing-Friendly Curves {#impl}

We show the pairing-friendly curves selected by existing standards, applications and cryptographic libraries.

<!-- standards -->

ISO/IEC 15946-5 {{ISOIEC15946-5}} shows examples of BN curves with the size of 160, 192, 224, 256, 384 and 512 bits of p. There is no action so far after the proposal of exTNFS.

TCG adopts an BN curve of 256 bits specified in ISO/IEC 15946-5 (TPM\_ECC\_BN\_P256) and of 638 bits specified by their own (TPM\_ECC\_BN\_P638).
FIDO Alliance {{FIDO}} and W3C {{W3C}} adopt the BN curves specified in TCG, a 512-bit BN curve shown in ISO/IEC 15946-5 and another 256-bit BN curve.

<!-- applications -->

MIRACL {{MIRACL}} implements BN curves and BLS12 curves.

Zcash implemented a BN curve (named BN128) in their library libsnark {{libsnark}}.
After exTNFS, they propose a new parameter of BLS12 as BLS12-381 {{BLS12-381}}
and publish its experimental implementation {{zkcrypto}}.

Cloudflare implements a 256-bit BN curve (bn256) {{cloudflare-bn256}}.
There is no action so far after exTNFS.

Ethereum 2.0 adopts BLS12-381 (BLS12\_381), BN curves with 254 bits of p (CurveFp254BNb) and 382 bits of p (CurveFp382\_1 and CurveFp382\_2) {{go-bls}}. Their implementation calls mcl {{mcl}} for pairing computation.

<!-- libraries -->

Cryptographic libraries which implement pairings include PBC {{PBC}}, mcl {{mcl}}, RELIC {{relic}}, TEPLA {{TEPLA}}, AMCL {{AMCL}}, Intel IPP {{intel-ipp}} and a library by Kyushu University {{bls48}}.

{{adoption}} shows the adoption of pairing-friendly curves in existing standards, applications and libraries.
In this table, the curves marked as (\*) indicate that there is no research result on the security evaluation, 
but that the implementers states that they hold 128 bits of security.

| Category | Name | 100 bit | 128 bit | 256 bit |
| standards | ISO/IEC {{ISOIEC15946-5}} | BN256 | BN384 | |
| | TCG | BN256 | | |
| | FIDO/W3C | BN256 | | |
| applications | MIRACL | BN254 | BLS12 | |
| | Zcash | BN128 (CurveSNARK) | BLS12-381 | |
| | Cloudflare | BN256 | | |
| | Ethereum | BN254 | BN382 (\*) / BLS12-381 (\*)  | |
| libraries | PBC | BN | | |
| | mcl | BN254 / BN_SNARK1 | BN381_1 (\*) / BN462 / BLS12-381 | |
| | RELIC {{relic}} | BN254 / BN256 | BLS12-381 / BLS12-455 | |
| | TEPLA | BN254 | | |
| | AMCL | BN254 / BN256 | BLS12-381 (\*) / BLS12-383 (\*) / BLS12-461 | BLS48 |
| | Intel IPP  | BN256 | | |
| | Kyushu Univ. | | | BLS48 |
{: #adoption title="Adoption of Pairing-Friendly Curves"} 

# Security Considerations

This memo entirely describes the security of pairing-friendly curves, and introduces secure parameters of pairing-friendly curves. We give these parameters in terms of security, efficiency and global acceptance. The parameters for 100, 128 and 256 bits of security are introduced since the security level will different in the requirements of the pairing-based applications.

Pairing-friendly curves MUST NOT be used for the elliptic curve cryptography whose security relies on the hardness of decision Diffie-Hellman (DDH) problem.

# IANA Considerations

This document has no actions for IANA.

# Acknowledgements

The authors would like to thank Akihiro Kato for his significant contribution to the early version of this memo.

# Change log

--- back

# Computing Optimal Ate Pairing {#comp_pairing}

Before presenting the computation of optimal Ate pairing e(P, Q) satisfying the properties shown in {{pairing}}, 
we give subfunctions used for pairing computation.

The following algorithm shows the computation of the line function.
It takes A = (A\[1\], A\[2\]), B = (B\[1\], B\[2\]) in G\_2 and P = ((P\[1\], P\[2\])) in G\_1 as input and outputs an element of G\_T.

        if (A = B) then
            l := (3 * A[1]^2) / (2 * A[2]);
        else if (A = -B) then
            return P[1] - A[1];
        else
            l := (B[2] - A[2]) / (B[1] - A[1]);
        end if;
        return (l * (P[1] -A[1]) + A[2] -P[2]);

When implementing the line function, implementer should consider the isomorphism of E and its twisted curve E' so that one can reduce the computational cost of operations in G\_2. We note that the function Line\_function does not consider such isomorphism.

Computation of optimal Ate pairing for BN curves uses Frobenius map.
Let a Frobenius map pi for a point Q = (x, y) over E' be pi(p, Q) = (x^p, y^p).

## Optimal Ate Pairings over Barreto-Naehrig Curves

Let s = 6u + 2 for a parameter u and s\_0, s\_1, ... , s\_l in {-1,0,1} such that the sum of s\_i \* 2^i (i = 0, 1, ..., L) equals to s.

The following algorithm shows the computation of optimal Ate pairing over Barreto-Naehrig curves.
It takes P in G\_1, Q in G\_2, an integer s, s\_0, ...,s\_L in {-1,0,1} such that the sum of s\_i \* 2^i (i = 0, 1, ..., L) equals to s, and an order r as input, and outputs e(P, Q).

        f := 1; T := Q;
        if (s_L = -1)
            T := -T;
        end if
        for i = L-1 to 0
            f := f^2 * Line_function(T, T, P); T := 2 * T;
            if (s_i = 1 | s_i = -1)
                f := f * Line_function(T, s_i * Q); T := T + s_i * Q;
            end if
        end for
        Q_1 := pi(p, Q); Q_2 := pi(p, Q_1);
        f := f * Line_function(T, Q_1, P); T := T + Q_1;
        f := f * Line_function(T, -Q_2, P);
        f := f^{(p^k - 1) / r}
        return f;

## Optimal Ate Pairings over Barreto-Lynn-Scott Curves

Let u\_0, u\_1, ... , u\_l in {-1,0,1} be a sign-digit representation of a parameter u 
such that the sum of u\_i * 2^i (i = 0, 1, ..., L) equals to u.
The following algorithm shows the computation of optimal Ate pairing over Barreto-Naehrig curves.
It takes P in G\_1, Q in G\_2, a parameter u, u\_0, u\_1, ..., u\_L in {-1,0,1} such that the sum of u\_i \* 2^i (i = 0, 1, ..., L), 
and an order r as input, and outputs e(P, Q).

        f := 1; T := Q;
        if (u_L = -1)
            T := -T;
        end if
        for i = L-1 to 0
            f := f^2 * Line_function(T, T, P); T := 2 * T;
            if (u_i = 1 | u_i = -1)
                f := f * Line_function(T, s_i * Q, P); T := T + s_i * Q;
            end if
        end for
        f := f^{(p^k - 1) / r};
        retern f;

# Test Vectors of Optimal Ate Pairing

We provide test vectors for Optimal Ate Pairing e(P, Q) given in {{comp_pairing}} for the curves BN462, BLS12-381 and BLS48-581 given in {{secure_params}}.

<!-- BN462: -->

<!-- Input P value:
: (TBD)

Input Q value:
: (TBD)

Output e(P, Q):
: 0x3C8193BED979F4EA5012851F2EB824BA7D21F5845C0416410F26A09772AB76E9153AD0DF012C6AADB90B2DB791B4865DC0DCE2A1DEEC684403BC919A350D007725F4AAF2EB1C6A6A84C3D68B3EB71C8F6D21A6696D3B70B82AB34CA3D8E362F8570AEEC978D9276154940920D459438E2141831FE6813BDA88F0A239D693499F07806C588498A881870A313A26C0362944F4895525034B30BECB184D52E0D806622157504C392059308A3AB60F567FCE39169B9636932988ABB8689F709A4AD26EBC8DC265F7938619357015CF8AEBEC069412B882DD79BF112713EC241D5E20D6003B614943D666403CB4458E4AC7B8800873EB55D6E5AABB6398C1C0F349F09E4BA501F239E3F54D09AD6140452545F07A20D53D075B2630FEFB61F46EAE734A0098C1B7B7BAF533A6072A5E288590CFB0C85B4EDF7BE906E01B4F023387D85E9CA9AA70EC3B5CC1ACB450685F41345391A237182295B9FE23EBBBF8485065DA74C4A591A01F3E5E3C5710337C050B01C17724D7CC02B4F0F512DA2AF145260028235DE26FE8977BC0A2E57C183729661ED63FAEF4570078E30F16D09E1C58888E561DA1CB4ADB1390360DD8D7B7B5F097B0E07C988743001EB5D150DA6218428C960F10441667E4CE905CE9CB9176987E1731403181B2D197C26727F8FEF00A612956A43B172FEA11BA6F660BE51F12C1F80A3697B28B4D685AB67816E4B9A8265A21825A059DB092CFC1CC28D1428988B01A3EC9A14B8B95BF1D3D111BE382848F2C1E9AE9FEDBEFB52E8EBA88EA17AD2E3730BA6D0EFCD916DE43C1666F3B25CD7FE72147F45E6C55CC701A64691426D6CD9FBBE8316A00537A53650496D27C28194B5C1D2C4909BCF006AB5E0F90FD82A14E45C5D008448080154B4723B44BBC0D48911427DBC54E0C0D41A0436A1C2D36252B921A2560DDCCAD362CB902F79D7F1210DDAC950BF406D0F0C79F299BCEBD -->

<!-- BLS12-381: -->

<!-- Input P value:
: (TBD)

Input Q value:
: (TBD)

Output e(P, Q):
: 0x109913307699946FFB01BB6A8708EFDAE7A380D3D0EEED9B73440E46BA128C4DB75A7B21DF4CABBA972239301955454F8E43F3437F83953557F251D93C11E3891134DA9E9D0A017DB6BBEF8F9F00689B05A4E7B66CA3B5EBD345258F776E9E1117E41EC691209560E0AC469921183F476C8DC140D30C301A7A673E4FC51655E0C4130E547E1F648386A15557AB73DD7B113EE92608695687DD9CB795060647EFEAC9894C0049AB34F1CBDEAC9527013EF5810ECF567269274A0425AFF77859249FDD23AAF67E3665C40A2B94A0AAE91112FB6AAD05AC5CA8E3FA0BC6B185C94447D2368136BA383BBEC5528AF53F2981628BA4B906E54F060383B92FC46F84E2E7C50D79CF7FF6D21E81A6715B31A660AA418EADE81887EC995285A656D0A43208EF51827FD935A1D617142AD008F3615201E00017154AC5AEE4C2DAA96433F97CC470559F94D64DCF4C69CFC254475D1365BC4A3D18524BE1F6A7ACD1AD2E64A901E5CF97C6291EFA4951CDBA232E2172C7E944C89F6FCF6074D23F41EA7ED783BE9BAACE67AE27E9C682FD8FC347E533D5E2E550B72EEEE9F250F427AC1F1A0BB315EE5582635065EC196F68776AB97CDD86E9F1117B3873800A19C2221C93A810A717FB6AE09A8EAC52D707158C783D45B9EEC3ADFA83B62644860679B2EE242888DC0AE8C3F7A4E2C5F8D9060B84B7C53C23992B50215170D86A8A1A1E62737E951647CE5872379CC01AB977532CEFDDF8539A8223F3DF88ACCDD1C9FA2C66227B95549471B462370AA61B58C57E9035EF90D630357D852EAA3 -->

<!-- BLS48-581: -->

<!-- Input P value:
: (TBD)

Input Q value:
: (TBD)

Output e(P, Q):
: 0x27643363D8D5BCD15F0B28C5097EEF37DE371C67B599C1EDB176719754FF47A6EA75AD80480617A2769333ED4D189C7E90B36A7F3C9873A13AFF7CD16047A3C7FDCBF0C8471BB51016494C2E0751DA368ED41B9C2AE12694B363ABC6E6E4F17927871D4D68DB391F9BED8DF52831E6EFE0AFA3816FD8387CA115D2CBA0C16A347590CEA2FA9D358712DCF6C023AD4F5DFB9FFD8CB2E2778E6F695185E58E2D81C2F0CEBCC270E0FAE678F758EF6E319D634F860A03F10953E203C7E419F9EB8A0B1AF2890B2B4182D8AF9FCBD410527E6378C1A5ACA0EA8C085E2784E787C1E4712FD891DC6C20E5C72A2B899CD21AEDE46358BC4C017270F723CC2986617FBABD4B9C24FF744B9A0321A2EBB392034D2AE4D415EB8FD45330E8FAE1C93F5D8849F558E14DCF20E60B519122407CDB876B2EB7897A89A602B0C61093E87D7DFC7C15CACF77A9C71E9EAE43A6DFBFA4F68B89019F3945CAF71C19682779C533E0CE0002C16CF123D3AFFB99103D04D3FDB2A6A1682AB3A34CC417F369850A22DB3A6C5B2D34BE0E97FA1EB9E7D6E45431E64E6F0D20BF725CB4323807531FCA7994A1447BB9C1FC39FA887750F5376C69ECB8C58C70FF11A9F6D5F5F780A831BE9A61729EE1778F050D6C2AFCDDA6CAB13BD952DE323222FBAEA4638E0295FBD5B8F5C60EE91429B078F36F3DC2BE436236D5FD2282CFF6203252456F6834B9AEA6212D9D478DDCDB1FC0537DB305CC854F39ACA861938D0AAB553F0D449F4CA5BC7653101B8F90B70C941BBCD9E7775F8102009C9C4F268E0D15305C28741D048B178F1F8CE599C66AAE2401D1F29E4987DE3D448ABB6462856FE8805118FE5D21AE5CE44BBA7EEF2AC2CD4138AB98152A08028275FA08A6D3EFE9344D16945016DE83C7287FFF6B6AA95CF2757C27CA48ECE8B8397DA3EB8F99555085343ABA1755660283B5EA74E5E526528184D100002192E244061F917EFF3331617CC10BD276167EC72579A942140E1C538858E84E5B7585B17B0EB8BD45B8915D448BFE9061FED09AA7B91E299B394CCF87C5FBB4C65ED6AB056F33C8BDB82AEA1BAAD3F3425B457E0FE6A61930D4DD22AE7E1E3946A655C72564B4B65D701A680C6CCF3FE88A1327D3399523A06E9D2AD2ECBB9ED9518634D2201150F7133381BD13115402F482E1715B68876F448C6E0FF0DFEC5D3174EE8026F73778692C61782236066E74B70996FA41DAEB068C9A78F5D8B59655985E0BD6E3785B5846F7E721339E6788731C24B80E26DD1182223B669AD4535E536F3DF711C31F1AA022718FDB6E8B7AD06C7647850507B3C6A7E454DC498B86769BD1FE57AA7959F972E8EDB1326B2A4233A5D7E34D32C545B92415B19443339642D441FD7EFAB7E16EEAEBC422D92C614C485E5E18EC3B990DB473A2DC27277C5CC408C42D8E1615DE5151A4EBA594C8D9827F4B14E38E3AFD1302AA4F86AD4D4CE621F5DE77B7F04B8FA3CA11CD701EEE9F7094AC3242596705A30CCF2DBF32491074EE2ADE6595C1171CF54D12EBAD23E383624B563C1EBA7A76E4002F1CDD4A0E1F8C24E9227AA53B56E077ED371BABD5935C20CD64EA0A045037849980895707A54167F68ABCC8E06D4D4B1027B6CDA799CEAA2B254B9EA7F34A4378417E12A1BEF63AC3DD3B15641F92E83911AC76D4EBFAACABDF0F81EBA243180CF9A12D40F188A822D427533A06969E9B15DED5785971636F9F980E727B2262897CCB665A3857AB7754C2BAC6627A5B18FC419DA14B8BB5F2FE3D29C62F8BE1FBDD078D6529087E3002039DA3C1930383D5582D29D061C87D68ACF45618F7DA265194F7F02FAE405B0C0868715DF1C3FAF6B71DF7331B79C0E9FE708C05FF1CB11A14B68684A04A338359484CB994DC2F432292817A1FD00C12DAE52F8D151C6FE34B3DCC9CA7EB559D44BAAF58CF94F0646C4694C49E3F181E0B1FB382056AA771C411833D7CFBF8212BC96EE303DFC15623717C814FD49E9355F48A480AF44BD7D2C94031D9881456A9EAB57E43962668F17973CFA0E9A075D94E3DB2AD9C06D4A2EE8DB81DB2862AF5F2EAC946630F61A8AB1B868469A9F7C28867C45CF5D801BBBD74ECF2FCECD6C9939865D7E27DBE56FBFF5321CD829ACF9C316C24778ECC263E491CF8ED0B23E1F2EC9BF0036E9F4442AD14DB4997DAF8F4DBD4E7E7D96FA32F0474E04AADCED225E9B723462900CB3409320DFD854181422D8135667897D62CC15A7E844B72F713B983E33F2017417FCEF9D384F58600B022FBD93BB2B405B74896ACDC32B5C459A4584AEA93FACF3D41C103D8538FEF57A8FF66715F84AAB22D6B2613CEE764038579A5334B212A15B9DDC3914524F85A889ED7CAC72BD23DFEE819CB2073F64A1BD7A5B303119A5715BAE052C7B71B0230D941D65BD1863227935EB6B0B648608D044A2549EDDDAE246F935C682BF92009FB1D1E4204A39468138E0DD73B5C4518C14FAF269B7A50D2C187367748AFF27EE960EF292BBBCAA86DB4F6DCA77DD661ECA3FBFBE11E01287B40AEB81FEA4A20F8870DDFC910B80E9FA9A7F3949FBF9E100C79026256FFE35B0B427E9BF6364616B3E4445BA35FC3C65C44249544AEA848B25778A7D3CED9A3393CF6AAB49F7337CDA34DFA94FB76283645F7551A49F0FC0960DB6538505374BC05EBA88344A2771051700AAED456EBE28D2F987AC363DD8A3395617100C00355AD30A22CD1334E32157BE9540654FA2841EB370760F182D8D8F11380D0DD358C2BEB3C2A9B1C791A14236DEC80DEAABF2FAD5076703649C4C67091E366C593D5AD763598A8A64BB95C91C5D4C1CF39410949BC3E0AE5EAA0E4CAFB2E5203DA185495F81C36E309E807AD6B5679B1978BA41582C3C750D703E95D77E479D433867D0FBE6C074519848150FCEC4351C912DED64844BF1E2E966FAF64C520E89517FA92996536AF096C4407DA5C1B1BEE0F040CB440D0095FB43A3E1EE5846CCDB0E068A8086C03C2668ABE161554EFB4F0B1975DF1D818CD386142E343186162CCE43C9D05212DDCAD50E10BDD3659007F156DCFD40E27B36BAEF4CD5184B71F5C342BF3B39E3D0F145F6515F2EEDB926C99953AF049168376477632B74355D180B72109E4049323D051767EC3B5858C545D8ED85E074C839558EEFAECFEA112062BB9E000D822FAD823C2F59387A62687738FB74C5E124B75FC6384BD4E9450AD801DB149C4E89A02A1445504E84E9D44B8304CE52EA513E923E40C833EE663A23FC64365CC3EF8ABECDE2C359009712DEC9511E11E282685A625580CE56E517AB3010CC21D2B4A656E3A5BABB900A1678EEEF9AD5A046A8CF8ED82C25B429C08D2FF6F3F5157D589D84230378A45649DE302DDB5DA6B05790DF8FE450E7BC583ABC7AAA9B831FA93A64A12C379AF6CAB1C9A6CDF3EA44A651CEC8D9F607AB0509045C6583C3C3827C0B990C4D9363139193CBDF158A50B8F989166865DBBB6D66587B7F2785F2FD4810CEB085AF5CABC6612E5544F1D0DE7CEBA180309503E625449749619C619DD15E190F46BF75788250304F3214460ACD9BA78D1626B75EBEEB8F08B9D1CB6183D1FCF37B1FFF2CD4909B05070CCF3D2275266A42A31E5204D155CE15877CD4E0C6AFA46A0550BE923F66B6BE1893383DD79D231D997FA9A89D039B96F0A3BB28D98080706FDD87EBBAFFD5199AA5C0A01E351C6D9E4A93C3CD4BC9EEBAAFB0BFFE7D9E2D796979DEDC16D9964A449DE47CA4B04DB2A192E96E396ED2286C8CFC6D584DBBEAB100D82E97BA3C88E29A2E563E30760DB21AE180EF88496722AC5DE877B85A805BECAF51F0CF000E27FC525D2F665471911153A6D19CBC5070C8404BFDE12034254A1AB038D6626DC83E9652B497CFEC9485A9EC756B7C870995DE420E12B91CDC8664E41C760C71D519381EEBC66A315B21429D11591A5D6994ABB8D2F511C64F500FBE7EAEA507B74925849338BE99843882124A2C7DEAC03FF2B8B53E0459DCF41296E5A8574DC008F089F47938C2789367C5E27FC634434A331C8A227B49B31EE9EC5425407E2C108F127CA8324CF96DCE1A3227F6EC4AEA2D9BAFA8C2E33DE6B32376C2F324A351E8678E552AB8077D1294EC0954D2B134CDDCF2937952A2C27F6A5CB719B6A14C39084095B5D42AE8FCE2A7A13A1DB1D9C7B2E1E07C0E7DBDE19C62C5EB6B030FAA55C33B202A56C15DD99FC289E14F33BA8BB68C36B0944C14EF52CC4078426DDBA5ABB05F3205882C644ADB6FBE0FE6B1920F505B4AB163DEF78363D152CA8855ADF93A84BCD7743570328AC022CB2872058F84E35D416CB7D65A6A5A6C26C547477A86DFA6C3F59DBBE3D1208CC31571777AF026B24F8AAB6C167F6A604708E34A15C77C9C5C1BF246F287A8AB4F128CF48F84CB9643DF8F6EEE07DE9731C1B61493A07041B844E507F8371476D544C1118553B3D6C5BBFEA589E4939F1A0786CBB3432AA823DD8B1F360E576148AACD5D859F8C6DB4D9EAD25DE7E3962CFD47CD40B33D3151E1AB08F521047A5104621878A246B5A0A675E6D4C3315D18A39DC8456759FBB9A6BDA2CC73E391D050B7DD4C1A2D73E07B32FBE7201194AC67C827570C17F3ADD5E58ED5951B9164483445D8C448AB486DDE3AC677443B6BA8F7ACF2617058B65500A23CAF76D83E0211D1966B89A55A8DFAECC979A05BDB64C10BAA802DAAFB1CEDEBD8EB3BBF3EDA50E5A1E97398B1E7112CD2D29D8EB71D66AD1D39F85AF41DA1CD3A3330FC8C7ADFCC91A13CE5AB5B29CF0EB2CC0D747FE5F1588E10D1BE6ED5052CF5BA84A9FF273C7B14C1763DE0B128F1A37CF746B27933880550C256A0AC8549A52EF3FC0BC8A3EED01024DDFFE6FC75D8E8EE2FC302D4AA3F556DC16852CB53A373A7555B99A1E914CBF855DA764C -->

