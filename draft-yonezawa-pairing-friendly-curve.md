---
coding: utf-8

title: Pairing-Friendly Curves
docname: draft-yonezawa-pairing-friendly-curves-00
date: 2019-01-28

ipr: trust200902
area: Networking
kw: Internet-Draft
category: exp

stand_alone: yes
pi: 
    toc: yes
    tocdepth: 4
    sortrefs: yes
    symrefs : yes
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
    RFC6507:
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
        date:
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
        date:
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

--- abstract

This memo introduces pairing-friendly curves used for constructing pairing-based cryptography.
It describes recommended parameters for each security level and recent implementations of pairing-friendly curves.

--- middle

# Introduction

## Pairing-Based Cryptography

Elliptic curve cryptography is one of the important areas in recent cryptography. The cryptographic algorithms based on elliptic curve cryptography, such as ECDSA, is widely used in many applications.

Pairing-based cryptography, a variant of elliptic curve cryptography, is attracted the attention for its flexible and applicable functionality.
Pairing is a special map defined over elliptic curves.
Generally, elliptic curves is defined so that pairing is not efficiently computable since elliptic curve cryptography is broken if pairing is efficiently computable.
As the importance of pairing grows, elliptic curves where pairing is efficiently computable are studied and the special curves called pairing-friendly curves are proposed.

Thanks to the characteristics of pairing, it can be applied to construct several cryptographic algorithms and protocols such as identity-based encryption (IBE), attribute-based encryption (ABE), authenticated key exchange (AKE), short signatures and so on. Several applications of pairing-based cryptography is now in practical use.


## Applications of Pairing-Based Cryptography

Several applications using pairing-based cryptography are standardized and implemented. We show example applications available in the real world.

IETF issues RFCs for pairing-based cryptography such as identity-based cryptography {{RFC5091}}, certificateless signatures {{RFC6507}}, 
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

Let p > 3 be a prime and F_p be a finite field.
The curve defined by the following equation E is called an elliptic curve.

       E : y^2 = x^3 + A * x + B,

where A, B are in F_p and satisfies 4 * A^3 + 27 * B^2 != 0 mod p.

Solutions (x, y) for an elliptic curve E, as well as the point at infinity, O_E, 
are called F_p-rational points.
If P and Q are two points on the curve E, we can define R = P + Q as the opposite point of the intersection between the curve E and the line that intersects P and Q. 
We can define P + O_E = P = O_E + P as well.
The additive group is constructed by the well-defined operation in the set of F_p-rational points.
Similarly, a scalar multiplication S = \[a\]P for a positive integer a can be defined as an a-time addition of P.  

Typically, the cyclic additive group with a prime order r and the base point G in its group is used for the elliptic curve cryptography.
Furthermore, we define terminology used in this memo as follows.

O_E: 
: the point at infinity over an elliptic curve E.

\#E(F_p): 
: number of points on an elliptic curve E over F_p.

h: 
: a cofactor such that h =  \#E(F_p)/r.

k: 
: an embedding degree, a minimum integer such that r is a divisor of p^k - 1.

## Pairing

Pairing is a kind of the bilinear map defined over an elliptic curve.
Examples include Weil pairing, Tate pairing, optimal Ate pairing {{o-pairing}} and so on.
Especially, optimal Ate pairing is considered to be efficient to compute and mainly used for practical implementation.

Let E be an elliptic curve defined over the prime field F_p.
Let G_1 be a cyclic subgroup generated by a rational point on E with order r, and G_2 be a cyclic subgroup generated by a twisted curve E' of E with order r.
Let G_T be an order r subgroup of a field F_p^k, where k is an embedded degree.
Pairing is defined as a bilinear map e: (G_1, G_2) -> G_T
satisfying the following properties:

1. Bilinearity: for any S in G_1, T in G_2, a, b in Z_r, we have the relation e(\[a\]S, \[b\]T) = e(S, T)^{a * b}.
2. Non-degeneracy: for any T in G_2, e(S, T) = 1 if and only if S = O_E.
    Similarly, for any S in G_1, e(S, T) = 1 if and only if T = O_E.
3. Computability: for any S in G_1 and T in G_2, the bilinear map is efficiently computable.

## Barreto-Naehrig Curve {#BNdef}

A BN curve {{BN05}} is one of the instantiations of pairing-friendly curves proposed in 2005. A pairing over BN curves constructs optimal Ate pairings.

A BN curve is an elliptic curve E defined over a finite field F_p, where p is more than or equal to 5, such that p and its order r are prime numbers parameterized by

       p = 36u^4 + 36u^3 + 24u^2 + 6u + 1
       r = 36u^4 + 36u^3 + 18u^2 + 6u + 1

for some well chosen integer u. The elliptic curve has an equation of the form E: y^2 = x^3 + b, where b is an element of multiplicative group of order p.

BN curves always have order 6 twists. If w is an element which is neither a square nor a cube in a finite field F_p^2, the twisted curve E' of E is defined over a finite field F_p^2 by the equation E': y^2 = x^3 + b' with b' = b/w or b' = bw.

A pairing e is defined by taking G_1 as a cyclic group composed by rational points on the elliptic curve E, G_2 as a cyclic group composed by rational points on the elliptic curve E', and G_T as a multiplicative group of order p^12.

## Barreto-Lynn-Scott Curve {#BLSdef}

A BLS curve {{BLS02}} is another instantiations of pairings proposed in 2002. Similar to BN curves, a pairing over BLS curves constructs optimal Ate pairings.

A BLS curve is an elliptic curve E defined over a finite field F_p by an equation of the form E: y^2 = x^3 + b and has a twist of order 6 defined in the same way as BN curves. In contrast to BN curves, a BLS curve does not have a prime order but its order is divisible by a large parameterized prime r and the pairing will be defined on the r-torsions points.

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

- The elliptic curve discrete logarithm problem (ECDLP) in G_1 and G_2
- The finite field discrete logarithm problem (FFDLP) in G_T

There are other hard problems over pairing-friendly curves, which are used for proving the security of pairing-based cryptography. Such problems include bilinear computational Diffie-Hellman (BCDH) problem, bilinear decisional Diffie-Hellman (BDDH) problem, gap BDDH problem, etc {{ECRYPT}}.
Almost all of these variants are reduced to the hardness of discrete logarithm problems described above and believed to be easier than the discrete logarithm problems.

There would be the case where the attacker solves these reduced problems to break the pairing-based cryptography. Since such attacks have not been discovered yet, we discuss the hardness of the discrete logarithm problems in this memo.

The security level of pairing-friendly curves is estimated by the computational cost of the most efficient algorithm to solve the above discrete logarithm problems. 
The well-known algorithms for solving the discrete logarithm problems includes Pollard's rho algorithm {{Pollard78}}, Index Calculus {{IndexCalculus}} and so on. 
In order to make index calculus algorithms more efficient, number field sieve (NFS) algorithms are utilized.

In addition, the special case where the cofactors of G_1, G_2 and G_T are small should be taken care {{subgroup}}.
In such case, the discrete logarithm problem can be efficiently solved.
One has to choose parameters so that the cofactors of G_1, G_2 and G_T contain no prime factors smaller than |G_1|, |G_2| and |G_T|.

## Impact of the Recent Attack {#impact}

In 2016, Kim and Barbulescu proposed a new variant of the NFS algorithms, the extended number field sieve (exTNFS), which drastically reduces the complexity of solving FFDLP {{KB16}}.
Due to exTNFS, the security level of pairing-friendly curves asymptotically dropped down.
For instance, Barbulescu and Duquesne estimates that the security of the BN curves which was believed to provide 128 bits of security (BN256, for example) dropped down to approximately 100 bits {{BD18}}.

Some papers show the minimum bitlength of the parameters of pairing-friendly curves for each security level when applying exTNFS as an attacking method for FFDLP.
For 128 bits of security, Menezes, Sarkar and Singh estimated the minimum bitlength of p of BN curves after exTNFS as 383 bits, and that of BLS12 curves as 384 bits {{MSS17}}.
For 256 bits of security, Kiyomura et al. estimated the minimum bitlength of p^k of BLS48 curves as 27,410 bits, which implied 572 bits of p {{Kiy}}.

# Security Evaluation of Pairing-Friendly Curves

We give security evaluation for pairing-friendly curves based on the evaluating method presented in {{security_pfc}}. We also introduce secure parameters of pairing-friendly curves for each security level.
The parameters introduced here are chosen with the consideration of security, efficiency and global acceptance.

For security, we introduce 100 bits, 128 bits and 256 bits of security.
We note that 100 bits of security is no longer secure
and recommend 128 bits and 256 bits of security for secure applications.
We follow TLS 1.3 which specifies the cipher suites with 128 bits and 256 bits of security as mandatory-to-implement for the choice of the security level.

Implementors of the applications have to choose the parameters with appropriate security level according to the security requirements of the applications.
For efficiency, we refer to the benchmark by mcl {{mcl}} for 128 bits of security, and by Kiyomura et al. {{Kiy}} for 256 bits of security and choose sufficiently efficient parameters.
For global acceptance, we give the implementations of pairing-friendly curves in section {{impl}}.


## For 100 Bits of Security

Before exTNFS, BN curves with 256-bit size of underlying finite field (so-called BN256) were considered to have 128 bits of security. After exTNFS, however, the security level of BN curves with 256-bit size of underlying finite field fell into 100 bits.

Implementors who will newly develop the applications of pairing-based cryptography SHOULD NOT use BN256 as a pairing-friendly curve when their applications require 128 bits of security.
In case an application does not require higher security level and is sufficient to have 100 bits of security (i.e. IoT), implementors MAY use BN256.

## For 128 Bits of Security

A BN curve with 128 bits of security is shown in {{BD18}}, which we call BN462. BN462 is defined by a parameter u = 2^114 + 2^101 - 2^14 - 1 for the definition in {{BNdef}}. Defined by u, the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 - 4 and E': y^2 = x^3 - 4 * (1 + i), where i is an element of an extension field F_p^2, respectively. The size of p becomes 462-bit length. 

A BLS12 curve with 128 bits of security shown in {{BD18}} is parameterized by u = -2^77 - 2^71 - 2^64 + 2^37 + 2^35 + 2^22 - 2^5, which we call BLS12-461.
Defined by u, the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 - 2 and E': y^2 = x^3 - 2 / (1 + i), respectively.
The size of p becomes 461-bit length. The curve BLS12-461 is subgroup-secure.

There is another BLS12 curve stating 128 bits of security, BLS12-381 {{BLS12-381}}. 
It is defined by a parameter u = -0xd201000000010000. 
Defined by u, the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 + 4 and E': y^2 = x^3 + 4(i + 1), respectively.

We have to note that, according to {{MSS17}}, the bit length of p for BLS12 to achieve 128 bits of security is calculated as 384 bits and more, which BLS12-381 does not satisfy. Although the computational time is conservatively estimated by 2^110 when exTNFS is applied with index calculus, there is no currently published efficient method for such computational time. They state that BLS12-381 achieves 127-bit security level evaluated by the computational cost of Pollard's rho.

## For 256 Bits of Security

As shown in {{impact}}, it is unrealistic to achieve 256 bits of security by BN curves since the minimum size of p becomes too large to implement.
Hence, we consider BLS48 for 256 bits of security.

A BLS48 curve with 256 bits of security is shown in {{Kiy}}, which we call BLS48-581. 
It is defined by a parameter u = -1 + 2^7 - 2^10 - 2^30 - 2^32 and the elliptic curve E and its twisted curve E' are represented by E: y^2 = x^3 + 1 and E': y^2 = x^3 - 1/w, 
where w is an element of an extension field F_p^8.
The size of p becomes 581-bit length.

# Implementations of Pairing-Friendly Curves {#impl}

We show the pairing-friendly curves selected by existing standards, applications and cryptographic libraries.

<!-- standards -->

ISO/IEC 15946-5 {{ISOIEC15946-5}} shows examples of BN curves with the size of 160, 192, 224, 256, 384 and 512 bits of p. There is no action so far after the proposal of exTNFS.

TCG adopts an BN curve of 256 bits specified in ISO/IEC 15946-5 (TPM_ECC_BN_P256) and of 638 bits specified by their own (TPM_ECC_BN_P638).
FIDO Alliance {{FIDO}} and W3C {{W3C}} adopt the BN curves specified in TCG, a 512-bit BN curve shown in ISO/IEC 15946-5 and another 256-bit BN curve.

<!-- applications -->

MIRACL {{MIRACL}} implements BN curves and BLS12 curves.

Zcash implemented a BN curve (named BN128) in their library libsnark {{libsnark}}.
After exTNFS, they propose a new parameter of BLS12 as BLS12-381 {{BLS12-381}}
and publish its experimental implementation {{zkcrypto}}.

Cloudflare implements a 256-bit BN curve (bn256) {{cloudflare-bn256}}.
There is no action so far after exTNFS.

Ethereum 2.0 adopts BLS12-381 (BLS12_381), BN curves with 254 bits of p (CurveFp254BNb) and 382 bits of p (CurveFp382_1 and CurveFp382_2) {{go-bls}}. Their implementation calls mcl {{mcl}} for pairing computation.

<!-- libraries -->

Cryptographic libraries which implement pairings include PBC {{PBC}}, mcl {{mcl}}, RELIC {{relic}}, TEPLA {{TEPLA}}, AMCL {{AMCL}}, Intel IPP {{intel-ipp}} and a library by Kyushu University {{bls48}}.

{{adoption}} shows the adoption of pairing-friendly curves in existing standards, applications and libraries.

<!-- Something wrong with PBC-->

| Category | Name | 100 bit | 128 bit | 256 bit |
| standards | ISO/IEC {{ISOIEC15946-5}} | BN256 | BN384 | |
| | TCG | BN256 | | |
| | FIDO/W3C | BN256 | | |
| applications | MIRACL | BN254 | BLS12 | |
| | Zcash | BN128 (CurveSNARK) | BLS12-381 | |
| | Cloudflare | BN256 | | |
| | Ethereum | BN254 | BN382 (\*) / BLS12-381 (\*)  | |
| libraries | PBC | BN254 / BN_SNARK1 | BN381_1 (\*) / BN462 / BLS12-381 | |
| | mcl | BN254 / BN_SNARK1 | BN381_1 (\*) / BN462 / BLS12-381 | |
| | RELIC {{relic}} | BN254 / BN256 | BLS12-381 / BLS12-455 | |
| | TEPLA | BN254 | | |
| | AMCL | BN254 / BN256 | BLS12-381 (\*) / BLS12-383 (\*) / BLS12-461 | BLS48 |
| | Intel IPP  | BN256 | | |
| | Kyushu Univ. | | | BLS48 |
{: #adoption title="Adoption of Pairing-Friendly Curves"} 

(*) There is no research result on the security evaluation, but the implementers states that they satisfy 128 bits of security.

# Security Considerations

This memo entirely describes the security of pairing-friendly curves, and introduces secure parameters of pairing-friendly curves. We give these parameters in terms of security, efficiency and global acceptance. The parameters for 100, 128 and 256 bits of security are introduced since the security level will different in the requirements of the pairing-based applications.

# IANA Considerations

This document has no actions for IANA.

# Acknowledgements

The authors would like to thank Akihiro Kato for his significant contribution to the early version of this memo.

# Change log

--- back

# Test Vectors of Optimal Ate Pairing

(TBD)
