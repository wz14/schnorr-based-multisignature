# An implementation for schnorr-based multi-signature.

An implementation for BN and MuSig based libecc.

# Features

- pure c
- portability(inherit from libecc) for all platform
- support elliptical curve include secp256k1,secp256r1,...
- incomplete security

# Usage in Linux

```sh
git clone https://github.com/WangZhuo2000/schnorr-based-multisignature.git
cd schnorr-based-multisignature
git submodule update --init
make
```

The `bin\BN.o` and `bin\MuSig.o` is the library for your project. See more details below and you can find some examples in the `example` folder.

# Implementation Details

## BN

[origin paper](./Papers/Simple%20Schnorr%20Multi-Signatures%20with%20Applications%20to%20Bitcoin.pdf).

## MuSig

[origin paper](./Papers/Multi-signatures%20in%20the%20plain%20public-key%20model%20and%20a%20general%20forking%20lemma.pdf)

## Additional Implementation

Although that hasn't been mentioned in the original paper, I think it is necessary to implement a "sign-in" check, which is engineering considered for an adversary who wants to destroy the multi-signature system.

The origin papers describing the two multi-signatures have given rigorous security proof based on a DL assumption. But adversary still can destroy the system by sending a random string in the last round of multi-signature. Though be destroyed by an adversary, no honest signer can distinguish an adversary and an honest signer without a "sign-in" check which not be described in origin papers.

### SignInCheck Algorithm

SignInCheck(PK,partial_sig) return true/false

If SignInCheck returns false, that means the signers who send the partial_sig may be evil. If he sends an invalid message for a long time, honest signers can take action.

# Security Guarantees

- blind key generation
- ...

Send to [zhuowangy2k@outlook.com](mailto:zhuowangy2k@outlook.com) if any security problem exists or more security guarantees.

# License

The source code is licensed under GPL v3. License is available [here](./LICENSE).
