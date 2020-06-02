# An implemention for schnorr based multi-signature.

An implementation for BN and MuSig based libecc.

# Features

- pure c
- portability(inherit from libecc) for all platform
- support elliptical curve include secp256k1,secp256r1,...
- incomplete security

# Usage in linux

```sh
git clone https://github.com/WangZhuo2000/schnorr-based-multisignature.git
cd schnorr-based-multisignature
git submodule init
make
```

The `bin\BN.o` and `bin\MuSig.o` is the library for your project.See more details below and you can find some examples in `example` folder.

# Implementation Details

## BN

[origin paper](./Papers/Simple%20Schnorr%20Multi-Signatures%20with%20Applications%20to%20Bitcoin.pdf).

## MuSig

[origin paper](./Papers/Multi-signatures%20in%20the%20plain%20public-key%20model%20and%20a%20general%20forking%20lemma.pdf)

## Additional Implementation

Although that hasn't be mentioned in the orginal paper, I think it is necessary to implemente a "sign-in" check, which is a engineering consider for adversary who want to destroy the multi-signature system.

The origin papers describing the two multi-signatures have give a rigorous security proof based a DL assumption.But adversary still can destory the system by sending a random string in the last round of multi-signature.Though be destroyed by a adversary, no honest signer can distinguish a adversary and a honest signer without a "sign-in" check which not be described in origin papers.

### SignInCheck Algorithm

SignInCheck(PK,partial_sig) return true/false

If SignInCheck return false, that means the signers who send the partial_sig may be evil.If he send a invalid message during a long time, honest signers can take a action.

# Security Guarantees

- blind key generation
- ...

Send to [zhuowangy2k@outlook.com](mailto:zhuowangy2k@outlook.com) if any security problem exists or more secuirty guarantees.

# License

The source code is licensed under GPL v3. License is available [here](./LICENSE).
