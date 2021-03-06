This is a set of tools for sybiling Cosmos airdrops by managing the distribution, staking, unstaking, and consolidation of Cosmos chains' native tokens across arbitrarily large numbers of wallets.

For example, you can easily distribute 1 JUNO to each of 100 wallets, stake all of them, claim and restake at an approximately optimal frequency (keeping in mind the gas cost of those operations), and when you are done, unstake and re-consolidate all your JUNO.

I no longer maintain any balances on Cosmos wallets and likely will not maintain any balance in the foreseeable future, so I am open-sourcing this code.

You need to have Python 3 installed, plus the following packages: `bech32`, `hdwallets`, `pycryptodome`, `protobuf`, `web3`.

You can then run `python3 cosmos.py` and a number of different options will show up in a menu. On your first run, you will want to save your seed phrase in an encrypted file (stored as `mnemonic.secret`) through the interactive menu option. (I would obviously recommend using a seed phrase that isn't associated with your primary wallets, for the sake of security.) Afterward, you will be prompted to decrypt the file with a password every time you perform operations with your wallets. As many wallets can be derived from your seed phrase as you want.

You can update IBC chain parameters or add/remove chains by editing `chains.json`.

Finally, note that the folder `deprecated` contains some ad-hoc scripts for sybiling Umee and Yeti Finance airdrops on testnet chains. These involved both IBC chain operations and EVM chain operations, and a small library to support EVM operations is supplied as `evm.py` (chain-specific settings configurable in `chains_evm.json`).
