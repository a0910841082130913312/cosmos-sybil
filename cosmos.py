import os
import sys
import json
import ecdsa
import base64
import bech32
import random
import hashlib
import requests
import hdwallets
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from functools import cache

# Interfaces compiled with protoc from protobuf specifications
import interfaces.any_pb2 as Any
import interfaces.coin_pb2 as Coin
import interfaces.msg_send_pb2 as MsgSend
import interfaces.msg_delegate_pb2 as MsgDelegate
import interfaces.msg_withdraw_delegator_reward_pb2 as MsgWithdrawDelegatorReward
import interfaces.pubkey_pb2 as PubKey
import interfaces.tx_pb2 as Tx

# Configurable parameters
MNEMONIC = 'mnemonic.secret'
CHAIN_LIST = 'chains.json'
SYNC_MODE = 'BROADCAST_MODE_BLOCK'
PRECISION = 3
MIN_REWARDS_THRESHOLD = 0.1

# Constant parameters related to mnemonic -> wallet derivation
# Do not change
PBKDF2_ROUNDS = 2048

# AES encryption of a string
# Based on https://stackoverflow.com/a/44212550
def encrypt(key, source):
  key = key.encode('utf-8')
  source = source.encode('utf-8')
  key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
  IV = Random.new().read(AES.block_size)  # generate IV
  encryptor = AES.new(key, AES.MODE_CBC, IV)
  padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
  source += bytes([padding]) * padding
  data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
  return base64.b64encode(data).decode('utf-8')

# Decryption of an AES-encrypted string
# Based on https://stackoverflow.com/a/44212550
def decrypt(key, source):
  key = key.encode('utf-8')
  source = base64.b64decode(source.encode("utf-8"))
  key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
  IV = source[:AES.block_size]  # extract the IV from the beginning
  decryptor = AES.new(key, AES.MODE_CBC, IV)
  data = decryptor.decrypt(source[AES.block_size:])  # decrypt
  padding = data[-1]  # pick the padding value from the end
  if data[-padding:] != bytes([padding]) * padding:
    raise ValueError('Invalid padding...')
  return data[:-padding].decode('utf-8')  # remove the padding

# Prompts the user to encrypt and save their mnemonic phrase
def encrypt_mnemonic():
  key = input('Password: ').strip()
  key_conf = input('Confirm password: ').strip()
  assert key == key_conf, 'passwords do not match'
  mnemonic = input('Mnemonic phrase: ').lower().strip()
  open(MNEMONIC, 'w').write(encrypt(key, mnemonic))

# Decrypts the saved mnemonic phrase given user-specified password
def decrypt_mnemonic():
  assert os.path.exists(MNEMONIC), 'encrypted mnemonic file does not exist'
  key = input('Password: ').strip()
  return decrypt(key, open(MNEMONIC).read().strip())

# Converts a mnemonic seed (without passphrase) to corresponding binary seed
# Based on https://github.com/trezor/python-mnemonic/blob/master/src/mnemonic/mnemonic.py
def mnemonic_to_seed(mnemonic):
  mnemonic_bytes = mnemonic.encode('utf-8')
  passcode_bytes = 'mnemonic'.encode('utf-8')
  stretched = hashlib.pbkdf2_hmac('sha512', mnemonic_bytes, passcode_bytes, PBKDF2_ROUNDS)
  return stretched[:64]

# Converts a mnemonic seed to a private key, given a specific account ID (0, 1, ...) and chain identifier
# The chain identifier is necessary to get the correct coin type in the derivation path
# Based on https://github.com/hukkin/cosmospy/blob/master/src/cosmospy/_wallet.py
def mnemonic_to_privkey(mnemonic, id, chain):
  binary_seed = mnemonic_to_seed(mnemonic)
  hd_wallet = hdwallets.BIP32.from_seed(binary_seed)
  derivation_path = f'm/44\'/{chain_info(chain)["derivationCoinType"]}\'/0\'/0/{id}'
  privkey = hd_wallet.get_privkey_from_path(derivation_path)
  return privkey

# Converts a private key to a public key
# Based on https://github.com/hukkin/cosmospy/blob/master/src/cosmospy/_wallet.py
def privkey_to_pubkey(privkey: bytes) -> bytes:
  privkey_obj = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
  pubkey_obj = privkey_obj.get_verifying_key()
  return pubkey_obj.to_string('compressed')

# Converts a public key to a bech32 address given a chain
def pubkey_to_address(pubkey, chain):
  prefix = chain_info(chain)['prefix']
  s = hashlib.new('sha256', pubkey).digest()
  r = hashlib.new('ripemd160', s).digest()
  five_bit_r = bech32.convertbits(r, 8, 5)
  return bech32.bech32_encode(prefix, five_bit_r)

# Converts a public/private keypair and a chain prefix to a bech32 encoded address
def keypair_to_address(pubkey, privkey, chain):
  bech32_address = pubkey_to_address(pubkey, chain)
  return {
    'chain': chain,
    'address': bech32_address,
    'pubkey': pubkey,
    'privkey': privkey
    }

# Returns a list of accounts given a mnemonic, max account number, and list of chain prefixes
def mnemonic_to_accounts(mnemonic, num_accounts, chains):
  accounts = []
  for id in range(num_accounts):
    account = {'id': id, 'addresses': []}
    for chain in chains:
      print(f'Retrieving data for account {id} on {chain}...')
      privkey = mnemonic_to_privkey(mnemonic, id, chain)
      pubkey = privkey_to_pubkey(privkey)
      address = keypair_to_address(pubkey, privkey, chain)
      account['addresses'].append(address)
    accounts.append(account)
  return accounts

# Returns list of chains in config file
@cache
def chain_list():
  return [chain['chain'] for chain in json.loads(open(CHAIN_LIST).read())]

# Returns specific config info for a given chain
@cache
def chain_info(chain):
  chains = json.loads(open(CHAIN_LIST).read())
  for c in chains:
    if c['chain'] == chain:
      return c
  raise RuntimeError('chain not found')

# Queries API given a specific API call and returns corresponding JSON object
def query_api(api_call):
  #print(f'Querying API: {api_call}')
  return requests.get(api_call).json()

# Returns (account number, sequence) for a given address on a given chain
def get_account_number_and_sequence(chain, address):
  api_call = f'{chain_info(chain)["api"]}/cosmos/auth/v1beta1/accounts/{address}'
  data = query_api(api_call)
  return (int(data['account']['account_number']), int(data['account']['sequence']))

# Given an address object, adds account number and sequence infp
def add_account_number_and_sequence(address):
  account_number, sequence = get_account_number_and_sequence(address['chain'], address['address'])
  address['account_number'] = account_number
  address['sequence'] = sequence

# Returns the native token balance on a given chain for a given address
def get_wallet_balance(chain, address):
  api_call = f'{chain_info(chain)["api"]}/cosmos/bank/v1beta1/balances/{address}'
  data = query_api(api_call)
  token_balance = 0
  for balance in data['balances']:
    if balance['denom'] == chain_info(chain)['token']:
      token_balance = int(balance['amount'])
  return token_balance / (10 ** chain_info(chain)['decimals'])

# Returns all delegated balances of native tokens on a given chain for a given address
def get_all_delegated(chain, address):
  api_call = f'{chain_info(chain)["api"]}/cosmos/staking/v1beta1/delegations/{address}'
  data = query_api(api_call)
  return data['delegation_responses']

# Returns the total amount of staked native tokens on a given chain for a given address
def get_total_delegated(chain, address):
  api_call = f'{chain_info(chain)["api"]}/cosmos/staking/v1beta1/delegations/{address}'
  data = query_api(api_call)
  total_delegated = sum([int(delegation['balance']['amount']) for delegation in data['delegation_responses']])
  return total_delegated / (10 ** chain_info(chain)['decimals'])

# Returns a dict with information about unclaimed staking rewards on a given chain for a given address
#  validators => list of (validator_address, rewards) where rewards is not decimals-corrected
#  total_rewards => total pending rewards, decimals-corrected
def get_delegation_rewards(chain, address):
  api_call = f'{chain_info(chain)["api"]}/cosmos/distribution/v1beta1/delegators/{address}/rewards'
  data = query_api(api_call)
  validators = []
  total_rewards = 0
  for validator in data['rewards']:
    for reward in validator['reward']:
      if reward['denom'] == chain_info(chain)['token']:
        reward_amt = float(reward['amount'])
        validators.append((validator['validator_address'], reward_amt))
        total_rewards += reward_amt
        break
  total_rewards = total_rewards / (10 ** chain_info(chain)['decimals'])
  return {'validators': validators, 'total_rewards': total_rewards}

# Returns a dict giving all native token balances for a given chain and address:
#   wallet => decimal-adjusted wallet balance
#   delegated => decimal-adjusted delegated token balance
#   rewards => see get_delegation_rewards(...) documentation
def get_all_token_balances(chain, address):
  wallet = get_wallet_balance(chain, address)
  delegated = get_total_delegated(chain, address)
  rewards = get_delegation_rewards(chain, address)
  return {'wallet': wallet, 'delegated': delegated, 'rewards': rewards}

# Determines whether it's desirable to claim and restake tokens based on:
#   wallet_balance, number of tokens unstaked in wallet
#   min_wallet_balance, number of tokens to always keep in wallet for gas
#   staked_amount, number of tokens currently staked
#   staking_apr, the APR of token staking given as, e.g. staking_apr=15 => APR of 15%
#   pending_rewards, amount of tokens that can be claimed from validators
#   cost, the total transaction fee associated with claiming and restaking
#   num_transactions, number of transactions required to claim and restake (usually 2)
# Returns (should_claim, diff), where:
#   should_claim is either True or False
#   diff indicates how many more rewards need to accrue before claiming is optimal
def optimal_restaking(wallet_balance, min_wallet_balance, staked_amount, staking_apr, pending_rewards, cost, silent=True):
  # Immediately terminate if staking nonzero amount still leaves wallet balance too low
  if wallet_balance + pending_rewards - cost < min_wallet_balance:
    if not silent:
      print('Skipping optimization as balances are insufficient')
    return (False, None)

  # Otherwise, treat as if pending rewards include wallet balance, excluding maintenance minimum
  pending_rewards += wallet_balance - min_wallet_balance

  # Calculates rough approximation of annual return given:
  #   p, principal
  #   apr, given as e.g. apr=15 => 15% apr
  #   cost, the transaction fee to claim and restake
  #   freq, number of days between each restake
  def annual_return(p, apr, cost, freq):
    return p * (1 + (apr / 100) * freq / 365) ** (365 / freq) - cost * (365 / freq)

  # Calculates exact pending rewards given principal (p), apr, and time (t)
  def calc_pending_rewards(p, apr, t):
    return p * apr / 100 / 365  * t

  # Search for optimal restaking frequency
  max_freq = None
  max_return = -1
  max_pending_rewards = None
  for freq in range(1, 365):
    r = annual_return(staked_amount, staking_apr, cost, freq)
    if r > max_return:
      max_freq, max_return, max_pending_rewards = freq, r, calc_pending_rewards(staked_amount, staking_apr, freq)

  # Print out optimization results
  if not silent:
    print(f'For principal={staked_amount}, APR={staking_apr}%, total gas={cost}, optimal restaking time is:')
    print(f'  n={max_freq} days, with {max_pending_rewards} pending rewards')

  # Return results
  should_claim = pending_rewards >= max_pending_rewards
  return (should_claim, max_pending_rewards - pending_rewards)

# Given a list of accounts and a chain name, select the address object corresponding to that chain
def get_specific_address(account, chain):
  address = None
  for addr in account['addresses']:
    if addr['chain'] == chain:
      address = addr
  assert address is not None, f'address for {chain} not found'
  return address

# Initializes and returns a dictionary representing an empty transaction
def initialize_transaction(address):
  try:
    add_account_number_and_sequence(address)
  except:
    raise RuntimeError('likely trying to send transaction from uninitialized account with 0 tokens for gas')
  return {
    'address': address,
    'gas': 0,
    'fee': 0,
    'tx_body': Tx.TxBody(),
    'tx_raw': Tx.TxRaw()
  }

# Given a transaction generated by initialize_transaction, adds a transfer operation for the chain's native token
def tx_add_transfer(tx, recipient, amount):
  # Change amount transferred into integer with implied decimals, rounded down
  amount = amount * (10 ** chain_info(tx['address']['chain'])['decimals'])
  amount = str(int(amount))

  # Increment total gas and fee
  tx['gas'] += chain_info(tx['address']['chain'])['gasTransfer']
  tx['fee'] += chain_info(tx['address']['chain'])['feeTransfer']

  # Create and append message object
  msg = MsgSend.MsgSend()
  msg.from_address = tx['address']['address']
  msg.to_address = recipient
  _amount = Coin.Coin()
  _amount.denom = chain_info(tx['address']['chain'])['token']
  _amount.amount = amount
  msg.amount.append(_amount)
  msg_any = Any.Any()
  msg_any.Pack(msg)
  msg_any.type_url = '/cosmos.bank.v1beta1.MsgSend'
  tx['tx_body'].messages.append(msg_any)

# Given a transaction generated by initialize_transaction, adds a validator delegation operation
def tx_add_delegation(tx, validator, amount):
  # Change amount to delegate into integer with implied decimals, rounded down
  amount = amount * (10 ** chain_info(tx['address']['chain'])['decimals'])
  amount = str(int(amount))

  # Increment total gas and fee
  tx['gas'] += chain_info(tx['address']['chain'])['gasStake']
  tx['fee'] += chain_info(tx['address']['chain'])['feeStake']

  # Create and append message object
  msg = MsgDelegate.MsgDelegate()
  msg.delegator_address = tx['address']['address']
  msg.validator_address = validator
  _amount = Coin.Coin()
  _amount.denom = chain_info(tx['address']['chain'])['token']
  _amount.amount = amount
  msg.amount.CopyFrom(_amount)
  msg_any = Any.Any()
  msg_any.Pack(msg)
  msg_any.type_url = '/cosmos.staking.v1beta1.MsgDelegate'
  tx['tx_body'].messages.append(msg_any)

# Given a transaction generated by initialize_transaction, adds a rewards claiming operation
def tx_claim_rewards(tx, validator):
  # Increment total gas and fee
  tx['gas'] += chain_info(tx['address']['chain'])['gasClaim']
  tx['fee'] += chain_info(tx['address']['chain'])['feeClaim']

  # Create and append message object
  msg = MsgWithdrawDelegatorReward.MsgWithdrawDelegatorReward()
  msg.delegator_address = tx['address']['address']
  msg.validator_address = validator
  msg_any = Any.Any()
  msg_any.Pack(msg)
  msg_any.type_url = '/cosmos.distribution.v1beta1.MsgWithdrawDelegatorReward'
  tx['tx_body'].messages.append(msg_any)

# Internal method for protobuf object structure
def get_auth_info(tx):
  auth_info = Tx.AuthInfo()
  auth_info.signer_infos.append(get_signer_infos(tx))
  auth_info.fee.gas_limit = tx['gas']
  fee = Coin.Coin()
  fee.amount = str(tx['fee'])
  fee.denom = chain_info(tx['address']['chain'])['token']
  auth_info.fee.amount.append(fee)
  return auth_info

# Internal method for protobuf object structure
def get_signer_infos(tx):
  signer_infos = Tx.SignerInfo()
  signer_infos.sequence = tx['address']['sequence']
  pubkey = PubKey.PubKey()
  pubkey.key = tx['address']['pubkey']
  signer_infos.public_key.Pack(pubkey)
  signer_infos.public_key.type_url = '/cosmos.crypto.secp256k1.PubKey'
  signer_infos.mode_info.single.mode = 1
  return signer_infos

# Internal method for protobuf object structure
def get_sign_doc(tx):
  sign_doc = Tx.SignDoc()
  sign_doc.body_bytes = tx['tx_body'].SerializeToString()
  sign_doc.auth_info_bytes = get_auth_info(tx).SerializeToString()
  sign_doc.chain_id = chain_info(tx['address']['chain'])['chainId']
  sign_doc.account_number = tx['address']['account_number']
  return sign_doc

# Internal method for protobuf object structure
def get_signatures(tx):
  privkey = ecdsa.SigningKey.from_string(tx['address']['privkey'], curve=ecdsa.SECP256k1)
  signature_compact = privkey.sign_deterministic(
    get_sign_doc(tx).SerializeToString(),
    hashfunc=hashlib.sha256,
    sigencode=ecdsa.util.sigencode_string_canonize,
  )
  return signature_compact

# Finalizes a transaction and returns a 'pushable' string ready for API submission
def generate_pushable_tx(tx):
  tx['tx_raw'].body_bytes = tx['tx_body'].SerializeToString()
  tx['tx_raw'].auth_info_bytes = get_auth_info(tx).SerializeToString()
  tx['tx_raw'].signatures.append(get_signatures(tx))
  tx_raw = base64.b64encode(bytes(tx['tx_raw'].SerializeToString())).decode('utf-8')
  #return json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': SYNC_MODE, 'params': {'tx': tx_raw}})
  return json.dumps({'tx_bytes': tx_raw, 'mode': SYNC_MODE})

# Sends a complete transaction to the corresponding chain
def send_transaction(tx):
  print('Preparing and sending transaction...')
  chain = tx['address']['chain']
  pushable_tx = generate_pushable_tx(tx)
  tx['address']['sequence'] += 1
  api_call = f'{chain_info(chain)["api"]}/cosmos/tx/v1beta1/txs'
  r = requests.post(api_call, data=pushable_tx)
  if r.status_code == 200:
    print(f'Transaction succeeded with status code {r.status_code} ({r.reason}).')
  else:
    print(f'Transaction failed with status code {r.status_code} ({r.reason}).')

# Returns a list of all accounts derived from an encrypted mnemonic phrase for the specified chains
# Accepts user input for the number of wallets derived from the mnemonic
def get_accounts(chains):
  accounts = mnemonic_to_accounts(decrypt_mnemonic(), int(input('Number of accounts: ')), chains)
  return accounts

# Prints out item selection menu
def print_item_menu(items):
  for i, items in enumerate(items):
    print(f'[{i}] {items}')

# Presents the user with a menu to select a chain
def select_chain(chains):
  print_item_menu(chains)
  selection = input(f'Enter an index from 0 to {len(chains)}: ')
  selection = int(selection)
  assert selection >= 0 and selection < len(chains), 'chain selection out of range'
  return chains[selection]

# Asks the user to select one item from a list of items
def select_item(items):
  selection = input(f'Enter a single index from 0 to {len(items) - 1}: ')
  selection = int(selection)
  assert selection >= 0 and selection < len(items), 'index selection out of range'
  return items[selection]

# Asks the user to select one or multiple items from a list of items
# Accepts "all"
def select_items(items):
  selection = input(f'Enter a range of indices ("0, 1, 2-3") from 0 to {len(items) - 1}, or "all": ')
  if selection.strip().lower() == 'all':
    return items
  selection = selection.strip().split(',')
  indices = []
  for s in selection:
    assert s.count('-') <= 1, 'range incorrectly formatted'
    if '-' in s:
      first, last = s.split('-')
      first, last = int(first), int(last)
      indices.extend(list(range(first, last + 1)))
    else:
      indices.append(int(s))
  assert min(indices) >= 0 and max(indices) < len(items), 'index selection out of range'
  return [items[i] for i in indices]

# Rounds a number to decimals of precision
def round(n):
  return int(float(n) * (10 ** PRECISION)) / (10 ** PRECISION)

# Asks the user to enter a token quantity
def select_amount():
  selection = input('Enter a number: ')
  selection = round(selection)
  return selection

# Asks the user to enter a token quantity or "max" for max possible:
def select_amount_or_max():
  selection = input('Enter a number, or "max" for max possible: ')
  if selection != "max":
    selection = round(selection)
  return selection

# Asks the user to confirm (y/n)
def confirm():
  text = input('Enter "y" to confirm: ')
  text = text.strip().lower()
  if text == 'y' or text == 'yes':
    return True
  return False

# Shows native token balances on chains of interest
def show_balances():
  chains = chain_list()
  print('> Select one or more chains')
  print_item_menu(chains)
  chains = select_items(chains)
  print(f'> Selected chains: {", ".join(chains)}')
  print('> Loading accounts...')
  accounts = get_accounts(chains)
  chain_balances = {chain: {'wallet': 0, 'delegated': 0, 'rewards': 0} for chain in chains}
  for account in accounts:
    print(f'Fetching token balances for account {account["id"]}...')
    for address in account['addresses']:
      chain = address['chain']
      if chain in chains:
        balances = get_all_token_balances(chain, address['address'])
        chain_balances[chain]['wallet'] += balances['wallet']
        chain_balances[chain]['delegated'] += balances['delegated']
        chain_balances[chain]['rewards'] += balances['rewards']['total_rewards']
  for chain in chains:
    chain_balances[chain]["total"] = chain_balances[chain]["wallet"] + chain_balances[chain]["delegated"] + chain_balances[chain]["rewards"]
    info = f'{chain} balances:'
    info += f'\n  {chain_balances[chain]["wallet"]} {chain_info(chain)["symbol"]} in wallets'
    info += f'\n  {chain_balances[chain]["delegated"]} {chain_info(chain)["symbol"]} delegated'
    info += f'\n  {chain_balances[chain]["rewards"]} {chain_info(chain)["symbol"]} in pending rewards'
    info += f'\n  Total: {chain_balances[chain]["total"]} {chain_info(chain)["symbol"]}'
    print(info)

# Interactive prompts for one -> many native token transfers
def multisend_one_many():
  chains = chain_list()
  print('> Select a chain for the transfer')
  chain = select_chain(chains)
  print(f'> Chain selected: {chain}')
  print('> Loading accounts...')
  accounts = get_accounts([chain])
  print('> Select a source account for the transfer')
  account_from = select_item(accounts)
  address_from = get_specific_address(account_from, chain)
  print(f'> Selected account {account_from["id"]} with address {address_from["address"]}.')
  wallet_balance = get_wallet_balance(chain, address_from['address'])
  symbol = chain_info(chain)['symbol']
  print(f'> Wallet balance: {wallet_balance} {symbol}')
  print('> Select one or multiple destination accounts')
  accounts_to = select_items(accounts)
  print(f'> Selected {len(accounts_to)} destination accounts ({", ".join([str(account["id"]) for account in accounts_to])}).')
  print('> Choose the number of tokens per transfer')
  amount = select_amount()
  total_amount = len(accounts_to) * amount
  min_balance = chain_info(chain)['minBalance'] / (10 ** chain_info(chain)['decimals'])
  fee = len(accounts_to) * chain_info(chain)['feeTransfer'] / (10 ** chain_info(chain)['decimals'])
  print(f'> Total transfer quantity: {total_amount} {symbol}')
  print(f'> Minimum wallet balance: {min_balance} {symbol}')
  print(f'> Estimated transaction fee: {fee} {symbol}')
  print(f'> Remaining in wallet after transfer: {wallet_balance - total_amount - fee} {symbol}')
  if wallet_balance < total_amount:
    print(f'! Exiting: Insufficient tokens in wallet.')
    return
  if wallet_balance - total_amount - fee < min_balance:
    print(f'! Exiting: Transfer would leave wallet below minimum balance.')
    return
  print('> Confirm transaction details and proceed')
  proceed = confirm()
  if not proceed:
    print(f'! Exiting: User rejected transaction.')
    return
  tx = initialize_transaction(address_from)
  for account_to in accounts_to:
    address_to = get_specific_address(account_to, chain)
    tx_add_transfer(tx, address_to['address'], amount)
  send_transaction(tx)

# Interactive prompts for many -> one native token transfers
def multisend_many_one():
  chains = chain_list()
  print('> Select a chain for the transfer')
  chain = select_chain(chains)
  print(f'> Chain selected: {chain}')
  print('> Loading accounts...')
  accounts = get_accounts([chain])
  print('> Select one or multiple source accounts')
  accounts_from = select_items(accounts)
  print(f'> Selected {len(accounts_from)} source accounts ({", ".join([str(account["id"]) for account in accounts_from])}).')
  print('> Select a destination account for the transfer')
  account_to = select_item(accounts)
  address_to = get_specific_address(account_to, chain)
  print(f'> Selected account {account_to["id"]} with address {address_to["address"]}.')
  print('> Choose the number of tokens per transfer ("max" is an allowable option)')
  amount = select_amount_or_max()
  min_balance = chain_info(chain)['minBalance'] / (10 ** chain_info(chain)['decimals'])
  fee = chain_info(chain)['feeTransfer'] / (10 ** chain_info(chain)['decimals'])
  symbol = chain_info(chain)['symbol']
  print(f'> Sending {amount} {symbol} from {len(accounts_from)} wallets to account {account_to["id"]}')
  print('> Confirm transaction details and proceed')
  proceed = confirm()
  if not proceed:
    print(f'! Exiting: User rejected transaction.')
    return
  for account_from in accounts_from:
    address_from = get_specific_address(account_from, chain)
    print(f'> Processing transfer from wallet {account_from["id"]} ({address_from["address"]})')
    wallet_balance = get_wallet_balance(chain, address_from['address'])
    transfer_amount = round(wallet_balance - min_balance) - fee if amount == 'max' else amount
    print(f'Wallet balance: {wallet_balance} {symbol}')
    print(f'Minimum wallet balance: {min_balance} {symbol}')
    print(f'Estimated transaction fee: {fee} {symbol}')
    print(f'Remaining in wallet after transfer: {wallet_balance - transfer_amount - fee} {symbol}')
    if wallet_balance < transfer_amount or transfer_amount <= 0:
      print(f'Skipping: Insufficient tokens in wallet.')
    if wallet_balance - transfer_amount - fee < min_balance:
      print(f'Skipping: Transfer would leave wallet below minimum balance.')
    else:
      print(f'Sending {transfer_amount} {symbol} from wallet {account_from["id"]} to account {account_to["id"]}')
      tx = initialize_transaction(address_from)
      tx_add_transfer(tx, address_to['address'], transfer_amount)
      send_transaction(tx)

# Check all accounts on all chains and determine if tokens need claiming and restaking
def check_delegations():
  chains = chain_list()
  print('> Select one or more chains')
  print_item_menu(chains)
  chains = select_items(chains)
  print(f'> Selected chains: {", ".join(chains)}')
  print('> Loading accounts...')
  print('> Preserve wallet balances in first account?')
  skip_first = confirm()
  accounts = get_accounts(chains)
  for account in accounts:
    for chain in chains:
      address = get_specific_address(account, chain)
      print(f'> Processing wallet {account["id"]} on {chain} ({address["address"]})')

      # Retrieve all relevant balances, fees, parameters, etc.
      balances = get_all_token_balances(chain, address['address'])
      wallet, delegated, rewards = balances['wallet'], balances['delegated'], balances['rewards']
      symbol = chain_info(chain)['symbol']
      print(f'Wallet: {wallet} {symbol}')
      if account['id'] == 0 and skip_first:
        wallet = 0
      print(f'Delegated balance: {delegated} {symbol}')
      print(f'Total pending rewards: {rewards["total_rewards"]} {symbol}')
      print(f'Number of validators delegated to: {len(rewards["validators"])}')
      rewards['validators'] = [(validator, reward) for validator, reward in rewards['validators'] if reward  / (10 ** chain_info(chain)['decimals']) > MIN_REWARDS_THRESHOLD]
      fee_claim = len(rewards["validators"]) * chain_info(chain)['feeClaim']
      fee_stake = chain_info(chain)['feeStake']
      fee = (fee_claim + fee_stake) / (10 ** chain_info(chain)['decimals'])
      min_balance = chain_info(chain)['minBalance'] / (10 ** chain_info(chain)['decimals'])
      staking_apr = chain_info(chain)['stakingApr']
      print(f'Estimated transaction fee for claiming and restaking: {fee} {symbol}')

      # Determine whether it's desirable to claim and restake
      should_claim, diff = optimal_restaking(wallet, min_balance, delegated, staking_apr, rewards["total_rewards"], fee)
      if not should_claim:
        if diff is not None:
          print(f'It is NOT optimal to claim and restake (rewards need to be {diff} {symbol} higher).')
        else:
          print(f'It is NOT optimal to claim and restake (balance would decrease below minimum).')
      else:
        # Claim all nontrivial delegation rewards
        for validator, reward in rewards['validators']:
          print(f'Claiming {reward / (10 ** chain_info(chain)["decimals"])} {symbol} in rewards from validator {validator}...')
          tx = initialize_transaction(address)
          tx_claim_rewards(tx, validator)
          send_transaction(tx)

        # Attempt to select target validator as validator with largest delegated amount currently
        delegations = get_all_delegated(chain, address['address'])
        best_validator = None
        max_amount = -1
        for delegation in delegations:
          delegated_amount = int(delegation['balance']['amount'])
          if delegated_amount > max_amount:
            max_amount = delegated_amount
            best_validator = delegation['delegation']['validator_address']
            print(f'Selected {best_validator} as delegation target (current delegation amount: {delegated_amount})')

        # If no delegations, select a random validator from preferredValidator{1,2,3} in chains config
        if best_validator is None:
          preferred_validators = [chain_info(chain)['preferredValidator' + str(i)] for i in [1, 2, 3]]
          preferred_validators = [validator for validator in preferred_validators if validator != '']
          best_validator = random.choice(preferred_validators)
          print(f'Selected {best_validator} as delegation target (random preferred validator)')

        # Proceed with staking transaction if target validator successfully selected:
        if best_validator is not None:
          amount_stake = round(wallet + rewards['total_rewards'] - fee - min_balance)
          print(f'Staking {amount_stake} {symbol} with {best_validator}...')
          tx = initialize_transaction(address)
          tx_add_delegation(tx, best_validator, amount_stake)
          send_transaction(tx)
        else:
          print('Failed to select target validator for delegation!')

# Main interactive menu
def main_menu():
  options = ['Encrypt mnemonic']
  if os.path.exists(MNEMONIC):
    options.append('Decrypt mnemonic')
    options.append('Show balances')
    options.append('Check delegations')
    options.append('Multisend (one -> many)')
    options.append('Multisend (many -> one)')
    options.append('Exit')
  print('> Choose an option')
  print_item_menu(options)
  opt = select_item(options)
  if opt == 'Encrypt mnemonic':
    encrypt_mnemonic()
  elif opt == 'Decrypt mnemonic':
    decrypt_mnemonic()
  elif opt == 'Show balances':
    show_balances()
  elif opt == 'Check delegations':
    check_delegations()
  elif opt == 'Multisend (one -> many)':
    multisend_one_many()
  elif opt == 'Multisend (many -> one)':
    multisend_many_one()
  elif opt == 'Exit':
    sys.exit(0)

if __name__ == '__main__':
  while True:
    main_menu()