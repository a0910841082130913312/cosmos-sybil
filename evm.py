from __future__ import annotations
import json
import time
import requests
from cosmos import *
from functools import cache
from web3 import Web3
from web3.middleware import geth_poa_middleware

from typing import TYPE_CHECKING
if TYPE_CHECKING:
  from web3.main import Web3
  from web3.contract import Contract
  from eth_account.signers.local import LocalAccount

CHAIN_LIST_EVM = 'chains_evm.json'
PRIORITY_GAS_MULTIPLIER = 0.1
DELAY_AFTER_TX = 5
DELAY_AFTER_EXCEPTION = 10
DELAY_AFTER_HIGH_GAS = 30
MAX_RETRIES = 5
GAS_TRANSFER = 21000
MAX_VALUE = 115792089237316195423570985008687907853269984665640564039457584007913129639935
ZERO_ADDRESS = Web3.toChecksumAddress('0x0000000000000000000000000000000000000000')
GENERIC_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36'

# Returns specific config info for a given chain
@cache
def evm_chain_info(chain):
  chains = json.loads(open(CHAIN_LIST_EVM).read())
  for c in chains:
    if c['chain'] == chain:
      return c
  raise RuntimeError('chain not found')

# Get latest block number of an EVM chain as a hex string
def get_evm_latest_block_number(chain: str) -> str:
  req = requests.get(f'{evm_chain_info(chain)["scanner"]}/api?module=proxy&action=eth_blockNumber&apikey={evm_chain_info(chain)["scannerAPIKey"]}', headers={'User-Agent': GENERIC_USER_AGENT})
  return req.json()['result']

# Get the base gas fee corresponding to the latest block
def get_evm_recent_gas(chain: str):
  block_num = get_evm_latest_block_number(chain)
  headers = {'Content-Type': 'application/json'}
  data = {'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': [block_num, True]}
  req = requests.post(evm_chain_info(chain)['rpc'], headers=headers, json=data)
  return int(req.json()['result']['baseFeePerGas'], 16)

# Waits until base fee of latest block is lower than configured maximum
# Returns a recommended base fee for the next transaction
def wait_until_cheap_gas(chain):
  max_gas = evm_chain_info(chain)['maxBaseFee']
  gas = get_evm_recent_gas(chain)
  ratio = str(gas / max_gas)[:6] + 'x'
  while gas >= max_gas:
    print(f'Currently gas is {ratio} higher than max ({gas} and {max_gas} respectively), waiting {DELAY_AFTER_HIGH_GAS} seconds...')
    time.sleep(DELAY_AFTER_HIGH_GAS)
    gas = get_evm_recent_gas(chain)
    ratio = str(gas / max_gas)[:6] + 'x'
  print(f'Gas check passed: {ratio} compared to max ({gas} and {max_gas} respectively)!')
  return int(gas * 1.125)

# Returns an address's token balance
def get_evm_token_balance(chain: str, address: str, token_contract: str) -> int:
  req = requests.get(f'{evm_chain_info(chain)["scanner"]}/api?module=proxy&action=eth_blockNumber&apikey={evm_chain_info(chain)["scannerAPIKey"]}')
  return int(req.json()['result'])

# Generic internal function for retrieving verified contract ABIs from Etherscan and Etherscan forks
def get_abi(chain: str, contract_address: str) -> str:
  req = requests.get(f'{evm_chain_info(chain)["scanner"]}/api?module=contract&action=getabi&address={contract_address}&apikey={evm_chain_info(chain)["scannerAPIKey"]}')
  data = req.json()
  abi = json.dumps(data['result']).replace('\\', '')[1:-1]
  return abi

# Retrieve nonce of a web3 account object
# Returns nonce stored as attribute if present, otherwise queries RPC for nonce
def get_nonce(w3: Web3, account: LocalAccount) -> int:
  if not hasattr(account, 'nonce'):
    account.nonce = w3.eth.getTransactionCount(account.address)
  return account.nonce

# Returns a web3 Contract object for a given chain and contract address
# ABI can be retrieved from contract_address directly, or from a proxy contract's proxy_address, or directly overriden with a fixed ABI string
def get_contract(w3: Web3, chain: str, contract_address: str, proxy_address: str = None, abi_override: str = None) -> Contract:
  # Ensure addresses are given as strings
  contract_address = str(contract_address)
  if proxy_address is not None:
    proxy_address = str(proxy_address)

  # Retrieve contract ABI
  if abi_override is not None:
    abi = abi_override
  elif proxy_address is not None:
    abi = get_abi(chain, proxy_address)
  else:
    abi = get_abi(chain, contract_address)

  # Form final Contract object
  return w3.eth.contract(address=w3.toChecksumAddress(contract_address.lower()), abi=abi)

# Given a caller Account, web3 Contract object, a function name, and a list of args, estimates gas requirement
def estimate_gas(account: LocalAccount, contract: Contract, function: str, args: list) -> int:
  return getattr(contract.functions, function)(*args).estimateGas({'from': account.address})

# Given a mnemonic string and an account ID, returns corresponding LocalAccount object using derived private key
def mnemonic_to_evm_account(w3: Web3, mnemonic: str, id: int) -> LocalAccount:
  privkey = mnemonic_to_privkey_from_derivation(mnemonic, f'm/44\'/60\'/0\'/0/{id}')
  return w3.eth.account.privateKeyToAccount(privkey)

# Loads multiple EVM accounts, prompting user to decrypt seed phrase
def get_evm_accounts(w3: Web3, num_accounts: int = None) -> list:
  if num_accounts is None:
    num_accounts = int(input('Number of accounts: '))
  mnemonic = decrypt_mnemonic()
  return [mnemonic_to_evm_account(w3, mnemonic, id) for id in range(num_accounts)]

# Signs and sends a built transaction to a Web3 instance
def send_evm_transaction(w3: Web3, account: LocalAccount, tx: dict, delay: int = DELAY_AFTER_TX) -> str:
  # Sign and send transaction
  signed_tx = w3.eth.account.signTransaction(tx, private_key=account.privateKey)
  tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)

  # Increment nonce
  account.nonce += 1

  # Sleep and return
  print(f'Sleeping for {delay} seconds...')
  time.sleep(delay)
  return tx_hash

# Helper function for sending EVM based transactions that resends several times in case of error
# func should return a dictionary representing a built transaction ready to be sent
# args and kwargs are passed in directly to func
def send_evm_transaction_robust(func: function, chain: str, w3: Web3, account: LocalAccount, *args, count: int = 0, **kwargs) -> str:
  try:
    return func(chain, w3, account, *args, **kwargs)
  except Exception as e:
    if count <= MAX_RETRIES:
      print(f'Encountered an exception, sleeping for {DELAY_AFTER_EXCEPTION} seconds...')
      print(e)
      if hasattr(account, 'nonce'):
        del account.nonce
      time.sleep(DELAY_AFTER_EXCEPTION)
      print('Retrying transaction...')
      return send_evm_transaction_robust(func, chain, w3, account, *args, count=count+1, **kwargs)
    else:
      print('Too many retries! Skipping transaction...')
      return None

# Forms dictionary object for EVM contract call with specific named function
def form_evm_contract_call(chain: str, w3: Web3, account: LocalAccount, contract: Contract, function: str, args: list = [], proxy_address: str = None, abi_override: str = None):
  contract = get_contract(w3, chain, contract_address=contract, proxy_address=proxy_address, abi_override=abi_override)
  gas = wait_until_cheap_gas(chain)
  tx = {
    'from': account.address,
    'gas': estimate_gas(account, contract, function, args) * 2,
    'nonce': get_nonce(w3, account),
    'maxFeePerGas': gas,
    'maxPriorityFeePerGas': int(gas * PRIORITY_GAS_MULTIPLIER)
  }
  built_tx = getattr(contract.functions, function)(*args).buildTransaction(tx)
  return send_evm_transaction(w3, account, built_tx, delay=evm_chain_info(chain)['delayAfterTx'])

# Form dictionary object for EVM transaction where given amount of ether is transferred to a recipient
def form_evm_transfer(chain: str, w3: Web3, account: LocalAccount, amount: int, recipient: str) -> str:
  gas = wait_until_cheap_gas(chain)
  tx = {
    'from': account.address,
    'to': recipient,
    'value': w3.toWei(amount, 'ether'),
    'gas': GAS_TRANSFER,
    'nonce': get_nonce(w3, account),
    'maxFeePerGas': gas,
    'maxPriorityFeePerGas': int(gas * PRIORITY_GAS_MULTIPLIER),
    'chainId': w3.eth.chain_id
  }
  return send_evm_transaction(w3, account, tx, evm_chain_info(chain)['delayAfterTx'])

# Returns a Web3 object for a given chain with an RPC connection
def get_web3_connection(chain: str) -> Web3:
  w3 = Web3(Web3.HTTPProvider(evm_chain_info(chain)['rpc']))
  if evm_chain_info(chain)['injectMiddleware']:
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
  return w3

# Prompts user to return the lower and upper bound of a range of account IDs
def get_range():
  min_id = int(input('Min ID: '))
  max_id = int(input('Max ID: '))
  return min_id, max_id

# Simple wrapper for Web3.toChecksumAddress
def format_addr(address: str) -> str:
  return Web3.toChecksumAddress(address)

if __name__ == '__main__':
  get_evm_recent_gas('Avalanche Fuji')
  get_evm_recent_gas('Goerli')