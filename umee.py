import time
from web3 import Web3
from web3.middleware import geth_poa_middleware
from etherscan import Etherscan
from cosmos import *

ETHERSCAN_API_KEY = '63EQXB7PPAHS878I39WTK56JHS6ZUAF4QQ'
INFURA_PROJECT_ID = '1b56fe63a99144c783f9fd2cf8b30e0e'
MAX_VALUE = 115792089237316195423570985008687907853269984665640564039457584007913129639935
GAS_TRANSFER = 21000
GAS_ESTIMATE = 1200000
MAX_FEE = 6
MAX_FEE_PRIORITY = 2
DELAY_AFTER_TX = 15
DELAY_AFTER_EXCEPTION = 10
MAX_TX_RETRY = 4

CONTRACT_DAI = Web3.toChecksumAddress('0xd787ec2b6c962f611300175603741db8438674a0')
CONTRACT_USDC = Web3.toChecksumAddress('0x0aa78575e17ac357294bb7b5a9ea512ba07669e2')
CONTRACT_USDT = Web3.toChecksumAddress('0x77baa6a171e5084a9e7683b1f6658bf330bf0011')
CONTRACT_ATOM = Web3.toChecksumAddress('0x260edffa7648ddc398b91884d78485612fc6d246')
CONTRACT_BANK = Web3.toChecksumAddress('0x75d5e88adf8f3597c7c3e4a930544fb48089c779')
CONTRACT_BANK_PROXY = Web3.toChecksumAddress('0xea08c7bc64cf48bd167ddd978157b78e62d51ac2')
CONTRACT_BRIDGE = Web3.toChecksumAddress('0xb76197af55d294994fcec380964131b824132ec6')

MINT_AMOUNT_DAI = 2000000000000000000
MINT_AMOUNT_USDC = 2000000
BORROW_AMOUNT_USDT = 2000000
BORROW_AMOUNT_ATOM = 50000
ETH_FUNDING_AMOUNT = 0.02
ABI_BRIDGE = '[{"inputs":[{"internalType":"address","name":"_tokenContract","type":"address"},{"internalType":"string","name":"_destination","type":"string"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendToCosmos","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'

def get_contract(address, proxy=None, abi=None):
  if isinstance(address, str):
    address = Web3.toChecksumAddress(address.lower())
  return w3.eth.contract(address=address, abi=es.get_contract_abi(address if proxy is None else str(proxy)) if abi is None else abi)

def estimate_gas(contract, function, args):
  return getattr(contract.functions, function)(*args).estimateGas({'from': account.address})

def get_nonce(account):
  return w3.eth.getTransactionCount(account.address)

def get_account_info(id):
  privkey_eth = mnemonic_to_privkey(decrypt_mnemonic(key=key), id, 'Ethereum')
  account = w3.eth.account.privateKeyToAccount(privkey_eth)
  privkey_cosmos = mnemonic_to_privkey(decrypt_mnemonic(key=key), id, 'Cosmos')
  umee_address = pubkey_to_address(privkey_to_pubkey(privkey_cosmos), prefix='umee')
  return account, privkey, umee_address

def sign_and_send_tx(tx, privkey, repeats=0):
  try:
    signed_tx = w3.eth.account.signTransaction(tx, private_key=privkey)
    tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
    print(f'Sleeping for {DELAY_AFTER_TX} seconds...')
    time.sleep(DELAY_AFTER_TX)
    return tx_hash
  except:
    if repeats < MAX_TX_RETRY:
      print(f'Encountered an exception, sleeping for {DELAY_AFTER_EXCEPTION} seconds...')
      time.sleep(DELAY_AFTER_EXCEPTION)
      print('Retrying transaction...')
      return sign_and_send_tx(tx, privkey, repeats=repeats+1)
    else:
      raise RuntimeError('exceeded transaction retry maximum')

def send_tx(account, privkey, contract, function, args, proxy=None, abi=None):
  contract = get_contract(contract, proxy=proxy, abi=abi)
  tx = {
    'from': account.address,
    'gas': GAS_ESTIMATE,
    'nonce': get_nonce(account),
    'maxFeePerGas': w3.toWei(MAX_FEE, 'gwei'),
    'maxPriorityFeePerGas': w3.toWei(MAX_FEE_PRIORITY, 'gwei')
  }
  built_tx = getattr(contract.functions, function)(*args).buildTransaction(tx)
  return sign_and_send_tx(built_tx, privkey)

def send_ether(account, privkey, amount, recipient):
  tx = {
    'from': account.address,
    'to': recipient,
    'value': w3.toWei(amount, 'ether'),
    'gas': GAS_TRANSFER,
    'nonce': get_nonce(account),
    'maxFeePerGas': w3.toWei(MAX_FEE, 'gwei'),
    'maxPriorityFeePerGas': w3.toWei(MAX_FEE_PRIORITY, 'gwei'),
    'chainId': w3.eth.chain_id
  }
  return sign_and_send_tx(built_tx, privkey)

w3 = Web3(Web3.HTTPProvider(f'https://goerli.infura.io/v3/{INFURA_PROJECT_ID}'))
w3.middleware_onion.inject(geth_poa_middleware, layer=0)
es = Etherscan(ETHERSCAN_API_KEY, net='goerli')

key = input('Password: ').strip()
min_id = int(input('Min ID: '))
max_id = int(input('Max ID: '))
account0, privkey0, _ = get_account_info(0)
for id in range(min_id, max_id + 1):
  print(f'Beginning transactions for account ID {id}.')

  account, privkey, umee_address = get_account_info(id)
  print(f'Account address: {account.address}')

  print(f'Funding with {ETH_FUNDING_AMOUNT} ETH...')
  send_ether(account0, privkey0, 0.02, account.address)

  print('Approving DAI...')
  send_tx(account, privkey, CONTRACT_DAI, 'approve', [CONTRACT_BANK, MAX_VALUE])

  print('Approving USDC...')
  send_tx(account, privkey, CONTRACT_USDC, 'approve', [CONTRACT_BANK, MAX_VALUE])

  print('Minting testnet DAI...')
  send_tx(account, privkey, CONTRACT_DAI, 'mint', [MINT_AMOUNT_DAI])

  print('Minting testnet USDC...')
  send_tx(account, privkey, CONTRACT_USDC, 'mint', [MINT_AMOUNT_USDC])

  print('Depositing DAI...')
  send_tx(account, privkey, CONTRACT_BANK, 'deposit', [CONTRACT_DAI, MINT_AMOUNT_DAI, account.address, 0], proxy=CONTRACT_BANK_PROXY)

  print('Depositing USDC...')
  send_tx(account, privkey, CONTRACT_BANK, 'deposit', [CONTRACT_USDC, MINT_AMOUNT_USDC, account.address, 0], proxy=CONTRACT_BANK_PROXY)

  print('Approving USDT...')
  send_tx(account, privkey, CONTRACT_USDT, 'approve', [CONTRACT_BANK, MAX_VALUE])

  print('Borrowing USDT...')
  send_tx(account, privkey, CONTRACT_BANK, 'borrow', [CONTRACT_USDT, BORROW_AMOUNT_USDT, 2, 0, account.address], proxy=CONTRACT_BANK_PROXY)

  print('Depositing USDT...')
  send_tx(account, privkey, CONTRACT_BANK, 'deposit', [CONTRACT_USDT, BORROW_AMOUNT_USDT, account.address, 0], proxy=CONTRACT_BANK_PROXY)

  print('Approving ATOM (mint)...')
  send_tx(account, privkey, CONTRACT_ATOM, 'approve', [CONTRACT_BANK, MAX_VALUE], proxy=CONTRACT_DAI)

  print('Approving ATOM (bridge)...')
  send_tx(account, privkey, CONTRACT_ATOM, 'approve', [CONTRACT_BRIDGE, MAX_VALUE], proxy=CONTRACT_DAI)

  print('Borrowing ATOM...')
  send_tx(account, privkey, CONTRACT_BANK, 'borrow', [CONTRACT_ATOM, BORROW_AMOUNT_ATOM, 2, 0, account.address], proxy=CONTRACT_BANK_PROXY)

  print(f'Bridging ATOM to {umee_address}...')
  send_tx(account, privkey, CONTRACT_BRIDGE, 'sendToCosmos', [CONTRACT_ATOM, umee_address, BORROW_AMOUNT_ATOM], abi=ABI_BRIDGE)

  print('Done!')