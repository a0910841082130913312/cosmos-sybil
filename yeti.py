import time
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import ContractLogicError
from cosmos import *
from evm import *

# 1 through 500

MAX_VALUE = 115792089237316195423570985008687907853269984665640564039457584007913129639935

CONTRACT_QIUSDC = Web3.toChecksumAddress('0xac9518d66df4ba4570b3a0213e7df45802d5e7f3')
CONTRACT_WAVAX = Web3.toChecksumAddress('0xdd30dff5f83f53789520118fc8ab15f5b2c2c850')
CONTRACT_WETH = Web3.toChecksumAddress('0x5085f96fab5a4f4cd6acedf8054b431aacf298f9')
CONTRACT_YUSD = Web3.toChecksumAddress('0x6a62e076f10ecd61ca91a456bf86d40fdb8bcc65')
CONTRACT_YUSD_MINTER = Web3.toChecksumAddress('0xfc10fbc4b3c64af67e53e615af46c21d666baab5')
CONTRACT_YETI = Web3.toChecksumAddress('0x07937297c4768856c97606e3c2b42824a5d46633')
CONTRACT_SYETI = Web3.toChecksumAddress('0x774cfe9bcd1bf857e3cd0f1e7b25aef8e40acf09')
CONTRACT_JOE = Web3.toChecksumAddress('0xc1315eb36397e70330fea4fa7b04c24db16c294c')
CONTRACT_DANGER = Web3.toChecksumAddress('0xef70bfaca59bbbbd9e48efd2cd81d45aa97c507b')
CONTRACT_JLP = Web3.toChecksumAddress('0x2e945f4de1586ea62003024829a1e8019e8e00f8')
CONTRACT_TROVE = Web3.toChecksumAddress('0x6387c0e385196fecb43d5fe37ebe9777b790a882')

ETH_FUNDING_AMOUNT = 0.2

if __name__ == '__main__':
  w3 = Web3(Web3.HTTPProvider('https://api.avax-test.network/ext/bc/C/rpc'))
  w3.middleware_onion.inject(geth_poa_middleware, layer=0)

  min_id = int(input('Min ID: '))
  max_id = int(input('Max ID: '))
  accounts = get_evm_accounts(w3, max_id+1)
  for id in range(min_id, max_id+1):
    try:
      print(f'Beginning transactions for account ID {id}.')

      account = accounts[id]
      print(f'Account address: {account.address}')
      params = [form_evm_contract_call, 'Avalanche Fuji', w3, account]

      print(f'Funding with {ETH_FUNDING_AMOUNT} AVAX...')
      send_evm_transaction_robust(form_evm_transfer, *params[1:3], accounts[0], ETH_FUNDING_AMOUNT, account.address)
      print('Sleeping 10 extra seconds...')
      time.sleep(10)

      print('Minting qiUSDC, WAVAX, WETH, YUSD, JOE, JLP, and DANGER...')
      send_evm_transaction_robust(*params, CONTRACT_QIUSDC, 'mint', [])
      send_evm_transaction_robust(*params, CONTRACT_WAVAX, 'mint', [])
      send_evm_transaction_robust(*params, CONTRACT_WETH, 'mint', [])
      send_evm_transaction_robust(*params, CONTRACT_YUSD_MINTER, 'mint', [])
      send_evm_transaction_robust(*params, CONTRACT_JOE, 'mint', [])
      send_evm_transaction_robust(*params, CONTRACT_JLP, 'mint', [])
      send_evm_transaction_robust(*params, CONTRACT_DANGER, 'mint', [])

      print('Approving YUSD, YETI, and JOE...')
      send_evm_transaction_robust(*params, CONTRACT_YUSD, 'approve', [CONTRACT_TROVE, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_JOE, 'approve', [CONTRACT_TROVE, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_YETI, 'approve', [CONTRACT_YETI, MAX_VALUE])

      # Create trove with 26k JOE and borrow 10k YUSD
      print('Creating trove...')
      send_evm_transaction_robust(*params, CONTRACT_TROVE, 'openTrove', [100000000000000000, 10000000000000000000000, Web3.toChecksumAddress('0x282061bb62f3a88e56b14fdca84c4477b33f2c4a'), Web3.toChecksumAddress('0x2c02078935fe5b407583209d7bc22df60fbdf958'), [CONTRACT_JOE], [26000000000000000000000]])

      print('Done!')
    except ContractLogicError:
      print('Encountered contract logic error, account already tried... skipping')