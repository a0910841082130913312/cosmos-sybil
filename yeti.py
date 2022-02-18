import time
from cosmos import *
from evm import *

# 463

CONTRACT_QIUSDC = format_addr('0xac9518d66df4ba4570b3a0213e7df45802d5e7f3')
CONTRACT_WAVAX = format_addr('0xdd30dff5f83f53789520118fc8ab15f5b2c2c850')
CONTRACT_WETH = format_addr('0x5085f96fab5a4f4cd6acedf8054b431aacf298f9')
CONTRACT_YUSD = format_addr('0x6a62e076f10ecd61ca91a456bf86d40fdb8bcc65')
CONTRACT_YUSD_MINTER = format_addr('0xfc10fbc4b3c64af67e53e615af46c21d666baab5')
CONTRACT_YETI = format_addr('0x07937297c4768856c97606e3c2b42824a5d46633')
CONTRACT_SYETI = format_addr('0x774cfe9bcd1bf857e3cd0f1e7b25aef8e40acf09')
CONTRACT_JOE = format_addr('0xc1315eb36397e70330fea4fa7b04c24db16c294c')
CONTRACT_DANGER = format_addr('0xef70bfaca59bbbbd9e48efd2cd81d45aa97c507b')
CONTRACT_JLP = format_addr('0x2e945f4de1586ea62003024829a1e8019e8e00f8')
CONTRACT_TROVE = format_addr('0x6387c0e385196fecb43d5fe37ebe9777b790a882')
CONTRACT_SPOOL = format_addr('0x9ab04cd8b701e5bb4fdf31378af679d2f4534f8a')

ETH_FUNDING_AMOUNT = 0.3
ABI_SPOOL = '[{"inputs":[{"internalType":"uint256","name":"_amount","type":"uint256"},{"internalType":"address","name":"_frontEndTag","type":"address"}],"name":"provideToSP","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"withdrawFromSP","outputs":[],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]'

if __name__ == '__main__':
  w3 = get_web3_connection('Avalanche Fuji')
  min_id, max_id = get_range()
  option = int(input('Choose option (1, 2): '))
  accounts = get_evm_accounts(w3, max_id+1)
  for id in range(min_id, max_id+1):
    print(f'Beginning transactions for account ID {id}.')
    account = accounts[id]
    print(f'Account address: {account.address}')
    params = [form_evm_contract_call, 'Avalanche Fuji', w3, account]
    if option == 1:
      print(f'Funding with {ETH_FUNDING_AMOUNT} AVAX...')
      send_evm_transaction_robust(form_evm_transfer, *params[1:3], accounts[0], ETH_FUNDING_AMOUNT, account.address)

      print('Minting qiUSDC, WAVAX, WETH, YUSD, JOE, JLP, and DANGER...')
      send_evm_transaction_robust(*params, CONTRACT_QIUSDC, 'mint')
      send_evm_transaction_robust(*params, CONTRACT_WAVAX, 'mint')
      send_evm_transaction_robust(*params, CONTRACT_WETH, 'mint')
      send_evm_transaction_robust(*params, CONTRACT_YUSD_MINTER, 'mint')
      send_evm_transaction_robust(*params, CONTRACT_JOE, 'mint')
      send_evm_transaction_robust(*params, CONTRACT_JLP, 'mint')
      send_evm_transaction_robust(*params, CONTRACT_DANGER, 'mint')

      print('Approving YUSD, YETI, and JOE...')
      send_evm_transaction_robust(*params, CONTRACT_YUSD, 'approve', [CONTRACT_TROVE, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_JOE, 'approve', [CONTRACT_TROVE, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_YETI, 'approve', [CONTRACT_YETI, MAX_VALUE])

      print('Creating trove...')
      send_evm_transaction_robust(*params, CONTRACT_TROVE, 'openTrove', [100000000000000000, 10000000000000000000000, format_addr('0x282061bb62f3a88e56b14fdca84c4477b33f2c4a'), format_addr('0x2c02078935fe5b407583209d7bc22df60fbdf958'), [CONTRACT_JOE], [26000000000000000000000]])

      print('Providing YUSD to stability pool...')
      send_evm_transaction_robust(*params, CONTRACT_SPOOL, 'provideToSP', [int(20000 * 1e18), ZERO_ADDRESS], abi_override=ABI_SPOOL) 
    elif option == 2:
      print('Withdrawing stability pool rewards...')
      send_evm_transaction_robust(*params, CONTRACT_SPOOL, 'withdrawFromSP', [0], abi_override=ABI_SPOOL) 

      balance = get_evm_token_balance(chain, str(account.address), str(CONTRACT_YETI))
      print(f'Staking {balance} YETI...')
      send_evm_transaction_robust(*params, CONTRACT_SYETI, 'mint', [balance])
    print('Done!')