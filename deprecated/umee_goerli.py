import time
from cosmos import *
from evm import *

CONTRACT_DAI = format_addr('0xd787ec2b6c962f611300175603741db8438674a0')
CONTRACT_USDC = format_addr('0x0aa78575e17ac357294bb7b5a9ea512ba07669e2')
CONTRACT_USDT = format_addr('0x77baa6a171e5084a9e7683b1f6658bf330bf0011')
CONTRACT_ATOM = format_addr('0x260edffa7648ddc398b91884d78485612fc6d246')
CONTRACT_BANK = format_addr('0x75d5e88adf8f3597c7c3e4a930544fb48089c779')
CONTRACT_BANK_PROXY = format_addr('0xea08c7bc64cf48bd167ddd978157b78e62d51ac2')
CONTRACT_BRIDGE = format_addr('0xb76197af55d294994fcec380964131b824132ec6')

MINT_AMOUNT_DAI = 2000000000000000000
MINT_AMOUNT_USDC = 2000000
BORROW_AMOUNT_USDT = 2000000
BORROW_AMOUNT_ATOM = 50000
ETH_FUNDING_AMOUNT = 0.02
ABI_BRIDGE = '[{"inputs":[{"internalType":"address","name":"_tokenContract","type":"address"},{"internalType":"string","name":"_destination","type":"string"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"sendToCosmos","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]'

def get_account_info(id):
  privkey_eth = mnemonic_to_privkey_from_derivation(decrypt_mnemonic(key=key), f'm/44\'/60\'/0\'/0/{id}')
  account = w3.eth.account.privateKeyToAccount(privkey_eth)
  privkey_cosmos = mnemonic_to_privkey(decrypt_mnemonic(key=key), id, 'Cosmos')
  umee_address = pubkey_to_address(privkey_to_pubkey(privkey_cosmos), prefix='umee')
  return account, umee_address

if __name__ == '__main__':
  w3 = get_web3_connection('Goerli')
  key = input('Password: ').strip()
  min_id, max_id = get_range()
  account0, _ = get_account_info(0)
  option = int(input('Option: '))
  for id in range(min_id, max_id+1):
    print(f'Beginning transactions for account ID {id}.')

    account, umee_address = get_account_info(id)
    print(f'Account address: {account.address}')
    params = [form_evm_contract_call, 'Goerli', w3, account]

    if option == 1:
      print(f'Funding with {ETH_FUNDING_AMOUNT} ETH...')
      send_evm_transaction_robust(form_evm_transfer, *params[1:3], account0, 0.02, account.address)

      print('Approving DAI, USDC, USDT, and ATOM...')
      send_evm_transaction_robust(*params, CONTRACT_DAI, 'approve', [CONTRACT_BANK, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_USDC, 'approve', [CONTRACT_BANK, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_USDT, 'approve', [CONTRACT_BANK, MAX_VALUE])
      send_evm_transaction_robust(*params, CONTRACT_ATOM, 'approve', [CONTRACT_BANK, MAX_VALUE], proxy_address=CONTRACT_DAI)
      send_evm_transaction_robust(*params, CONTRACT_ATOM, 'approve', [CONTRACT_BRIDGE, MAX_VALUE], proxy_address=CONTRACT_DAI)

    print('Minting testnet DAI and USDC...')
    send_evm_transaction_robust(*params, CONTRACT_DAI, 'mint', [MINT_AMOUNT_DAI])
    send_evm_transaction_robust(*params, CONTRACT_USDC, 'mint', [MINT_AMOUNT_USDC])
    time.sleep(60)

    print('Depositing DAI and USDC...')
    send_evm_transaction_robust(*params, CONTRACT_BANK, 'deposit', [CONTRACT_DAI, MINT_AMOUNT_DAI, account.address, 0], proxy_address=CONTRACT_BANK_PROXY)
    send_evm_transaction_robust(*params, CONTRACT_BANK, 'deposit', [CONTRACT_USDC, MINT_AMOUNT_USDC, account.address, 0], proxy_address=CONTRACT_BANK_PROXY)
    time.sleep(60)

    print('Borrowing and depositing USDT, then borrowing ATOM...')
    if option == 1:
      send_evm_transaction_robust(*params, CONTRACT_BANK, 'borrow', [CONTRACT_USDT, BORROW_AMOUNT_USDT, 2, 0, account.address], proxy_address=CONTRACT_BANK_PROXY)
      send_evm_transaction_robust(*params, CONTRACT_BANK, 'deposit', [CONTRACT_USDT, BORROW_AMOUNT_USDT, account.address, 0], proxy_address=CONTRACT_BANK_PROXY)
    send_evm_transaction_robust(*params, CONTRACT_BANK, 'borrow', [CONTRACT_ATOM, BORROW_AMOUNT_ATOM, 2, 0, account.address], proxy_address=CONTRACT_BANK_PROXY)
    time.sleep(60)

    print(f'Bridging ATOM to {umee_address}...')
    send_evm_transaction_robust(*params, CONTRACT_BRIDGE, 'sendToCosmos', [CONTRACT_ATOM, umee_address, BORROW_AMOUNT_ATOM], abi_override=ABI_BRIDGE)

    print('Done!')