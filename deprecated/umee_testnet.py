from cosmos import *
from umee_goerli import *

# transfer fee: 800
# bridge tx fee: 5000
# bridge intrinsic fee: 100
# total fee: 5900
# send 9200 umee (0.0092), bridge 9200-5900 = 3300 ~ 3000
# done: 4-160

BRIDGE_AMOUNT = 3000

def get_eth_address(id, key):
  privkey_eth = mnemonic_to_privkey_from_derivation(decrypt_mnemonic(key=key), f'm/44\'/60\'/0\'/0/{id}')
  account = w3.eth.account.privateKeyToAccount(privkey_eth)
  return str(account.address)

key = input('Password: ').strip()
min_id = int(input('Min ID: '))
max_id = int(input('Max ID: '))
accounts = load_accounts('Umee Testnet', number_of_accounts=max_id+1)
w3 = Web3(Web3.HTTPProvider(f'https://goerli.infura.io/v3/{INFURA_PROJECT_ID}'))

for id in range(min_id, max_id+1):
  print(f'Beginning transactions for account ID {id}.')
  account = accounts[id]
  address = get_specific_address(account, 'Umee Testnet')
  print('Umee testnet address:', address['address'])
  eth_address = get_eth_address(id, key)
  print('Goerli testnet address:', eth_address)
  tx = initialize_transaction(address)
  tx_add_gravity_bridge_to_eth(tx, eth_address, BRIDGE_AMOUNT)
  send_transaction(tx)