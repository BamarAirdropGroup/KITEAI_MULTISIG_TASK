from web3 import Web3
from web3.exceptions import InvalidAddress
from colorama import init, Fore, Style
import os
import time
import random
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import warnings
from web3.exceptions import MismatchedABI
from web3.providers.rpc import HTTPProvider
import sys
import requests
from eth_account import Account

warnings.filterwarnings("ignore", category=UserWarning, module="eth_utils")

init()


RPC_URL = 'https://rpc-testnet.gokite.ai/'
PRIVATE_KEY_FILE = 'accounts.txt'
RECEIVER_FILE = 'address.txt'
GAS_LIMIT = 100000
GAS_PRICE = Web3.to_wei('2', 'gwei')
DELAY_BETWEEN_TX = 2
MIN_KITE = 0.00001
MAX_KITE = 0.00006
GAS_BUFFER = Web3.to_wei('0.000001', 'ether')
INTERVAL_SECONDS = 12 * 3600


PROXY_FACTORY_ABI = [
    {
        "inputs": [
            {"internalType": "address", "name": "_singleton", "type": "address"},
            {"internalType": "bytes", "name": "initializer", "type": "bytes"},
            {"internalType": "uint256", "name": "saltNonce", "type": "uint256"}
        ],
        "name": "createProxyWithNonce",
        "outputs": [{"internalType": "contract GnosisSafeProxy", "name": "proxy", "type": "address"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "internalType": "contract GnosisSafeProxy", "name": "proxy", "type": "address"},
            {"indexed": False, "internalType": "address", "name": "singleton", "type": "address"}
        ],
        "name": "ProxyCreation",
        "type": "event"
    }
]

def load_proxies():
    try:
        with open('proxy.txt', 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
        formatted_proxies = []
        for proxy in proxies:
            try:
                
                if '@' not in proxy:
                    print(f"{Fore.YELLOW}Invalid proxy format: {proxy}. Expected username:password@ip:port{Style.RESET_ALL}")
                    continue
                auth, address = proxy.split('@', 1)
                if ':' not in auth or ':' not in address:
                    print(f"{Fore.YELLOW}Invalid proxy format: {proxy}. Expected username:password@ip:port{Style.RESET_ALL}")
                    continue
                username, password = auth.split(':', 1)
                ip, port = address.split(':', 1)
                formatted_proxy = f"{username}:{password}@{ip}:{port}"
                formatted_proxies.append(formatted_proxy)
            except Exception as e:
                print(f"{Fore.YELLOW}Failed to parse proxy {proxy}: {str(e)}{Style.RESET_ALL}")
        if not formatted_proxies:
            print(f"{Fore.RED}No valid proxies found in proxy.txt{Style.RESET_ALL}")
            sys.exit(1)
        return formatted_proxies
    except FileNotFoundError:
        print(f"{Fore.RED}proxy.txt not found{Style.RESET_ALL}")
        sys.exit(1)

class ProxyHTTPProvider(HTTPProvider):
    def __init__(self, endpoint_uri, proxy, **kwargs):
        super().__init__(endpoint_uri, **kwargs)
        self.session = requests.Session()
        self.session.proxies = {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}',
        }

    def make_request(self, method, params):
        try:
            response = super().make_request(method, params)
            return response
        except Exception as e:
            print(f"{Fore.RED}Proxy error: {str(e)}{Style.RESET_ALL}")
            raise

proxies = load_proxies()
selected_proxy = random.choice(proxies)
print(f"{Fore.CYAN}Initial proxy: {selected_proxy}{Style.RESET_ALL}")

w3 = Web3(ProxyHTTPProvider(RPC_URL, selected_proxy))
PROXY_FACTORY_ADDRESS = Web3.to_checksum_address('0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2')
proxy_factory = w3.eth.contract(address=PROXY_FACTORY_ADDRESS, abi=PROXY_FACTORY_ABI)

if not w3.is_connected():
    print(f"{Fore.RED}Failed to connect to Kitescan testnet{Style.RESET_ALL}")
    sys.exit(1)

try:
    chain_id = w3.eth.chain_id
    print(f"{Fore.CYAN}Connected to network with chain ID: {chain_id}{Style.RESET_ALL}")
except Exception as e:
    print(f"{Fore.RED}Failed to retrieve chain ID: {str(e)}{Style.RESET_ALL}")
    sys.exit(1)

singleton = Web3.to_checksum_address('0x3E5c63644E683549055b9Be8653de26E0B4CD36E')
initializer = '0xb63e800d0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000f48f2b2d2a534e402487b3ee7c18c33aec0fe5e4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000027f45f4d6e1a48902bc1079dAc67B3B690b9816f0000000000000000000000000000000000000000000000000000000000000000'

try:
    with open('accounts.txt', 'r') as file:
        private_keys = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print(f"{Fore.RED}accounts.txt not found{Style.RESET_ALL}")
    sys.exit(1)

if not private_keys:
    print(f"{Fore.RED}No private keys found in accounts.txt{Style.RESET_ALL}")
    sys.exit(1)

def display_countdown(seconds):
    while seconds > 0:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds_left = divmod(remainder, 60)
        print(f"{Fore.CYAN}Next run in {hours:02d}:{minutes:02d}:{seconds_left:02d}{Style.RESET_ALL}", end='\r')
        time.sleep(1)
        seconds -= 1
    print(" " * 50, end='\r')

@retry(stop=stop_after_attempt(5), wait=wait_fixed(5), retry=retry_if_exception_type(Exception))
def process_transaction(idx, private_key, attempt, request_count, proxy_mapping):
    global w3, proxy_factory, proxies
    
    selected_proxy = random.choice(proxies)
    print(f"{Fore.CYAN}Using proxy for attempt {attempt}, request {request_count}: {selected_proxy}{Style.RESET_ALL}")
    w3 = Web3(ProxyHTTPProvider(RPC_URL, selected_proxy))
    proxy_factory = w3.eth.contract(address=PROXY_FACTORY_ADDRESS, abi=PROXY_FACTORY_ABI)

    try:
        if not private_key.startswith('0x'):
            private_key = '0x' + private_key
        if len(private_key) != 66:
            raise ValueError(f"Invalid private key length for account {idx}")

        account = w3.eth.account.from_key(private_key)
        sender_address = account.address
        print(f"{Fore.CYAN}Processing account {idx}, attempt {attempt}, request {request_count}: {sender_address}{Style.RESET_ALL}")

        salt_nonce = random.randint(1, 10**18)

        balance = w3.eth.get_balance(sender_address)
        if balance < w3.to_wei('0.001', 'ether'):
            print(f"{Fore.YELLOW}Insufficient balance for {sender_address}: {w3.from_wei(balance, 'ether')} ETH{Style.RESET_ALL}")
            return None, None

        nonce = w3.eth.get_transaction_count(sender_address, 'pending')

        gas_estimate = proxy_factory.functions.createProxyWithNonce(
            singleton,
            initializer,
            salt_nonce
        ).estimate_gas({'from': sender_address})

        tx = proxy_factory.functions.createProxyWithNonce(
            singleton,
            initializer,
            salt_nonce
        ).build_transaction({
            'from': sender_address,
            'gas': gas_estimate + 100000,
            'gasPrice': w3.eth.gas_price,
            'nonce': nonce,
            'chainId': chain_id
        })

        signed_tx = w3.eth.account.sign_transaction(tx, private_key)

        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"{Fore.YELLOW}Transaction sent: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")

        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)

        if tx_receipt['status'] == 1:
            print(f"{Fore.GREEN}Transaction successful for {sender_address}! Tx Explorer: https://testnet.kitescan.ai/tx/{w3.to_hex(tx_hash)}{Style.RESET_ALL}")
            try:
                logs = proxy_factory.events.ProxyCreation().process_receipt(tx_receipt)
                for log in logs:
                    proxy_address = log['args']['proxy']
                    print(f"{Fore.GREEN}Created proxy address: {proxy_address}{Style.RESET_ALL}")
                    code = w3.eth.get_code(proxy_address)
                    if len(code) <= 2:
                        print(f"{Fore.RED}Proxy {proxy_address} is not a valid contract!{Style.RESET_ALL}")
                        return None, None
                    else:
                        print(f"{Fore.GREEN}Proxy {proxy_address} is a valid contract.{Style.RESET_ALL}")
                        if request_count == 2:
                            with open('address.txt', 'a') as f:
                                f.write(f"{proxy_address}\n")
                            proxy_mapping[proxy_address] = sender_address
                        return tx_receipt, proxy_address
            except MismatchedABI:
                print(f"{Fore.YELLOW}Warning: Could not parse ProxyCreation event due to ABI mismatch for Tx hash: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")
                return None, None
        else:
            print(f"{Fore.RED}Transaction failed for {sender_address}. Tx hash: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")
            try:
                tx_params = {
                    'from': sender_address,
                    'to': PROXY_FACTORY_ADDRESS,
                    'data': tx['data'],
                    'value': 0,
                    'gas': gas_estimate,
                    'gasPrice': w3.eth.gas_price,
                }
                w3.eth.call(tx_params)
            except Exception as re:
                print(f"{Fore.RED}Revert reason: {str(re)}{Style.RESET_ALL}")
            return None, None

    except Exception as e:
        print(f"{Fore.RED}Error processing account {idx}, attempt {attempt}, request {request_count} ({sender_address}): {str(e)}{Style.RESET_ALL}")
        raise

def slow(text, delay_ms):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay_ms / 1000)
    print()

def load_receivers():
    try:
        with open(RECEIVER_FILE, 'r') as file:
            receivers = [line.strip() for line in file if line.strip()]
        valid_receivers = [addr for addr in receivers if Web3.is_address(addr)]
        if not valid_receivers:
            print(f"{Fore.RED}No valid receiver addresses found in {RECEIVER_FILE}{Style.RESET_ALL}")
            return []
        return valid_receivers
    except FileNotFoundError:
        print(f"{Fore.RED}{RECEIVER_FILE} not found{Style.RESET_ALL}")
        return []

def send_with_gas(w3, private_key, sender_address, to_address, amount, gas_limit, gas_price, nonce):
    try:
        tx = {
            'to': Web3.to_checksum_address(to_address),
            'value': amount,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'nonce': nonce,
            'chainId': w3.eth.chain_id
        }
        print(f"{Fore.YELLOW}Preparing to send {w3.from_wei(amount, 'ether')} KITE to {to_address} with nonce {nonce}{Style.RESET_ALL}")
        signed_tx = w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
        print(f"{Fore.YELLOW}Transaction hash: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")

        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
        if receipt['status'] == 0:
            print(f"{Fore.RED}Transaction reverted for {to_address}. Tx hash: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}Transaction confirmed for {to_address} in block: {receipt['blockNumber']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Gas used: {receipt['gasUsed']}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Failed to send to {to_address}: {str(e)}{Style.RESET_ALL}")

def process_wallet(w3, private_key, receiver, min_kite, max_kite, gas_limit, gas_price):
    try:
        if not private_key.startswith('0x'):
            private_key = '0x' + private_key
        if len(private_key) != 66:
            raise ValueError("Invalid private key length")

        account = w3.eth.account.from_key(private_key)
        sender_address = account.address
        print(f"{Fore.CYAN}\nProcessing wallet: {sender_address}{Style.RESET_ALL}")

        balance = w3.eth.get_balance(sender_address)
        print(f"{Fore.CYAN}Current balance: {w3.from_wei(balance, 'ether')} KITE{Style.RESET_ALL}")

        gas_cost = gas_limit * gas_price
        print(f"{Fore.CYAN}Estimated gas cost: {w3.from_wei(gas_cost, 'ether')} KITE{Style.RESET_ALL}")

        amount_kite = random.uniform(min_kite, max_kite)
        amount_wei = w3.to_wei(amount_kite, 'ether')
        total_needed = amount_wei + gas_cost

        if balance < total_needed:
            print(f"{Fore.RED}Insufficient balance. Need at least {w3.from_wei(total_needed, 'ether')} KITE for transaction and gas costs{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}Sending {amount_kite} KITE to second proxy address: {receiver}{Style.RESET_ALL}")

        nonce = w3.eth.get_transaction_count(sender_address, 'pending')
        send_with_gas(w3, private_key, sender_address, receiver, amount_wei, gas_limit, gas_price, nonce)

    except Exception as e:
        print(f"{Fore.RED}Error processing wallet {sender_address}: {str(e)}{Style.RESET_ALL}")

def process_account(idx, private_key, proxy_mapping):
    try:
        for attempt in range(1, 4):
            try:
                
                tx_receipt_1, proxy_address_1 = process_transaction(idx, private_key, attempt, 1, proxy_mapping)
                if tx_receipt_1 and tx_receipt_1['status'] == 1 and proxy_address_1:
                    print(f"{Fore.GREEN}First request successful for account {idx}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}First request failed or invalid proxy for account {idx}. Retrying...{Style.RESET_ALL}")
                    time.sleep(5)
                    continue
                
                time.sleep(3)
                
                
                tx_receipt_2, proxy_address_2 = process_transaction(idx, private_key, attempt, 2, proxy_mapping)
                if tx_receipt_2 and tx_receipt_2['status'] == 1 and proxy_address_2:
                    print(f"{Fore.GREEN}Second request successful for account {idx}{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.YELLOW}Second request failed or invalid proxy for account {idx}. Retrying...{Style.RESET_ALL}")
                    time.sleep(5)
                    continue
                    
            except Exception as e:
                print(f"{Fore.YELLOW}Retrying account {idx}, attempt {attempt + 1} due to error: {str(e)}{Style.RESET_ALL}")
                time.sleep(5)
    except Exception as e:
        print(f"{Fore.RED}Account {idx} failed after retries: {str(e)}{Style.RESET_ALL}")

def process_all_accounts():
    with open('address.txt', 'w') as f:
        f.write('')
    proxy_mapping = {}
    header = f"{Fore.GREEN}🪁🪁🪁🪁🪁 KITEAI_MULTISIG_TASK_BOT 1.0 🪁🪁🪁🪁🪁{Style.RESET_ALL}"
    slow(header, 100)
    print(f"{Fore.CYAN}Starting account processing at {time.ctime()}{Style.RESET_ALL}")
    for idx, private_key in enumerate(private_keys, 1):
        process_account(idx, private_key, proxy_mapping)
    print(f"{Fore.CYAN}Finished account processing at {time.ctime()}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}Starting KITE transfer process to second proxy addresses...{Style.RESET_ALL}")
    receivers = load_receivers()
    if not receivers:
        print(f"{Fore.RED}No receivers to process. Skipping KITE transfer.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}Found {len(private_keys)} private keys and {len(receivers)} second proxy addresses{Style.RESET_ALL}")
    
    for idx, private_key in enumerate(private_keys, 1):
        selected_proxy = random.choice(proxies)
        print(f"{Fore.CYAN}Using proxy for wallet {idx}: {selected_proxy}{Style.RESET_ALL}")
        w3_transfer = Web3(ProxyHTTPProvider(RPC_URL, selected_proxy))
        
        if not w3_transfer.is_connected():
            print(f"{Fore.RED}Failed to connect to Kitescan testnet with proxy {selected_proxy}{Style.RESET_ALL}")
            continue

        try:
            chain_id = w3_transfer.eth.chain_id
            print(f"{Fore.CYAN}Connected to network with chain ID: {chain_id}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Failed to retrieve chain ID: {str(e)}{Style.RESET_ALL}")
            continue

        
        account = w3.eth.account.from_key(private_key)
        sender_address = account.address
        second_proxy = next((proxy for proxy, owner in proxy_mapping.items() if owner == sender_address), None)
        
        if not second_proxy:
            print(f"{Fore.RED}No second proxy address found for account {sender_address}. Skipping transfer.{Style.RESET_ALL}")
            continue

        process_wallet(w3_transfer, private_key, second_proxy, MIN_KITE, MAX_KITE, GAS_LIMIT, GAS_PRICE)
        time.sleep(3)

    print(f"{Fore.GREEN}All KITE transfer operations to second proxy addresses completed!{Style.RESET_ALL}")

if __name__ == "__main__":
    while True:
        try:
            process_all_accounts()
            print(f"{Fore.CYAN}Waiting for next run...{Style.RESET_ALL}")
            display_countdown(INTERVAL_SECONDS)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Script interrupted by user. Exiting...{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Unexpected error in main loop: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Restarting process after delay...{Style.RESET_ALL}")
            time.sleep(60)
