from web3 import Web3
from web3.exceptions import InvalidAddress
from colorama import init, Fore, Style
import os
import time
import random
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import warnings
from web3.exceptions import MismatchedABI
import requests
from web3.providers.rpc import HTTPProvider

warnings.filterwarnings("ignore", category=UserWarning, module="eth_utils")

init()


def load_proxies():
    try:
        with open('proxy.txt', 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
        if not proxies:
            print(f"{Fore.RED}No proxies found in proxy.txt{Style.RESET_ALL}")
            exit(1)
        return proxies
    except FileNotFoundError:
        print(f"{Fore.RED}proxy.txt not found{Style.RESET_ALL}")
        exit(1)


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


w3 = Web3(ProxyHTTPProvider('https://rpc-testnet.gokite.ai/', selected_proxy))
PROXY_FACTORY_ADDRESS = Web3.to_checksum_address('0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2')
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
proxy_factory = w3.eth.contract(address=PROXY_FACTORY_ADDRESS, abi=PROXY_FACTORY_ABI)

if not w3.is_connected():
    print(f"{Fore.RED}Failed to connect to Kitescan testnet{Style.RESET_ALL}")
    exit(1)

try:
    chain_id = w3.eth.chain_id
    print(f"{Fore.CYAN}Connected to network with chain ID: {chain_id}{Style.RESET_ALL}")
except Exception as e:
    print(f"{Fore.RED}Failed to retrieve chain ID: {str(e)}{Style.RESET_ALL}")
    exit(1)

singleton = Web3.to_checksum_address('0x3E5c63644E683549055b9Be8653de26E0B4CD36E')
initializer = '0xb63e800d0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000f48f2b2d2a534e402487b3ee7c18c33aec0fe5e4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000027f45f4d6e1a48902bc1079dAc67B3B690b9816f0000000000000000000000000000000000000000000000000000000000000000'

try:
    with open('accounts.txt', 'r') as file:
        private_keys = [line.strip() for line in file if line.strip()]
except FileNotFoundError:
    print(f"{Fore.RED}accounts.txt not found{Style.RESET_ALL}")
    exit(1)

if not private_keys:
    print(f"{Fore.RED}No private keys found in accounts.txt{Style.RESET_ALL}")
    exit(1)

def display_countdown(seconds):
    while seconds > 0:
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds_left = divmod(remainder, 60)
        print(f"{Fore.CYAN}Next run in {hours:02d}:{minutes:02d}:{seconds_left:02d}{Style.RESET_ALL}", end='\r')
        time.sleep(1)
        seconds -= 1
    print(" " * 50, end='\r')

@retry(stop=stop_after_attempt(5), wait=wait_fixed(5), retry=retry_if_exception_type(Exception))
def process_transaction(idx, private_key, nonce, attempt):
    global w3, proxy_factory, proxies
    
    selected_proxy = random.choice(proxies)
    print(f"{Fore.CYAN}Using proxy for attempt {attempt}: {selected_proxy}{Style.RESET_ALL}")
    w3 = Web3(ProxyHTTPProvider('https://rpc-testnet.gokite.ai/', selected_proxy))
    proxy_factory = w3.eth.contract(address=PROXY_FACTORY_ADDRESS, abi=PROXY_FACTORY_ABI)

    try:
        if not private_key.startswith('0x'):
            private_key = '0x' + private_key
        if len(private_key) != 66:
            raise ValueError(f"Invalid private key length for account {idx}")

        account = w3.eth.account.from_key(private_key)
        sender_address = account.address
        print(f"{Fore.CYAN}Processing account {idx}, attempt {attempt}: {sender_address}{Style.RESET_ALL}")

        salt_nonce = nonce

        balance = w3.eth.get_balance(sender_address)
        if balance < w3.to_wei('0.001', 'ether'):
            print(f"{Fore.YELLOW}Insufficient balance for {sender_address}: {w3.from_wei(balance, 'ether')} ETH{Style.RESET_ALL}")
            return None

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
            'gas': gas_estimate + 10000,
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
                    print(f"{Fore.GREEN}Proxy address: {log['args']['proxy']}{Style.RESET_ALL}")
            except MismatchedABI:
                print(f"{Fore.YELLOW}Warning: Could not parse ProxyCreation event due to ABI mismatch for Tx hash: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Transaction failed for {sender_address}. Tx hash: {w3.to_hex(tx_hash)}{Style.RESET_ALL}")
            try:
                revert_reason = w3.eth.call(tx, block_number=tx_receipt['blockNumber'] - 1)
                print(f"{Fore.RED}Revert reason: {revert_reason}{Style.RESET_ALL}")
            except Exception as re:
                print(f"{Fore.RED}Could not fetch revert reason: {str(re)}{Style.RESET_ALL}")

        return tx_receipt

    except Exception as e:
        print(f"{Fore.RED}Error processing account {idx}, attempt {attempt} ({sender_address}): {str(e)}{Style.RESET_ALL}")
        raise

def process_account(idx, private_key):
    try:
        account = w3.eth.account.from_key(private_key)
        sender_address = account.address
        nonce = w3.eth.get_transaction_count(sender_address)

        for attempt in range(1, 3):
            tx_receipt = process_transaction(idx, private_key, nonce, attempt)
            if tx_receipt and tx_receipt['status'] == 1:
                nonce += 1
            else:
                break
    except Exception as e:
        print(f"{Fore.RED}Account {idx} failed after retries: {str(e)}{Style.RESET_ALL}")

def slow(text, delay_ms):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay_ms / 1000)
    print()

def process_all_accounts():
    header = f"{Fore.GREEN}🪁🪁🪁🪁🪁 KITEAI_MULTISIG_TASK_BOT 🪁🪁🪁🪁🪁{Style.RESET_ALL}"
    slow(header, 100)
    print(f"{Fore.CYAN}Starting account processing at {time.ctime()}{Style.RESET_ALL}")
    for idx, private_key in enumerate(private_keys, 1):
        process_account(idx, private_key)
    print(f"{Fore.CYAN}Finished account processing at {time.ctime()}{Style.RESET_ALL}")

INTERVAL_SECONDS = 12 * 3600
while True:
    process_all_accounts()
    print(f"{Fore.CYAN}Waiting for next run...{Style.RESET_ALL}")
    display_countdown(INTERVAL_SECONDS)
