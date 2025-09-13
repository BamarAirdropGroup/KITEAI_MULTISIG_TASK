import asyncio
import json
import os
import sys
import time
import random
import requests
from datetime import datetime, timezone
from aiohttp import ClientSession, ClientTimeout, ClientResponseError
from colorama import Fore, Style, init
from web3 import Web3
from web3.exceptions import InvalidAddress, MismatchedABI
from web3.providers.rpc import HTTPProvider
from eth_account import Account
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import warnings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import binascii
import pytz
from dotenv import load_dotenv
try:
    from fake_useragent import UserAgent
except ImportError:
    UserAgent = None  


init(convert=True, strip=False, autoreset=True)
warnings.filterwarnings("ignore", category=UserWarning, module="eth_utils")

load_dotenv()

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

class Colors:
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    WHITE = Fore.WHITE
    CYAN = Fore.CYAN
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT

class Logger:
    @staticmethod
    def info(msg): print(f"{Colors.GREEN}[✓] {msg}{Colors.RESET}")
    @staticmethod
    def wallet(msg): print(f"{Colors.YELLOW}[➤] {msg}{Colors.RESET}")
    @staticmethod
    def error(msg): print(f"{Colors.RED}[✗] {msg}{Colors.RESET}")
    @staticmethod
    def success(msg): print(f"{Colors.GREEN}[] {msg}{Colors.RESET}")
    @staticmethod
    def loading(msg): print(f"{Colors.CYAN}[⟳] {msg}{Colors.RESET}")
    @staticmethod
    def step(msg): print(f"{Colors.WHITE}[➤] {msg}{Colors.RESET}")
    @staticmethod
    def banner(title):
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("---------------------------------------------")
        print(f"             {title}")
        print(f"---------------------------------------------{Colors.RESET}\n")

logger = Logger()

class ProxyHTTPProvider(HTTPProvider):
    def __init__(self, endpoint_uri, proxy, **kwargs):
        super().__init__(endpoint_uri, **kwargs)
        self.session = requests.Session()
        if proxy:
            
            proxy_parts = proxy.split('@')
            if len(proxy_parts) == 2:
                credentials, host = proxy_parts
                username, password = credentials.split(':')[1:]  
                self.session.auth = (username, password)
                self.session.proxies = {
                    'http': f'http://{host}',
                    'https': f'http://{host}',
                }
            else:
                self.session.proxies = {
                    'http': proxy,
                    'https': proxy,
                }

    def make_request(self, method, params):
        try:
            response = super().make_request(method, params)
            return response
        except Exception as e:
            logger.error(f"Proxy error: {str(e)}")
            raise

class KiteAIBot:
    def __init__(self):
        self.NEO_API = "https://neo.prod.gokite.ai"
        self.TESTNET_API = "https://testnet.gokite.ai"
        self.TESTNET_HEADERS = {}
        self.auth_tokens = {}
        self.header_cookies = {}
        self.access_tokens = {}
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.wib = pytz.timezone('Asia/Jakarta')
        self.w3 = None
        self.proxy_factory = None
        self.singleton = Web3.to_checksum_address('0x3E5c63644E683549055b9Be8653de26E0B4CD36E')
        self.initializer = '0xb63e800d0000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000f48f2b2d2a534e402487b3ee7c18c33aec0fe5e4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000027f45f4d6e1a48902bc1079dAc67B3B690b9816f0000000000000000000000000000000000000000000000000000000000000000'
        self.PROXY_FACTORY_ADDRESS = Web3.to_checksum_address('0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2')

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    async def load_proxies(self):
        filename = "proxy.txt"
        try:
            if not os.path.exists(filename):
                logger.info("proxy.txt not found or empty, will use direct connection")
                return
            with open(filename, 'r') as f:
                proxies = [line.strip() for line in f.read().splitlines() if line.strip() and not line.startswith("#")]
            self.proxies = []
            for proxy in proxies:
                try:
                    
                    parts = proxy.split('@')
                    if len(parts) != 2:
                        logger.error(f"Invalid proxy format: {proxy}. Expected username:password@ip:port")
                        continue
                    credentials, host = parts
                    scheme, username, password = credentials.split(':')
                    ip, port = host.split(':')
                    self.proxies.append(f"{scheme}:{username}:{password}@{ip}:{port}")
                except Exception as e:
                    logger.error(f"Invalid proxy format: {proxy}. Error: {str(e)}")
            if not self.proxies:
                logger.info("No valid proxies found in proxy.txt")
                return
            logger.info(f"Loaded {len(self.proxies)} valid proxies from proxy.txt")
        except Exception as e:
            logger.error(f"Failed to load proxies: {e}")
            self.proxies = []

    def check_proxy_schemes(self, proxy):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxy.startswith(scheme) for scheme in schemes):
            return proxy
        return f"http://{proxy}"

    def get_next_proxy_for_account(self, account):
        if account not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[account] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[account]

    def rotate_proxy(self, account):
        """Rotate to the next proxy for the given account."""
        if not self.proxies:
            return None
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[account] = proxy
        logger.info(f"Rotated to new proxy for {account}: {proxy}")
        return proxy

    def generate_address(self, private_key: str):
        try:
            account = Account.from_key(private_key)
            logger.info(f"Wallet created: {account.address}")
            return account.address
        except Exception as e:
            logger.error(f"Invalid private key: {e}")
            return None

    def mask_account(self, account):
        try:
            return account[:6] + '*' * 6 + account[-6:]
        except Exception:
            return None

    def encrypt_address(self, address):
        try:
            key_hex = "6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a"
            key = bytes.fromhex(key_hex)
            iv = os.urandom(12)
            aesgcm = AESGCM(key)
            encrypted = aesgcm.encrypt(iv, address.encode(), None)
            auth_tag = encrypted[-16:]
            ciphertext = encrypted[:-16]
            result = iv + ciphertext + auth_tag
            return result.hex()
        except Exception as e:
            logger.error(f"Auth token generation failed for {address}: {str(e)}")
            return None

    def extract_cookies(self, headers):
        try:
            raw_cookies = headers.getall('Set-Cookie', [])
            skip_keys = ["expires", "path", "domain", "samesite", "secure", "httponly", "max-age"]
            cookies_dict = {}
            for cookie_str in raw_cookies:
                parts = cookie_str.split(";")
                for part in parts:
                    cookie = part.strip()
                    if "=" in cookie:
                        name, value = cookie.split("=", 1)
                        if name.lower() not in skip_keys:
                            cookies_dict[name] = value
            return "; ".join(f"{k}={v}" for k, v in cookies_dict.items()) or None
        except Exception:
            return None

    async def user_signin(self, address: str, use_proxy: bool, max_retries=3):
        url = f"{self.NEO_API}/v2/signin"
        proxy_attempts = len(self.proxies) if use_proxy else 1
        for proxy_attempt in range(proxy_attempts):
            proxy_url = self.get_next_proxy_for_account(address) if use_proxy else None
            logger.info(f"Using proxy for {address}: {proxy_url or 'None'}")
            for attempt in range(1, max_retries + 1):
                try:
                    logger.loading(f"Logging in to {address} (Proxy Attempt {proxy_attempt + 1}/{proxy_attempts}, Attempt {attempt}/{max_retries})")
                    auth_token = self.encrypt_address(address)
                    if not auth_token:
                        return None
                    headers = {
                        **self.TESTNET_HEADERS[address],
                        "Authorization": auth_token,
                        "Content-Type": "application/json"
                    }
                    body = json.dumps({"eoa": address})
                    async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                        async with session.post(url=url, headers=headers, data=body, proxy=proxy_url) as response:
                            if response.status == 500:
                                error_text = await response.text()
                                logger.error(f"Server Error (500) for {address} - Response: {error_text}")
                                if attempt < max_retries:
                                    await asyncio.sleep(10)
                                    continue
                                return None
                            if response.status == 407:
                                logger.error(f"Proxy Authentication Required for {address} with proxy {proxy_url}")
                                if use_proxy and proxy_attempt < proxy_attempts - 1:
                                    proxy_url = self.rotate_proxy(address)
                                    break  
                                return None
                            response.raise_for_status()
                            data = await response.json()
                            if data.get("error"):
                                logger.error(f"Login failed for {address}: {data['error']}")
                                return None
                            access_token = data["data"]["access_token"]
                            aa_address = data["data"]["aa_address"]
                            cookie_header = self.extract_cookies(response.headers)
                            logger.success(f"Login successful for {address}")
                            return {
                                "access_token": access_token,
                                "aa_address": aa_address,
                                "cookie_header": cookie_header
                            }
                except ClientResponseError as e:
                    logger.error(f"Login failed for {address} - {e.status}, message='{e.message}', url='{url}'")
                    if e.status == 407 and use_proxy and proxy_attempt < proxy_attempts - 1:
                        logger.info(f"Rotating proxy for {address} due to 407 error")
                        proxy_url = self.rotate_proxy(address)
                        break  
                    if attempt < max_retries:
                        await asyncio.sleep(5)
                        continue
                except Exception as e:
                    logger.error(f"Login failed for {address}: {str(e)}")
                    if attempt < max_retries:
                        await asyncio.sleep(5)
                        continue
            else:
                continue  
        return None

    async def create_quiz(self, address: str, use_proxy: bool, retries=5):
        url = f"{self.NEO_API}/v2/quiz/create"
        data = json.dumps({"title": self.generate_quiz_title(), "num": 1, "eoa": address})
        headers = {
            **self.TESTNET_HEADERS[address],
            "Authorization": f"Bearer {self.access_tokens[address]}",
            "Cookie": self.header_cookies.get(address, ''),
            "Content-Length": str(len(data)),
            "Content-Type": "application/json"
        }
        for attempt in range(retries):
            proxy_url = self.get_next_proxy_for_account(address) if use_proxy else None
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy_url) as response:
                        response.raise_for_status()
                        return await response.json()
            except Exception as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                logger.error(f"Fetch Today Quiz Failed for {address}: {str(e)}")
        return None

    async def get_quiz(self, address: str, quiz_id: int, use_proxy: bool, retries=5):
        url = f"{self.NEO_API}/v2/quiz/get?id={quiz_id}&eoa={address}"
        headers = {
            **self.TESTNET_HEADERS[address],
            "Authorization": f"Bearer {self.access_tokens[address]}",
            "Cookie": self.header_cookies.get(address, '')
        }
        for attempt in range(retries):
            proxy_url = self.get_next_proxy_for_account(address) if use_proxy else None
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy_url) as response:
                        response.raise_for_status()
                        return await response.json()
            except Exception as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                logger.error(f"Fetch Question & Answer Failed for {address}: {str(e)}")
        return None

    async def submit_quiz(self, address: str, quiz_id: int, question_id: int, quiz_answer: str, use_proxy: bool, retries=5):
        url = f"{self.NEO_API}/v2/quiz/submit"
        data = json.dumps({"quiz_id": quiz_id, "question_id": question_id, "answer": quiz_answer, "finish": True, "eoa": address})
        headers = {
            **self.TESTNET_HEADERS[address],
            "Authorization": f"Bearer {self.access_tokens[address]}",
            "Cookie": self.header_cookies.get(address, ''),
            "Content-Length": str(len(data)),
            "Content-Type": "application/json"
        }
        for attempt in range(retries):
            proxy_url = self.get_next_proxy_for_account(address) if use_proxy else None
            try:
                async with ClientSession(timeout=ClientTimeout(total=120)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy_url) as response:
                        response.raise_for_status()
                        return await response.json()
            except Exception as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                logger.error(f"Submit Answer Failed for {address}: {str(e)}")
        return None

    def generate_quiz_title(self):
        today = datetime.today().strftime('%Y-%m-%d')
        return f"daily_quiz_{today}"

    async def process_daily_quiz(self, address: str, use_proxy: bool):
        logger.step(f"Daily Quiz for {address}")
        create = await self.create_quiz(address, use_proxy)
        if not create:
            return
        quiz_id = create.get("data", {}).get("quiz_id")
        status = create.get("data", {}).get("status")
        logger.step(f"Quiz Id: {quiz_id}")
        if status != 0:
            logger.info(f"Already Answered Today for {address}")
            return
        quiz = await self.get_quiz(address, quiz_id, use_proxy)
        if not quiz:
            return
        questions = quiz.get("data", {}).get("question", [])
        for question in questions:
            if question:
                question_id = question.get("question_id")
                quiz_content = question.get("content")
                quiz_answer = question.get("answer")
                logger.step(f"Question: {quiz_content}")
                logger.step(f"Answer: {quiz_answer}")
                submit_quiz = await self.submit_quiz(address, quiz_id, question_id, quiz_answer, use_proxy)
                if not submit_quiz:
                    return
                result = submit_quiz.get("data", {}).get("result")
                if result == "RIGHT":
                    logger.success(f"Correct answer submitted for {address}")
                else:
                    logger.info(f"Wrong answer submitted for {address}")

    def load_receivers(self):
        try:
            with open(RECEIVER_FILE, 'r') as file:
                receivers = [line.strip() for line in file if line.strip()]
            valid_receivers = [addr for addr in receivers if Web3.is_address(addr)]
            if not valid_receivers:
                logger.error(f"No valid receiver addresses found in {RECEIVER_FILE}")
                return []
            return valid_receivers
        except FileNotFoundError:
            logger.error(f"{RECEIVER_FILE} not found")
            return []

    def slow(self, text, delay_ms):
        try:
            for char in text:
                print(char, end='', flush=True)
                time.sleep(delay_ms / 1000)
            print()
        except Exception as e:
            logger.error(f"Error during slow print: {str(e)}")

    @retry(stop=stop_after_attempt(5), wait=wait_fixed(5), retry=retry_if_exception_type(Exception))
    def process_transaction(self, idx, private_key, attempt, request_count, proxy_mapping):
        selected_proxy = random.choice(self.proxies) if self.proxies else None
        logger.info(f"Using proxy for attempt {attempt}, request {request_count}: {selected_proxy or 'None'}")
        w3 = Web3(ProxyHTTPProvider(RPC_URL, selected_proxy) if selected_proxy else HTTPProvider(RPC_URL))
        proxy_factory = w3.eth.contract(address=self.PROXY_FACTORY_ADDRESS, abi=PROXY_FACTORY_ABI)
        try:
            if not private_key.startswith('0x'):
                private_key = '0x' + private_key
            if len(private_key) != 66:
                raise ValueError(f"Invalid private key length for account {idx}")
            account = w3.eth.account.from_key(private_key)
            sender_address = account.address
            logger.info(f"Processing account {idx}, attempt {attempt}, request {request_count}: {sender_address}")
            salt_nonce = random.randint(1, 10**18)
            balance = w3.eth.get_balance(sender_address)
            if balance < Web3.to_wei('0.001', 'ether'):
                logger.warning(f"Insufficient balance for {sender_address}: {w3.from_wei(balance, 'ether')} ETH")
                return None, None
            nonce = w3.eth.get_transaction_count(sender_address, 'pending')
            gas_estimate = proxy_factory.functions.createProxyWithNonce(
                self.singleton, self.initializer, salt_nonce
            ).estimate_gas({'from': sender_address})
            tx = proxy_factory.functions.createProxyWithNonce(
                self.singleton, self.initializer, salt_nonce
            ).build_transaction({
                'from': sender_address,
                'gas': gas_estimate + 100000,
                'gasPrice': w3.eth.gas_price,
                'nonce': nonce,
                'chainId': w3.eth.chain_id
            })
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Transaction sent: {w3.to_hex(tx_hash)}")
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            if tx_receipt['status'] == 1:
                logger.success(f"Transaction successful for {sender_address}! Tx Explorer: https://testnet.kitescan.ai/tx/{w3.to_hex(tx_hash)}")
                try:
                    logs = proxy_factory.events.ProxyCreation().process_receipt(tx_receipt)
                    for log in logs:
                        proxy_address = log['args']['proxy']
                        logger.success(f"Created proxy address: {proxy_address}")
                        code = w3.eth.get_code(proxy_address)
                        if len(code) <= 2:
                            logger.error(f"Proxy {proxy_address} is not a valid contract!")
                            return None, None
                        else:
                            logger.success(f"Proxy {proxy_address} is a valid contract.")
                            with open('address.txt', 'a') as f:
                                f.write(f"{proxy_address}\n")
                            proxy_mapping[proxy_address] = sender_address
                            return tx_receipt, proxy_address
                except MismatchedABI:
                    logger.warning(f"Could not parse ProxyCreation event due to ABI mismatch for Tx hash: {w3.to_hex(tx_hash)}")
                    return None, None
            else:
                logger.error(f"Transaction failed for {sender_address}. Tx hash: {w3.to_hex(tx_hash)}")
                try:
                    tx_params = {
                        'from': sender_address,
                        'to': self.PROXY_FACTORY_ADDRESS,
                        'data': tx['data'],
                        'value': 0,
                        'gas': gas_estimate,
                        'gasPrice': w3.eth.gas_price,
                    }
                    w3.eth.call(tx_params)
                except Exception as re:
                    logger.error(f"Revert reason: {str(re)}")
                return None, None
        except Exception as e:
            logger.error(f"Error processing account {idx}, attempt {attempt}, request {request_count} ({sender_address}): {str(e)}")
            raise

    def send_with_gas(self, w3, private_key, sender_address, to_address, amount, gas_limit, gas_price, nonce):
        try:
            tx = {
                'to': Web3.to_checksum_address(to_address),
                'value': amount,
                'gas': gas_limit,
                'gasPrice': gas_price,
                'nonce': nonce,
                'chainId': w3.eth.chain_id
            }
            logger.info(f"Preparing to send {w3.from_wei(amount, 'ether')} KITE to {to_address} with nonce {nonce}")
            signed_tx = w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            logger.info(f"Transaction hash: {w3.to_hex(tx_hash)}")
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=300)
            if receipt['status'] == 0:
                logger.error(f"Transaction reverted for {to_address}. Tx hash: {w3.to_hex(tx_hash)}")
            else:
                logger.success(f"Transaction confirmed for {to_address} in block: {receipt['blockNumber']}")
                logger.success(f"Gas used: {receipt['gasUsed']}")
        except Exception as e:
            logger.error(f"Failed to send to {to_address}: {str(e)}")

    def process_wallet(self, w3, private_key, receiver, min_kite, max_kite, gas_limit, gas_price):
        try:
            if not private_key.startswith('0x'):
                private_key = '0x' + private_key
            if len(private_key) != 66:
                raise ValueError("Invalid private key length")
            account = w3.eth.account.from_key(private_key)
            sender_address = account.address
            logger.info(f"\nProcessing wallet: {sender_address}")
            balance = w3.eth.get_balance(sender_address)
            logger.info(f"Current balance: {w3.from_wei(balance, 'ether')} KITE")
            gas_cost = gas_limit * gas_price
            logger.info(f"Estimated gas cost: {w3.from_wei(gas_cost, 'ether')} KITE")
            amount_kite = random.uniform(min_kite, max_kite)
            amount_wei = w3.to_wei(amount_kite, 'ether')
            total_needed = amount_wei + gas_cost
            if balance < total_needed:
                logger.error(f"Insufficient balance. Need at least {w3.from_wei(total_needed, 'ether')} KITE for transaction and gas costs")
                return
            logger.info(f"Sending {amount_kite} KITE to second proxy address: {receiver}")
            nonce = w3.eth.get_transaction_count(sender_address, 'pending')
            self.send_with_gas(w3, private_key, sender_address, receiver, amount_wei, gas_limit, gas_price, nonce)
        except Exception as e:
            logger.error(f"Error processing wallet {sender_address}: {str(e)}")

    def process_account(self, idx, private_key, proxy_mapping):
        try:
            proxy_addresses = []
            for attempt in range(1, 4):
                logger.info(f"Attempt {attempt} for account {idx}")
                
                tx_receipt_1, proxy_address_1 = self.process_transaction(idx, private_key, attempt, 1, proxy_mapping)
                if tx_receipt_1 and tx_receipt_1['status'] == 1 and proxy_address_1:
                    logger.success(f"First proxy creation successful for account {idx}: {proxy_address_1}")
                    proxy_addresses.append(proxy_address_1)
                else:
                    logger.warning(f"First proxy creation failed for account {idx}. Retrying...")
                    time.sleep(5)
                    continue

                time.sleep(DELAY_BETWEEN_TX)  

                
                tx_receipt_2, proxy_address_2 = self.process_transaction(idx, private_key, attempt, 2, proxy_mapping)
                if tx_receipt_2 and tx_receipt_2['status'] == 1 and proxy_address_2:
                    logger.success(f"Second proxy creation successful for account {idx}: {proxy_address_2}")
                    proxy_addresses.append(proxy_address_2)
                    break 
                else:
                    logger.warning(f"Second proxy creation failed for account {idx}. Retrying...")
                    time.sleep(5)
                    continue
            if len(proxy_addresses) == 2:
                logger.success(f"Both proxy creations completed for account {idx}: {proxy_addresses}")
            else:
                logger.error(f"Failed to create both proxies for account {idx}. Only created: {proxy_addresses}")
            return proxy_addresses
        except Exception as e:
            logger.error(f"Account {idx} failed after retries: {str(e)}")
            return []

    async def process_all_accounts(self, private_keys, use_proxy):
        self.clear_terminal()
        logger.info(f"Starting processing for {len(private_keys)} accounts at {datetime.now(self.wib).strftime('%Y-%m-%d %H:%M:%S')}")
        separator = "=" * 25
        with open('address.txt', 'w') as f:
            f.write('')  
        proxy_mapping = {}

        for idx, private_key in enumerate(private_keys, 1):
            if not private_key:
                logger.error(f"Empty private key at index {idx}. Skipping.")
                continue
            address = self.generate_address(private_key)
            logger.wallet(f"{separator}[ {self.mask_account(address)} ]{separator}")
            if not address:
                logger.error("Invalid Private Key")
                continue

            
            if UserAgent:
                ua = UserAgent()
                user_agent = ua.random
            else:
                user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            self.TESTNET_HEADERS[address] = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                "Origin": "https://testnet.gokite.ai",
                "Referer": "https://testnet.gokite.ai/",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-site",
                "User-Agent": user_agent,
                "Content-Type": "application/json"
            }

            # Step 1: Perform daily quiz
            if use_proxy:
                proxy = self.get_next_proxy_for_account(address)
                logger.info(f"Using proxy for quiz: {proxy or 'None'}")
            else:
                logger.info("Using direct connection for quiz (no proxy)")
            auth_token = self.encrypt_address(address)
            if not auth_token:
                logger.error("Failed to generate auth token. Skipping account.")
                continue
            self.auth_tokens[address] = auth_token
            signin = await self.user_signin(address, use_proxy)
            if signin:
                self.access_tokens[address] = signin["access_token"]
                self.header_cookies[address] = signin["cookie_header"]
                await self.process_daily_quiz(address, use_proxy)
            else:
                logger.error("Login Failed. Skipping quiz for this account.")
                
            await asyncio.sleep(3)

            
            logger.banner("KiteAI Multisig Task Bot")
            logger.info(f"Starting multisig processing for account {idx} at {datetime.now(self.wib).strftime('%Y-%m-%d %H:%M:%S')}")
            proxy_addresses = self.process_account(idx, private_key, proxy_mapping)
            if len(proxy_addresses) != 2:
                logger.error(f"Failed to create two proxies for account {idx}. Skipping transfer.")
                continue
            logger.info(f"Finished multisig processing for account {idx} at {datetime.now(self.wib).strftime('%Y-%m-%d %H:%M:%S')}")

            
            logger.info("Starting KITE transfer to second proxy address...")
            selected_proxy = random.choice(self.proxies) if self.proxies else None
            logger.info(f"Using proxy for wallet {idx}: {selected_proxy or 'None'}")
            w3_transfer = Web3(ProxyHTTPProvider(RPC_URL, selected_proxy) if selected_proxy else HTTPProvider(RPC_URL))
            if not w3_transfer.is_connected():
                logger.error(f"Failed to connect to Kitescan testnet with proxy {selected_proxy or 'None'}")
                continue
            try:
                chain_id = w3_transfer.eth.chain_id
                logger.info(f"Connected to network with chain ID: {chain_id}")
            except Exception as e:
                logger.error(f"Failed to retrieve chain ID: {str(e)}")
                continue
            account = w3_transfer.eth.account.from_key(private_key)
            sender_address = account.address
            second_proxy = proxy_addresses[1]  
            if not second_proxy:
                logger.error(f"No second proxy address found for account {sender_address}. Skipping transfer.")
                continue
            self.process_wallet(w3_transfer, private_key, second_proxy, MIN_KITE, MAX_KITE, GAS_LIMIT, GAS_PRICE)
            logger.success(f"All tasks completed for account {idx}: {sender_address}")
            await asyncio.sleep(3)

        logger.info("="*72)
        logger.success("All accounts have been processed for quiz, multisig, and transfers")

    def display_countdown(self, seconds):
        while seconds > 0:
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds_left = divmod(remainder, 60)
            print(f"{Colors.CYAN}Next run in {hours:02d}:{minutes:02d}:{seconds_left:02d}{Colors.RESET}", end='\r')
            time.sleep(1)
            seconds -= 1
        print(" " * 50, end='\r')

    async def main(self):
        try:
            
            self.slow(f"{Colors.GREEN}🪁🪁🪁🪁🪁 KITEAI_DAILY_QUIZ_&_MULTISIG_TASK_BOT 1.1 🪁🪁🪁🪁🪁{Colors.RESET}", 100)
            with open('accounts.txt', 'r') as file:
                private_keys = [line.strip() for line in file if line.strip() and not line.startswith("#")]
            if not private_keys:
                logger.error("No private keys found in accounts.txt")
                sys.exit(1)
            self.clear_terminal()
            while True:
                print(f"{Colors.WHITE}1. Run With Proxy{Colors.RESET}")
                print(f"{Colors.WHITE}2. Run Without Proxy{Colors.RESET}")
                proxy_choice = input(f"{Colors.CYAN}Choose [1/2] -> {Colors.RESET}").strip()
                try:
                    proxy_choice = int(proxy_choice)
                    if proxy_choice in [1, 2]:
                        use_proxy = proxy_choice == 1
                        break
                    print(f"{Colors.RED}Please enter either 1 or 2.{Colors.RESET}")
                except ValueError:
                    print(f"{Colors.RED}Invalid input. Please enter 1 or 2.{Colors.RESET}")
            if use_proxy:
                await self.load_proxies()
                if not self.proxies:
                    logger.warning("No valid proxies loaded. Falling back to direct connection.")
                    use_proxy = False
            while True:
                try:
                    await self.process_all_accounts(private_keys, use_proxy)
                    logger.info("Waiting for next run...")
                    self.display_countdown(INTERVAL_SECONDS)
                except KeyboardInterrupt:
                    logger.warning("Script interrupted by user. Exiting...")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in main loop: {str(e)}")
                    logger.info("Restarting process after delay...")
                    time.sleep(60)
        except FileNotFoundError:
            logger.error("File 'accounts.txt' Not Found")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Critical Error: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    bot = KiteAIBot()
    asyncio.run(bot.main())
