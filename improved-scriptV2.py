import requests
import json
import time
import csv
import os
import re
import urllib.parse
import logging
import argparse
import threading
import queue
import random
from datetime import datetime
from typing import Dict, List, Optional, Union, Any, Tuple
from pathlib import Path
import concurrent.futures
import hashlib
import keyring
from dotenv import load_dotenv
from tqdm import tqdm

# Load environment variables from .env file if it exists
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"checker_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("BJP_Checker")

# For multipart form data
try:
    from requests_toolbelt.multipart.encoder import MultipartEncoder
except ImportError:
    logger.info("Installing requests-toolbelt for multipart form support...")
    import pip
    pip.main(["install", "requests-toolbelt"])
    from requests_toolbelt.multipart.encoder import MultipartEncoder

# User agent rotation for avoiding detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.171 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.170 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.2 Safari/605.1.15"
]

class TokenError(Exception):
    """Custom exception for token-related errors"""
    pass

class TokenManager:
    """Class to manage access tokens and refreshing with improved security"""
    
    SERVICE_NAME = "BJP_Phone_Checker"
    
    def __init__(self, access_token: str, refresh_token: str):
        """
        Initialize the token manager with access and refresh tokens
        
        Args:
            access_token (str): The access token for API calls
            refresh_token (str): The refresh token to get new access tokens
        """
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_refresh_attempts = 0
        self.max_refresh_attempts = 3
        self.token_lock = threading.Lock()
        self.last_refresh_time = 0
        
        # Cache the token creation time to track potential expiry
        self.token_created_at = time.time()
        
        # Session for connection pooling
        self.session = requests.Session()
        
        # Store tokens securely if possible
        try:
            self._secure_store_tokens()
        except Exception as e:
            logger.warning(f"Could not securely store tokens: {e}. Using memory storage only.")
    
    def _secure_store_tokens(self) -> None:
        """Store tokens securely using keyring if possible"""
        # Hash the tokens to create a unique username
        username_hash = hashlib.sha256(self.access_token[:10].encode()).hexdigest()[:16]
        try:
            keyring.set_password(self.SERVICE_NAME, f"{username_hash}_access", self.access_token)
            keyring.set_password(self.SERVICE_NAME, f"{username_hash}_refresh", self.refresh_token)
            self.keyring_username = username_hash
            self.using_keyring = True
            logger.debug("Tokens stored securely using keyring")
        except Exception as e:
            logger.warning(f"Keyring storage failed: {e}")
            self.using_keyring = False
    
    def _secure_retrieve_tokens(self) -> Tuple[str, str]:
        """Retrieve tokens from secure storage"""
        if not hasattr(self, 'using_keyring') or not self.using_keyring:
            return self.access_token, self.refresh_token
            
        try:
            access_token = keyring.get_password(self.SERVICE_NAME, f"{self.keyring_username}_access")
            refresh_token = keyring.get_password(self.SERVICE_NAME, f"{self.keyring_username}_refresh")
            return access_token, refresh_token
        except Exception as e:
            logger.warning(f"Error retrieving tokens from keyring: {e}")
            return self.access_token, self.refresh_token
    
    def _secure_update_tokens(self, access_token: str, refresh_token: str) -> None:
        """Update tokens in secure storage"""
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_created_at = time.time()
        
        if hasattr(self, 'using_keyring') and self.using_keyring:
            try:
                keyring.set_password(self.SERVICE_NAME, f"{self.keyring_username}_access", access_token)
                keyring.set_password(self.SERVICE_NAME, f"{self.keyring_username}_refresh", refresh_token)
                logger.debug("Updated tokens in secure storage")
            except Exception as e:
                logger.warning(f"Error updating tokens in keyring: {e}")
    
    def get_token(self) -> str:
        """
        Get the current access token, refreshing if necessary
        
        Returns:
            str: The current access token
        """
        with self.token_lock:
            access_token, _ = self._secure_retrieve_tokens()
            
            # Check if token might be expired based on time
            current_time = time.time()
            token_age = current_time - self.token_created_at
            
            # If token is older than 23 hours (being cautious), refresh it
            if token_age > 82800:  # 23 hours in seconds
                logger.info("Token might be expired based on age. Refreshing...")
                self.refresh_access_token()
                access_token, _ = self._secure_retrieve_tokens()
            
            return access_token
    
    def refresh_access_token(self) -> bool:
        """
        Refresh the access token using the refresh token with improved error handling
        
        Returns:
            bool: True if refresh was successful, False otherwise
        """
        with self.token_lock:
            # Rate limit token refreshes
            current_time = time.time()
            if current_time - self.last_refresh_time < 5:  # Don't refresh more than once every 5 seconds
                logger.debug("Throttling token refresh attempts")
                time.sleep(5)
            
            self.last_refresh_time = current_time
            
            if self.token_refresh_attempts >= self.max_refresh_attempts:
                logger.error("Maximum token refresh attempts reached.")
                return False
                
            self.token_refresh_attempts += 1
            
            # Retrieve tokens from secure storage if available
            access_token, refresh_token = self._secure_retrieve_tokens()
            
            try:
                # Correct endpoint for refreshing tokens
                refresh_url = "https://prod-pm-drive.bjp.org/api/v1/token/refresh"
                
                # Prepare multipart form data with the refresh token
                multipart_data = MultipartEncoder(
                    fields={
                        'refresh_token': refresh_token
                    }
                )
                
                # Select a random user agent
                user_agent = random.choice(USER_AGENTS)
                
                headers = {
                    "Content-Type": multipart_data.content_type,
                    "Authorization": f"Bearer {access_token}",
                    "User-Agent": user_agent,
                    "Origin": "https://bjpsadasyata.narendramodi.in",
                    "Referer": "https://bjpsadasyata.narendramodi.in/",
                    "Accept": "*/*",
                    "Sec-Fetch-Site": "cross-site",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Dest": "empty"
                }
                
                # Use connection pooling with timeout and keep-alive
                response = self.session.post(
                    refresh_url, 
                    headers=headers, 
                    data=multipart_data, 
                    timeout=15,
                    verify=True  # Ensure SSL verification is enabled
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    
                    if "token" in token_data and "access_token" in token_data["token"]:
                        new_access_token = token_data["token"]["access_token"]
                        new_refresh_token = token_data["token"].get("refresh_token", refresh_token)
                        
                        # Update tokens securely
                        self._secure_update_tokens(new_access_token, new_refresh_token)
                        
                        logger.info("Access token refreshed successfully.")
                        if "refresh_token" in token_data["token"]:
                            logger.info("Refresh token also updated.")
                            
                        # Reset counter on successful refresh
                        self.token_refresh_attempts = 0
                        return True
                
                # Handle common error codes
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited. Waiting for {retry_after} seconds before retry.")
                    time.sleep(retry_after)
                    return self.refresh_access_token()
                
                # Fallback to regular JSON approach if multipart fails
                if response.status_code != 200:
                    logger.warning(f"Multipart token refresh failed with status {response.status_code}. Trying JSON fallback.")
                    fallback_headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {access_token}",
                        "User-Agent": user_agent,
                        "Origin": "https://bjpsadasyata.narendramodi.in",
                        "Referer": "https://bjpsadasyata.narendramodi.in/"
                    }
                    
                    fallback_payload = {
                        "refresh_token": refresh_token
                    }
                    
                    fallback_response = self.session.post(
                        refresh_url, 
                        headers=fallback_headers, 
                        json=fallback_payload, 
                        timeout=15,
                        verify=True
                    )
                    
                    if fallback_response.status_code == 200:
                        fallback_data = fallback_response.json()
                        
                        if "token" in fallback_data and "access_token" in fallback_data["token"]:
                            new_access_token = fallback_data["token"]["access_token"]
                            new_refresh_token = fallback_data["token"].get("refresh_token", refresh_token)
                            
                            # Update tokens securely
                            self._secure_update_tokens(new_access_token, new_refresh_token)
                            
                            logger.info("Access token refreshed successfully using fallback approach.")
                            if "refresh_token" in fallback_data["token"]:
                                logger.info("Refresh token also updated.")
                                
                            # Reset counter on successful refresh
                            self.token_refresh_attempts = 0
                            return True
                
                logger.error(f"Failed to refresh token. Status code: {response.status_code}")
                logger.debug(f"Response: {response.text}")
                return False
                
            except requests.exceptions.Timeout:
                logger.error("Connection timeout during token refresh")
                return False
            except requests.exceptions.ConnectionError:
                logger.error("Connection error during token refresh")
                return False
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error during token refresh: {str(e)}")
                return False
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in response during token refresh")
                return False
            except Exception as e:
                logger.error(f"Error refreshing token: {str(e)}")
                return False
    
    @classmethod
    def from_redirect_url(cls, url: str) -> Optional['TokenManager']:
        """
        Create a TokenManager instance from a redirect URL containing tokens
        
        Args:
            url (str): The URL containing access_token and refresh_token parameters
            
        Returns:
            TokenManager: A new instance, or None if tokens couldn't be extracted
        """
        try:
            # Parse the URL
            parsed_url = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Extract tokens
            access_token = query_params.get('access_token', [None])[0]
            refresh_token = query_params.get('refresh_token', [None])[0]
            
            if access_token and refresh_token:
                return cls(access_token, refresh_token)
            else:
                logger.error("Failed to extract tokens from URL")
                return None
                
        except Exception as e:
            logger.error(f"Error extracting tokens from URL: {str(e)}")
            return None
    
    @classmethod
    def from_env(cls) -> Optional['TokenManager']:
        """
        Create a TokenManager instance from environment variables
        
        Returns:
            TokenManager: A new instance, or None if tokens couldn't be found
        """
        access_token = os.environ.get('BJP_ACCESS_TOKEN')
        refresh_token = os.environ.get('BJP_REFRESH_TOKEN')
        
        if access_token and refresh_token:
            logger.info("Using tokens from environment variables")
            return cls(access_token, refresh_token)
        return None

class PhoneValidator:
    """Validates and normalizes phone numbers"""
    
    @staticmethod
    def validate_phone(phone: str) -> Tuple[bool, str]:
        """
        Validate and normalize a phone number
        
        Args:
            phone (str): The phone number to validate
            
        Returns:
            Tuple[bool, str]: (is_valid, normalized_number)
        """
        # Remove all non-digit characters
        normalized = re.sub(r'\D', '', phone)
        
        # Check if it's a valid Indian phone number (10 digits, optionally with country code)
        if len(normalized) == 10 and normalized[0] in ['6', '7', '8', '9']:
            return True, normalized
        elif len(normalized) == 11 and normalized[0] == '0' and normalized[1] in ['6', '7', '8', '9']:
            return True, normalized[1:]  # Remove leading 0
        elif len(normalized) == 12 and normalized[0:2] == '91' and normalized[2] in ['6', '7', '8', '9']:
            return True, normalized[2:]  # Remove country code
        elif len(normalized) == 13 and normalized[0:3] == '+91' and normalized[3] in ['6', '7', '8', '9']:
            return True, normalized[3:]  # Remove country code with +
        
        return False, normalized

class APIClient:
    """Client for making API calls to check phone numbers"""
    
    def __init__(self, token_manager: TokenManager):
        """
        Initialize the API client
        
        Args:
            token_manager (TokenManager): Token manager for handling authentication
        """
        self.token_manager = token_manager
        self.session = requests.Session()
        self.request_count = 0
        self.last_request_time = 0
        self.request_lock = threading.Lock()
        self.results_cache = {}  # Cache results to avoid duplicate requests
    
    def _rate_limit(self) -> None:
        """Implement rate limiting to avoid API blocks"""
        with self.request_lock:
            self.request_count += 1
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            # Apply different rate limits based on request count
            if self.request_count > 100:
                min_delay = 2.0  # Slow down significantly after 100 requests
            elif self.request_count > 50:
                min_delay = 1.5  # Medium delay after 50 requests
            else:
                min_delay = 1.0  # Base delay
                
            # Add jitter to avoid detection patterns (±20%)
            jitter = min_delay * (0.8 + random.random() * 0.4)
            
            if time_since_last < jitter:
                sleep_time = jitter - time_since_last
                time.sleep(sleep_time)
                
            self.last_request_time = time.time()
    
    def check_phone_number(self, phone_number: str) -> Dict[str, Any]:
        """
        Check if a phone number is registered, with token refresh handling
        
        Args:
            phone_number (str): The phone number to check
        
        Returns:
            dict: Dictionary containing status and response data
        """
        # Validate phone number
        is_valid, normalized_phone = PhoneValidator.validate_phone(phone_number)
        if not is_valid:
            return {
                "status": "invalid_number",
                "phone_number": phone_number,
                "normalized_phone": normalized_phone,
                "message": "Invalid phone number format",
                "data": None,
                "raw_status_code": None
            }
        
        # Check cache first
        if normalized_phone in self.results_cache:
            cached_result = self.results_cache[normalized_phone]
            cached_result["from_cache"] = True
            logger.debug(f"Cache hit for {normalized_phone}")
            return cached_result
        
        # Apply rate limiting
        self._rate_limit()
        
        url = "https://prod-pm-drive.bjp.org/api/v1/pm/validate_referral"
        
        # Select a random user agent
        user_agent = random.choice(USER_AGENTS)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token_manager.get_token()}",
            "User-Agent": user_agent,
            "Origin": "https://bjpsadasyata.narendramodi.in",
            "Referer": "https://bjpsadasyata.narendramodi.in/",
            "Accept": "*/*",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "cross-site",
            "Sec-Fetch-Dest": "empty"
        }
        
        payload = {
            "phone_number": normalized_phone
        }
        
        try:
            response = self.session.post(
                url, 
                headers=headers, 
                json=payload, 
                timeout=15,
                verify=True  # Ensure SSL verification
            )
            
            # Successful response (registered number)
            if response.status_code == 200:
                result = {
                    "status": "registered",
                    "phone_number": phone_number,
                    "normalized_phone": normalized_phone,
                    "message": "Number is registered",
                    "data": response.json(),
                    "raw_status_code": response.status_code,
                    "from_cache": False
                }
                # Cache the result
                self.results_cache[normalized_phone] = result.copy()
                return result
                
            # Bad request (not registered)
            elif response.status_code == 400:
                result = {
                    "status": "not_registered",
                    "phone_number": phone_number,
                    "normalized_phone": normalized_phone,
                    "message": "Number is not registered",
                    "data": response.json(),
                    "raw_status_code": response.status_code,
                    "from_cache": False
                }
                # Cache the result
                self.results_cache[normalized_phone] = result.copy()
                return result
                
            # Token expired or invalid
            elif response.status_code in (401, 403):
                # Try to refresh the token
                token_refreshed = self.token_manager.refresh_access_token()
                
                if token_refreshed:
                    # Retry with new token
                    logger.info("Token refreshed, retrying request")
                    return self.check_phone_number(phone_number)
                else:
                    return {
                        "status": "token_expired",
                        "phone_number": phone_number,
                        "normalized_phone": normalized_phone,
                        "message": "Token expired and refresh failed",
                        "data": response.text,
                        "raw_status_code": response.status_code,
                        "from_cache": False
                    }
                    
            # Rate limiting
            elif response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 30))
                logger.warning(f"Rate limited. Waiting for {retry_after} seconds.")
                time.sleep(retry_after)
                return self.check_phone_number(phone_number)
                
            # Other response codes
            else:
                return {
                    "status": "error",
                    "phone_number": phone_number,
                    "normalized_phone": normalized_phone,
                    "message": f"Unexpected response: {response.status_code}",
                    "data": response.text,
                    "raw_status_code": response.status_code,
                    "from_cache": False
                }
                
        except requests.exceptions.Timeout:
            return {
                "status": "error",
                "phone_number": phone_number,
                "normalized_phone": normalized_phone,
                "message": "Request timed out",
                "data": None,
                "raw_status_code": None,
                "from_cache": False
            }
        except requests.exceptions.ConnectionError:
            return {
                "status": "error",
                "phone_number": phone_number,
                "normalized_phone": normalized_phone,
                "message": "Connection error",
                "data": None,
                "raw_status_code": None,
                "from_cache": False
            }
        except json.JSONDecodeError:
            return {
                "status": "error",
                "phone_number": phone_number,
                "normalized_phone": normalized_phone,
                "message": "Invalid JSON in response",
                "data": None,
                "raw_status_code": None,
                "from_cache": False
            }
        except Exception as e:
            return {
                "status": "error",
                "phone_number": phone_number,
                "normalized_phone": normalized_phone,
                "message": f"Error: {str(e)}",
                "data": None,
                "raw_status_code": None,
                "from_cache": False
            }

    def check_single_number_api(self, phone_number: str) -> Dict[str, Any]:
        """
        API function to check a single phone number with token refresh support
        
        Args:
            phone_number (str): Phone number to check
            
        Returns:
            dict: Result in simplified format for API response
        """
        result = self.check_phone_number(phone_number)
        
        # Create a simplified version for API response
        api_result = {
            "phone_number": phone_number,
            "normalized_phone": result.get("normalized_phone", phone_number),
            "is_registered": result["status"] == "registered",
            "status": result["status"],
            "message": result["message"],
            "from_cache": result.get("from_cache", False)
        }
        
        if result["status"] == "registered" and "data" in result and "data" in result["data"]:
            if "referred_by_name" in result["data"]["data"]:
                api_result["referred_by"] = result["data"]["data"]["referred_by_name"]
            if "referred_by_hash" in result["data"]["data"]:
                api_result["referred_by_hash"] = result["data"]["data"]["referred_by_hash"]
        
        return api_result

class BatchProcessor:
    """Process phone numbers in batch with parallel execution"""
    
    def __init__(self, api_client: APIClient, output_dir: str = "results", max_workers: int = 5):
        """
        Initialize the batch processor
        
        Args:
            api_client (APIClient): API client for checking numbers
            output_dir (str): Directory to store results
            max_workers (int): Maximum number of parallel workers
        """
        self.api_client = api_client
        self.output_dir = Path(output_dir)
        self.max_workers = max_workers
        self.result_queue = queue.Queue()
        self.writer_thread = None
        self.stop_event = threading.Event()
        
        # Create output directory
        if not self.output_dir.exists():
            self.output_dir.mkdir(parents=True)
    
    def _writer_worker(self, file_handlers: Dict[str, Any], total_numbers: int) -> None:
        """
        Worker thread to write results to files
        
        Args:
            file_handlers (Dict[str, Any]): Dictionary of file handlers
            total_numbers (int): Total number of phone numbers to process
        """
        processed_count = 0
        progress_bar = tqdm(total=total_numbers, desc="Processing numbers")
        
        while not self.stop_event.is_set() or not self.result_queue.empty():
            try:
                result = self.result_queue.get(timeout=0.5)
                self._write_result_to_files(result, file_handlers)
                processed_count += 1
                progress_bar.update(1)
                self.result_queue.task_done()
            except queue.Empty:
                pass
        
        progress_bar.close()
        logger.info(f"Processed {processed_count} phone numbers")
    
    def _write_result_to_files(self, result: Dict[str, Any], file_handlers: Dict[str, Any]) -> None:
        """
        Write a result to the appropriate files
        
        Args:
            result (Dict[str, Any]): Result from API check
            file_handlers (Dict[str, Any]): Dictionary of file handlers
        """
        # All results CSV
        file_handlers["all_writer"].writerow([
            result["phone_number"],
            result.get("normalized_phone", ""),
            result["status"],
            result["message"],
            result.get("raw_status_code", ""),
            json.dumps(result.get("data", "")) if result.get("data") else ""
        ])
        
        # Specific result files
        if result["status"] == "registered":
            referred_by_name = "N/A"
            referred_by_hash = "N/A"
            
            if "data" in result and result["data"] and "data" in result["data"]:
                if "referred_by_name" in result["data"]["data"]:
                    referred_by_name = result["data"]["data"]["referred_by_name"]
                if "referred_by_hash" in result["data"]["data"]:
                    referred_by_hash = result["data"]["data"]["referred_by_hash"]
                    
            file_handlers["registered_writer"].writerow([
                result["phone_number"], 
                result.get("normalized_phone", ""),
                referred_by_name, 
                referred_by_hash
            ])
            
        elif result["status"] == "not_registered":
            file_handlers["not_registered_writer"].writerow([
                result["phone_number"],
                result.get("normalized_phone", "")
            ])
            
        elif result["status"] == "invalid_number":
            file_handlers["invalid_writer"].writerow([
                result["phone_number"],
                result.get("normalized_phone", ""),
                result["message"]
            ])
            
        else:  # Errors
            file_handlers["error_writer"].writerow([
                result["phone_number"],
                result.get("normalized_phone", ""),
                result["message"]
            ])
    
    def process_phone_numbers(self, phone_numbers: List[str], checkpoint_interval: int = 100) -> Dict[str, str]:
        """
        Process a list of phone numbers with parallel execution
        
        Args:
            phone_numbers (List[str]): List of phone numbers to check
            checkpoint_interval (int): How often to save progress
            
        Returns:
            Dict[str, str]: Dictionary of output file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Prepare output files
        all_results_file = self.output_dir / f"all_results_{timestamp}.csv"
        registered_file = self.output_dir / f"registered_{timestamp}.csv"
        not_registered_file = self.output_dir / f"not_registered_{timestamp}.csv"
        invalid_file = self.output_dir / f"invalid_{timestamp}.csv"
        error_file = self.output_dir / f"errors_{timestamp}.csv"
        progress_file = self.output_dir / f"progress_{timestamp}.txt"
        summary_file = self.output_dir / f"summary_{timestamp}.txt"
        
        # Open all file handlers at once
        all_results_f = open(all_results_file, 'w', newline='', encoding='utf-8')
        registered_f = open(registered_file, 'w', newline='', encoding='utf-8')
        not_registered_f = open(not_registered_file, 'w', newline='', encoding='utf-8')
        invalid_f = open(invalid_file, 'w', newline='', encoding='utf-8')
        error_f = open(error_file, 'w', newline='', encoding='utf-8')
        
        # Create CSV writers
        all_writer = csv.writer(all_results_f)
        registered_writer = csv.writer(registered_f)
        not_registered_writer = csv.writer(not_registered_f)
        invalid_writer = csv.writer(invalid_f)
        error_writer = csv.writer(error_f)
        
        # Write headers
        all_writer.writerow(["Phone Number", "Normalized Number", "Status", "Message", "Raw Status Code", "Response Data"])
        registered_writer.writerow(["Phone Number", "Normalized Number", "Referred By Name", "Referred By Hash"])
        not_registered_writer.writerow(["Phone Number", "Normalized Number"])
        invalid_writer.writerow(["Phone Number", "Normalized Number", "Error Message"])
        error_writer.writerow(["Phone Number", "Normalized Number", "Error Message"])
        
        # Collect file handlers
        file_handlers = {
            "all_writer": all_writer,
            "registered_writer": registered_writer,
            "not_registered_writer": not_registered_writer,
            "invalid_writer": invalid_writer,
            "error_writer": error_writer,
            "all_file": all_results_f,
            "registered_file": registered_f,
            "not_registered_file": not_registered_f,
            "invalid_file": invalid_f,
            "error_file": error_f
        }
        
        # Start the writer thread
        self.stop_event.clear()
        self.writer_thread = threading.Thread(
            target=self._writer_worker,
            args=(file_handlers, len(phone_numbers))
        )
        self.writer_thread.daemon = True
        self.writer_thread.start()
        
        # Process phone numbers in parallel
        stats = {"registered": 0, "not_registered": 0, "invalid": 0, "error": 0, "total": len(phone_numbers)}
        processed_count = 0
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                future_to_phone = {
                    executor.submit(self.api_client.check_phone_number, phone): phone
                    for phone in phone_numbers
                }
                
                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_phone):
                    phone = future_to_phone[future]
                    try:
                        result = future.result()
                        self.result_queue.put(result)
                        
                        # Update statistics
                        stats[result["status"] if result["status"] in stats else "error"] += 1
                        
                        processed_count += 1
                        
                        # Save checkpoint
                        if processed_count % checkpoint_interval == 0:
                            with open(progress_file, 'w') as f:
                                f.write(str(processed_count))
                            logger.info(f"Checkpoint saved at {processed_count}/{len(phone_numbers)}")
                    
                    except Exception as e:
                        logger.error(f"Error processing {phone}: {str(e)}")
                        self.result_queue.put({
                            "status": "error",
                            "phone_number": phone,
                            "message": f"Processing error: {str(e)}",
                            "data": None,
                            "raw_status_code": None
                        })
                        stats["error"] += 1
        
        finally:
            # Signal writer thread to finish and wait for queue to empty
            self.stop_event.set()
            self.writer_thread.join()
            
            # Close all files
            for key, handler in file_handlers.items():
                if key.endswith('_file'):
                    handler.close()
            
            # Create summary file
            with open(summary_file, 'w') as f:
                f.write(f"Processing Summary\n")
                f.write(f"=================\n\n")
                f.write(f"Started: {timestamp}\n")
                f.write(f"Completed: {datetime.now().strftime('%Y%m%d_%H%M%S')}\n\n")
                f.write(f"Total numbers processed: {stats['total']}\n")
                f.write(f"  - Registered: {stats['registered']} ({stats['registered']/stats['total']*100:.1f}%)\n")
                f.write(f"  - Not registered: {stats['not_registered']} ({stats['not_registered']/stats['total']*100:.1f}%)\n")
                f.write(f"  - Invalid numbers: {stats['invalid']} ({stats['invalid']/stats['total']*100:.1f}%)\n")
                f.write(f"  - Errors: {stats['error']} ({stats['error']/stats['total']*100:.1f}%)\n")
        
        return {
            "all_results": str(all_results_file),
            "registered": str(registered_file),
            "not_registered": str(not_registered_file),
            "invalid": str(invalid_file),
            "errors": str(error_file),
            "summary": str(summary_file)
        }

class WebServer:
    """Web server to check phone numbers"""
    
    def __init__(self, api_client: APIClient, host: str = '0.0.0.0', port: int = 5000):
        """
        Initialize the web server
        
        Args:
            api_client (APIClient): API client for checking numbers
            host (str): Host to bind the server to
            port (int): Port to bind the server to
        """
        self.api_client = api_client
        self.host = host
        self.port = port
        self.app = None
    
    def setup_flask_server(self):
        """Set up a Flask server to check phone numbers"""
        try:
            from flask import Flask, request, jsonify, render_template_string, Response
            import flask
            
            app = Flask(__name__)
            self.app = app
            
            # Security headers middleware
            @app.after_request
            def add_security_headers(response):
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
                return response
            
            @app.route('/check', methods=['POST'])
            def check_number_api():
                try:
                    data = request.get_json()
                    
                    if not data or 'phone_number' not in data:
                        return jsonify({"error": "Missing phone_number parameter"}), 400
                        
                    phone_number = data['phone_number']
                    result = self.api_client.check_single_number_api(phone_number)
                    
                    return jsonify(result)
                except Exception as e:
                    logger.error(f"API error: {str(e)}")
                    return jsonify({"error": str(e)}), 500
                
            @app.route('/check/<phone_number>', methods=['GET'])
            def check_number_get(phone_number):
                try:
                    result = self.api_client.check_single_number_api(phone_number)
                    return jsonify(result)
                except Exception as e:
                    logger.error(f"API error: {str(e)}")
                    return jsonify({"error": str(e)}), 500
                
            @app.route('/healthz', methods=['GET'])
            def health_check():
                """Health check endpoint for monitoring"""
                return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})
                
            @app.route('/stats', methods=['GET'])
            def stats():
                """Get API client statistics"""
                return jsonify({
                    "request_count": self.api_client.request_count,
                    "cache_size": len(self.api_client.results_cache),
                    "cache_hits": sum(1 for r in self.api_client.results_cache.values() if r.get("from_cache", False))
                })
                
            @app.route('/bulk', methods=['POST'])
            def bulk_check():
                """Bulk check endpoint for multiple numbers"""
                try:
                    data = request.get_json()
                    
                    if not data or 'phone_numbers' not in data:
                        return jsonify({"error": "Missing phone_numbers parameter"}), 400
                        
                    phone_numbers = data['phone_numbers']
                    if not isinstance(phone_numbers, list):
                        return jsonify({"error": "phone_numbers must be a list"}), 400
                        
                    if len(phone_numbers) > 100:
                        return jsonify({"error": "Maximum 100 numbers allowed per request"}), 400
                    
                    results = []
                    for phone in phone_numbers:
                        result = self.api_client.check_single_number_api(phone)
                        results.append(result)
                        
                    return jsonify({"results": results})
                except Exception as e:
                    logger.error(f"Bulk API error: {str(e)}")
                    return jsonify({"error": str(e)}), 500
                
            @app.route('/', methods=['GET'])
            def home():
                token_preview = {
                    "access_token": f"{self.api_client.token_manager.access_token[:8]}...{self.api_client.token_manager.access_token[-8:]}",
                    "refresh_token": f"{self.api_client.token_manager.refresh_token[:8]}...{self.api_client.token_manager.refresh_token[-8:]}",
                    "request_count": self.api_client.request_count,
                    "cache_size": len(self.api_client.results_cache)
                }
                
                return render_template_string("""
                <!DOCTYPE html>
                <html>
                    <head>
                        <title>BJP Phone Number Registration Checker</title>
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <style>
                            :root {
                                --primary-color: #F97432;
                                --secondary-color: #F55A1D;
                                --text-color: #333;
                                --light-bg: #f8f9fa;
                                --border-color: #dee2e6;
                            }
                            
                            body { 
                                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                                margin: 0;
                                padding: 0;
                                color: var(--text-color);
                                background-color: var(--light-bg);
                            }
                            
                            .container { 
                                max-width: 800px; 
                                margin: 0 auto;
                                padding: 20px;
                            }
                            
                            header {
                                background-color: var(--primary-color);
                                color: white;
                                padding: 1rem;
                                text-align: center;
                                border-radius: 5px;
                                margin-bottom: 20px;
                            }
                            
                            .card {
                                background: white;
                                border-radius: 8px;
                                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                                padding: 20px;
                                margin-bottom: 20px;
                            }
                            
                            h1 {
                                color: white;
                                margin: 0;
                            }
                            
                            h2 {
                                color: var(--primary-color);
                                border-bottom: 2px solid var(--primary-color);
                                padding-bottom: 5px;
                                margin-top: 0;
                            }
                            
                            input, button, select { 
                                padding: 12px; 
                                font-size: 16px; 
                                border-radius: 4px;
                                border: 1px solid var(--border-color);
                            }
                            
                            input {
                                width: 100%;
                                box-sizing: border-box;
                                margin-bottom: 10px;
                            }
                            
                            button {
                                background-color: var(--primary-color);
                                color: white;
                                border: none;
                                cursor: pointer;
                                transition: background-color 0.3s;
                                width: 100%;
                            }
                            
                            button:hover {
                                background-color: var(--secondary-color);
                            }
                            
                            #result, #bulkResult { 
                                margin-top: 20px; 
                                padding: 15px; 
                                border-radius: 5px;
                                display: none;
                            }
                            
                            .result-card {
                                background: white;
                                border-left: 4px solid #ccc;
                                padding: 10px 15px;
                                margin-bottom: 10px;
                                border-radius: 4px;
                            }
                            
                            .registered { 
                                border-left-color: #28a745;
                            }
                            
                            .not-registered { 
                                border-left-color: #dc3545;
                            }
                            
                            .error, .invalid { 
                                border-left-color: #ffc107;
                            }
                            
                            .token-status { 
                                font-size: 12px; 
                                color: #666; 
                                background-color: #f8f9fa;
                                padding: 10px;
                                border-radius: 4px;
                                margin-top: 20px;
                            }
                            
                            .refresh-btn {
                                background-color: #6c757d;
                                color: white;
                                padding: 8px 16px;
                                border: none;
                                border-radius: 4px;
                                cursor: pointer;
                                margin-top: 10px;
                                font-size: 14px;
                                transition: background-color 0.3s;
                            }
                            
                            .refresh-btn:hover {
                                background-color: #5a6268;
                            }
                            
                            .refresh-btn:disabled {
                                background-color: #adb5bd;
                                cursor: not-allowed;
                            }
                            
                            #refreshStatus {
                                margin-top: 8px;
                                font-size: 14px;
                                min-height: 20px;
                            }
                            
                            .tabs {
                                display: flex;
                                margin-bottom: 20px;
                            }
                            
                            .tab {
                                padding: 10px 20px;
                                background-color: #e9ecef;
                                cursor: pointer;
                                border-radius: 5px 5px 0 0;
                                margin-right: 5px;
                            }
                            
                            .tab.active {
                                background-color: white;
                                font-weight: bold;
                                border-bottom: 2px solid var(--primary-color);
                            }
                            
                            .tab-content {
                                display: none;
                            }
                            
                            .tab-content.active {
                                display: block;
                            }
                            
                            .spinner {
                                border: 4px solid rgba(0, 0, 0, 0.1);
                                width: 24px;
                                height: 24px;
                                border-radius: 50%;
                                border-left-color: var(--primary-color);
                                animation: spin 1s linear infinite;
                                margin: 10px auto;
                                display: none;
                            }
                            
                            @keyframes spin {
                                0% { transform: rotate(0deg); }
                                100% { transform: rotate(360deg); }
                            }
                            
                            #bulkNumbers {
                                width: 100%;
                                height: 150px;
                                font-family: monospace;
                                padding: 10px;
                                resize: vertical;
                            }
                            
                            .footer {
                                text-align: center;
                                padding: 10px;
                                font-size: 12px;
                                color: #666;
                                margin-top: 40px;
                            }
                            
                            table {
                                width: 100%;
                                border-collapse: collapse;
                                margin-top: 10px;
                            }
                            
                            table th, table td {
                                padding: 8px;
                                text-align: left;
                                border-bottom: 1px solid #ddd;
                            }
                            
                            table th {
                                background-color: #f2f2f2;
                            }
                            
                            .api-section {
                                margin-top: 30px;
                                border-top: 1px solid #ddd;
                                padding-top: 20px;
                            }
                            
                            .api-example {
                                background-color: #f5f5f5;
                                padding: 10px;
                                border-radius: 4px;
                                font-family: monospace;
                                overflow-x: auto;
                            }
                            
                            @media (max-width: 600px) {
                                input, button {
                                    width: 100%;
                                    margin-bottom: 10px;
                                }
                                
                                .tabs {
                                    flex-direction: column;
                                }
                                
                                .tab {
                                    margin-bottom: 5px;
                                    border-radius: 5px;
                                }
                            }
                        </style>
                    </head>
                    <body>
                        <header>
                            <h1>BJP Phone Number Registration Checker</h1>
                        </header>
                        
                        <div class="container">
                            <div class="tabs">
                                <div class="tab active" onclick="switchTab('single')">Single Check</div>
                                <div class="tab" onclick="switchTab('bulk')">Bulk Check</div>
                                <div class="tab" onclick="switchTab('api')">API Guide</div>
                            </div>
                            
                            <div id="singleTab" class="tab-content active">
                                <div class="card">
                                    <h2>Check Single Number</h2>
                                    <input type="text" id="phoneNumber" placeholder="Enter phone number (e.g. 9876543210)" />
                                    <button onclick="checkNumber()">Check Number</button>
                                    <div id="spinner" class="spinner"></div>
                                    <div id="result"></div>
                                </div>
                            </div>
                            
                            <div id="bulkTab" class="tab-content">
                                <div class="card">
                                    <h2>Bulk Check</h2>
                                    <p>Enter up to 100 phone numbers (one per line)</p>
                                    <textarea id="bulkNumbers" placeholder="Enter phone numbers, one per line&#10;e.g.&#10;9876543210&#10;9876543211&#10;9876543212"></textarea>
                                    <button onclick="bulkCheck()">Check All Numbers</button>
                                    <div id="bulkSpinner" class="spinner"></div>
                                    <div id="bulkResult"></div>
                                </div>
                            </div>
                            
                            <div id="apiTab" class="tab-content">
                                <div class="card">
                                    <h2>API Documentation</h2>
                                    
                                    <h3>Endpoints</h3>
                                    <table>
                                        <tr>
                                            <th>Endpoint</th>
                                            <th>Method</th>
                                            <th>Description</th>
                                        </tr>
                                        <tr>
                                            <td>/check/{phone_number}</td>
                                            <td>GET</td>
                                            <td>Check a single phone number</td>
                                        </tr>
                                        <tr>
                                            <td>/check</td>
                                            <td>POST</td>
                                            <td>Check a single phone number (JSON body)</td>
                                        </tr>
                                        <tr>
                                            <td>/bulk</td>
                                            <td>POST</td>
                                            <td>Check multiple phone numbers (max 100)</td>
                                        </tr>
                                        <tr>
                                            <td>/stats</td>
                                            <td>GET</td>
                                            <td>Get API statistics</td>
                                        </tr>
                                        <tr>
                                            <td>/healthz</td>
                                            <td>GET</td>
                                            <td>Health check endpoint</td>
                                        </tr>
                                    </table>
                                    
                                    <h3>Example Request</h3>
                                    <div class="api-example">
                                        POST /bulk<br>
                                        Content-Type: application/json<br><br>
                                        {<br>
                                        &nbsp;&nbsp;"phone_numbers": ["9876543210", "9876543211"]<br>
                                        }
                                    </div>
                                    
                                    <h3>Example Response</h3>
                                    <div class="api-example">
                                        {<br>
                                        &nbsp;&nbsp;"results": [<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;{<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"is_registered": true,<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"message": "Number is registered",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"normalized_phone": "9876543210",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"phone_number": "9876543210",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"referred_by": "John Doe",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"status": "registered"<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;},<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;{<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"is_registered": false,<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"message": "Number is not registered",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"normalized_phone": "9876543211",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"phone_number": "9876543211",<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"status": "not_registered"<br>
                                        &nbsp;&nbsp;&nbsp;&nbsp;}<br>
                                        &nbsp;&nbsp;]<br>
                                        }
                                    </div>
                                </div>
                            </div>
                            
                            <div class="token-status">
                                <h3>System Status</h3>
                                <p>Access token: {{ token.access_token }}</p>
                                <p>Refresh token: {{ token.refresh_token }}</p>
                                <p>Requests processed: {{ token.request_count }}</p>
                                <p>Cache size: {{ token.cache_size }}</p>
                                <p><small>Note: Tokens are automatically refreshed when expired</small></p>
                                <button id="refreshTokenBtn" class="refresh-btn">Manually Refresh Token</button>
                                <div id="refreshStatus"></div>
                            </div>
                        </div>
                        
                        <div class="footer">
                            BJP Phone Number Registration Checker | Version 2.0
                        </div>
                        
                        <script>
                            // Token refresh functionality
                            document.addEventListener('DOMContentLoaded', function() {
                                const refreshBtn = document.getElementById('refreshTokenBtn');
                                if (refreshBtn) {
                                    refreshBtn.addEventListener('click', function() {
                                        const statusDiv = document.getElementById('refreshStatus');
                                        
                                        refreshBtn.disabled = true;
                                        refreshBtn.textContent = 'Refreshing...';
                                        statusDiv.innerHTML = '';
                                        
                                        fetch('/refresh-token', {
                                            method: 'POST',
                                        })
                                        .then(response => response.json())
                                        .then(data => {
                                            refreshBtn.disabled = false;
                                            refreshBtn.textContent = 'Manually Refresh Token';
                                            
                                            if (data.success) {
                                                statusDiv.innerHTML = `<span style="color: green">✓ ${data.message}</span>`;
                                                // Reload the page after a short delay to show updated tokens
                                                setTimeout(() => location.reload(), 1500);
                                            } else {
                                                statusDiv.innerHTML = `<span style="color: red">✗ ${data.message}</span>`;
                                            }
                                        })
                                        .catch(error => {
                                            refreshBtn.disabled = false;
                                            refreshBtn.textContent = 'Manually Refresh Token';
                                            statusDiv.innerHTML = `<span style="color: red">✗ Error: ${error.message}</span>`;
                                        });
                                    });
                                }
                            });
                            
                            function switchTab(tabName) {
                                // Hide all tabs
                                document.querySelectorAll('.tab-content').forEach(tab => {
                                    tab.classList.remove('active');
                                });
                                
                                // Deactivate all tab buttons
                                document.querySelectorAll('.tab').forEach(button => {
                                    button.classList.remove('active');
                                });
                                
                                // Show selected tab
                                document.getElementById(tabName + 'Tab').classList.add('active');
                                
                                // Activate selected tab button
                                document.querySelectorAll('.tab').forEach(button => {
                                    if (button.textContent.toLowerCase().includes(tabName)) {
                                        button.classList.add('active');
                                    }
                                });
                            }
                            
                            function checkNumber() {
                                const phoneNumber = document.getElementById('phoneNumber').value;
                                const resultDiv = document.getElementById('result');
                                const spinner = document.getElementById('spinner');
                                
                                if (!phoneNumber) {
                                    alert('Please enter a phone number');
                                    return;
                                }
                                
                                resultDiv.style.display = 'none';
                                spinner.style.display = 'block';
                                
                                fetch('/check/' + encodeURIComponent(phoneNumber))
                                    .then(response => response.json())
                                    .then(data => {
                                        spinner.style.display = 'none';
                                        resultDiv.style.display = 'block';
                                        
                                        let resultClass = '';
                                        if (data.is_registered) {
                                            resultClass = 'registered';
                                        } else if (data.status === "not_registered") {
                                            resultClass = 'not-registered';
                                        } else if (data.status === "invalid_number") {
                                            resultClass = 'invalid';
                                        } else {
                                            resultClass = 'error';
                                        }
                                        
                                        let resultHtml = `<div class="result-card ${resultClass}">`;
                                        resultHtml += `<p><strong>Phone Number:</strong> ${data.phone_number}</p>`;
                                        
                                        if (data.normalized_phone !== data.phone_number) {
                                            resultHtml += `<p><strong>Normalized Number:</strong> ${data.normalized_phone}</p>`;
                                        }
                                        
                                        if (data.is_registered) {
                                            resultHtml += `<p><strong>Status:</strong> <span style="color:#28a745">REGISTERED ✅</span></p>`;
                                            if (data.referred_by) {
                                                resultHtml += `<p><strong>Referred By:</strong> ${data.referred_by}</p>`;
                                            }
                                            if (data.referred_by_hash) {
                                                resultHtml += `<p><strong>Referral Hash:</strong> ${data.referred_by_hash}</p>`;
                                            }
                                        } else if (data.status === "token_expired") {
                                            resultHtml += `<p><strong>Status:</strong> <span style="color:#dc3545">ERROR ❌</span></p>`;
                                            resultHtml += `<p><strong>Message:</strong> Token expired and refresh failed.</p>`;
                                        } else if (data.status === "invalid_number") {
                                            resultHtml += `<p><strong>Status:</strong> <span style="color:#ffc107">INVALID NUMBER ⚠️</span></p>`;
                                            resultHtml += `<p><strong>Message:</strong> ${data.message}</p>`;
                                        } else {
                                            resultHtml += `<p><strong>Status:</strong> <span style="color:#dc3545">NOT REGISTERED ❌</span></p>`;
                                        }
                                        
                                        if (data.from_cache) {
                                            resultHtml += `<p><small>(Result from cache)</small></p>`;
                                        }
                                        
                                        resultHtml += `</div>`;
                                        resultDiv.innerHTML = resultHtml;
                                    })
                                    .catch(error => {
                                        spinner.style.display = 'none';
                                        resultDiv.style.display = 'block';
                                        resultDiv.innerHTML = `<div class="result-card error"><p><strong>Error:</strong> ${error.message}</p></div>`;
                                    });
                            }
                            
                            function bulkCheck() {
                                const phonesText = document.getElementById('bulkNumbers').value;
                                const resultDiv = document.getElementById('bulkResult');
                                const spinner = document.getElementById('bulkSpinner');
                                
                                if (!phonesText.trim()) {
                                    alert('Please enter at least one phone number');
                                    return;
                                }
                                
                                // Parse phone numbers (one per line)
                                const phoneNumbers = phonesText.split(/\\n/).map(p => p.trim()).filter(p => p);
                                
                                if (phoneNumbers.length === 0) {
                                    alert('No valid phone numbers found');
                                    return;
                                }
                                
                                if (phoneNumbers.length > 100) {
                                    alert('Maximum 100 phone numbers allowed at once');
                                    return;
                                }
                                
                                resultDiv.style.display = 'none';
                                spinner.style.display = 'block';
                                
                                fetch('/bulk', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({ phone_numbers: phoneNumbers }),
                                })
                                    .then(response => response.json())
                                    .then(data => {
                                        spinner.style.display = 'none';
                                        resultDiv.style.display = 'block';
                                        
                                        let resultHtml = '<h3>Bulk Check Results</h3>';
                                        const results = data.results || [];
                                        
                                        let registered = 0;
                                        let notRegistered = 0;
                                        let invalid = 0;
                                        let errors = 0;
                                        
                                        // Count statistics
                                        results.forEach(result => {
                                            if (result.is_registered) registered++;
                                            else if (result.status === 'not_registered') notRegistered++;
                                            else if (result.status === 'invalid_number') invalid++;
                                            else errors++;
                                        });
                                        
                                        // Add summary
                                        resultHtml += `
                                        <div class="summary" style="margin-bottom: 15px; padding: 10px; background-color: #f5f5f5; border-radius: 4px;">
                                            <p><strong>Total:</strong> ${results.length} numbers</p>
                                            <p><strong>Registered:</strong> ${registered} (${Math.round(registered/results.length*100) || 0}%)</p>
                                            <p><strong>Not Registered:</strong> ${notRegistered} (${Math.round(notRegistered/results.length*100) || 0}%)</p>
                                            <p><strong>Invalid:</strong> ${invalid} (${Math.round(invalid/results.length*100) || 0}%)</p>
                                            <p><strong>Errors:</strong> ${errors} (${Math.round(errors/results.length*100) || 0}%)</p>
                                        </div>`;
                                        
                                        // Add individual results
                                        results.forEach(result => {
                                            let resultClass = '';
                                            if (result.is_registered) {
                                                resultClass = 'registered';
                                            } else if (result.status === "not_registered") {
                                                resultClass = 'not-registered';
                                            } else if (result.status === "invalid_number") {
                                                resultClass = 'invalid';
                                            } else {
                                                resultClass = 'error';
                                            }
                                            
                                            resultHtml += `<div class="result-card ${resultClass}">`;
                                            resultHtml += `<p><strong>Phone:</strong> ${result.phone_number}`;
                                            
                                            if (result.is_registered) {
                                                resultHtml += ` <span style="color:#28a745">✅</span>`;
                                                if (result.referred_by) {
                                                    resultHtml += ` <small>(Referred by: ${result.referred_by})</small>`;
                                                }
                                            } else if (result.status === "invalid_number") {
                                                resultHtml += ` <span style="color:#ffc107">⚠️ Invalid</span>`;
                                            } else if (result.status === "error") {
                                                resultHtml += ` <span style="color:#dc3545">❌ Error: ${result.message}</span>`;
                                            } else {
                                                resultHtml += ` <span style="color:#dc3545">❌</span>`;
                                            }
                                            
                                            resultHtml += `</p>`;
                                            resultHtml += `</div>`;
                                        });
                                        
                                        resultDiv.innerHTML = resultHtml;
                                    })
                                    .catch(error => {
                                        spinner.style.display = 'none';
                                        resultDiv.style.display = 'block';
                                        resultDiv.innerHTML = `<div class="result-card error"><p><strong>Error:</strong> ${error.message}</p></div>`;
                                    });
                            }
                            
                            // Event listener for enter key on phone number input
                            document.getElementById('phoneNumber').addEventListener('keypress', function(event) {
                                if (event.key === 'Enter') {
                                    event.preventDefault();
                                    checkNumber();
                                }
                            });
                        </script>
                    </body>
                </html>
                """, token=token_preview)
            
            # Start the server
            logger.info(f"Server started at http://{self.host}:{self.port}")
            logger.info(f"API endpoints:")
            logger.info(f"  - GET /check/<phone_number>")
            logger.info(f"  - POST /check (with JSON body: {{\"phone_number\": \"1234567890\"}})")
            logger.info(f"  - POST /bulk (with JSON body: {{\"phone_numbers\": [\"1234567890\", \"0987654321\"]}})")
            logger.info(f"  - GET /stats (system statistics)")
            logger.info(f"  - GET /healthz (health check)")
            
            return app
            
        except ImportError:
            logger.error("Error: Flask is required for the server mode.")
            logger.error("Please install it with: pip install flask")
            return None
    
    def run(self):
        """Run the web server"""
        app = self.setup_flask_server()
        if app:
            app.run(host=self.host, port=self.port)
        else:
            logger.error("Failed to setup Flask server")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='BJP Phone Number Registration Checker')
    
    # Token options
    token_group = parser.add_argument_group('Token Options')
    token_group.add_argument('--access-token', help='Access token for API')
    token_group.add_argument('--refresh-token', help='Refresh token for API')
    token_group.add_argument('--url', help='URL containing tokens')
    token_group.add_argument('--env', action='store_true', help='Use tokens from environment variables')
    
    # Mode options
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Single mode
    single_parser = subparsers.add_parser('single', help='Check a single phone number')
    single_parser.add_argument('phone', help='Phone number to check')
    
    # File mode
    file_parser = subparsers.add_parser('file', help='Check numbers from a file')
    file_parser.add_argument('input_file', help='Path to file with phone numbers (one per line)')
    file_parser.add_argument('--output-dir', default='results', help='Directory to store results')
    file_parser.add_argument('--workers', type=int, default=5, help='Number of parallel workers')
    file_parser.add_argument('--checkpoint', type=int, default=100, help='Checkpoint interval')
    
    # Resume mode
    resume_parser = subparsers.add_parser('resume', help='Resume processing from a checkpoint')
    resume_parser.add_argument('input_file', help='Original input file path')
    resume_parser.add_argument('checkpoint_file', help='Checkpoint file path')
    resume_parser.add_argument('--output-dir', default='results', help='Directory to store results')
    resume_parser.add_argument('--workers', type=int, default=5, help='Number of parallel workers')
    
    # Server mode
    server_parser = subparsers.add_parser('server', help='Run as a web server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind the server to')
    server_parser.add_argument('--port', type=int, default=5000, help='Port to bind the server to')
    
    # Interactive mode (default)
    interactive_parser = subparsers.add_parser('interactive', help='Run in interactive mode')
    
    return parser.parse_args()

def interactive_mode():
    """Run the script in interactive mode"""
    logger.info("\n" + "=" * 60)
    logger.info("BJP Phone Number Registration Checker")
    logger.info("=" * 60)
    
    logger.info("\nToken input options:")
    logger.info("1. Enter access and refresh tokens separately")
    logger.info("2. Paste the full redirect URL containing tokens")
    logger.info("3. Use tokens from environment variables")
    token_input_mode = input("Choose option (1-3): ").strip()
    
    token_manager = None
    
    if token_input_mode == "1":
        access_token = input("\nEnter your access token: ").strip()
        # Remove 'Bearer ' prefix if present
        if access_token.startswith("Bearer "):
            access_token = access_token[7:]
            
        refresh_token = input("Enter your refresh token: ").strip()
        
        if not access_token:
            logger.error("Error: Access token is required")
            return
            
        token_manager = TokenManager(access_token, refresh_token)
        
    elif token_input_mode == "2":
        redirect_url = input("\nPaste the full redirect URL containing tokens: ").strip()
        
        token_manager = TokenManager.from_redirect_url(redirect_url)
        
        if not token_manager:
            logger.error("Failed to extract tokens from URL. Please try again with option 1.")
            return
    elif token_input_mode == "3":
        token_manager = TokenManager.from_env()
        
        if not token_manager:
            logger.error("No tokens found in environment variables. Please set BJP_ACCESS_TOKEN and BJP_REFRESH_TOKEN.")
            return
    else:
        logger.error("Invalid option. Please run the script again.")
        return
    
    # Create API client
    api_client = APIClient(token_manager)
    
    logger.info("\nSelect mode:")
    logger.info("1. Check a single number")
    logger.info("2. Check numbers from file")
    logger.info("3. Resume from checkpoint")
    logger.info("4. Run as web server")
    mode = input("Enter choice (1-4): ").strip()
    
    if mode == "1":
        phone_number = input("\nEnter the phone number to check: ").strip()
        logger.info(f"Checking {phone_number}...")
        
        result = api_client.check_single_number_api(phone_number)
        
        if result["is_registered"]:
            logger.info(f"✅ {phone_number} is REGISTERED")
            if "referred_by" in result:
                logger.info(f"   Referred by: {result['referred_by']}")
        elif result["status"] == "not_registered":
            logger.info(f"❌ {phone_number} is NOT REGISTERED")
        elif result["status"] == "invalid_number":
            logger.info(f"⚠️ {phone_number} is INVALID")
        else:
            logger.info(f"⚠️ Error checking {phone_number}: {result['message']}")
    
    elif mode == "2":
        input_file = input("Enter the path to your file with phone numbers (one per line): ").strip()
        
        workers = input("Enter number of parallel workers (default is 5): ").strip()
        workers = int(workers) if workers and workers.isdigit() else 5
        
        output_dir = input("Enter output directory (default is 'results'): ").strip()
        output_dir = output_dir if output_dir else "results"
        
        checkpoint_interval = input("Enter checkpoint interval (default is 100): ").strip()
        checkpoint_interval = int(checkpoint_interval) if checkpoint_interval and checkpoint_interval.isdigit() else 100
        
        try:
            with open(input_file, 'r') as f:
                phone_numbers = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error reading input file: {str(e)}")
            return
        
        total_numbers = len(phone_numbers)
        logger.info(f"\nStarting to process {total_numbers} numbers from {input_file}")
        logger.info(f"Using {workers} parallel workers")
        logger.info(f"Output directory: {output_dir}")
        logger.info(f"Checkpoint interval: {checkpoint_interval}")
        
        confirm = input("\nPress Enter to start or Ctrl+C to cancel...")
        
        processor = BatchProcessor(api_client, output_dir, workers)
        output_files = processor.process_phone_numbers(phone_numbers, checkpoint_interval)
        
        logger.info("\nProcessing complete!")
        logger.info(f"Results saved to:")
        for key, path in output_files.items():
            logger.info(f"- {key}: {path}")
        
    elif mode == "3":
        input_file = input("Enter the original input file path: ").strip()
        checkpoint_file = input("Enter the checkpoint file path: ").strip()
        
        workers = input("Enter number of parallel workers (default is 5): ").strip()
        workers = int(workers) if workers and workers.isdigit() else 5
        
        output_dir = input("Enter output directory (default is 'results'): ").strip()
        output_dir = output_dir if output_dir else "results"
        
        try:
            with open(checkpoint_file, 'r') as f:
                last_index = int(f.read().strip())
            
            with open(input_file, 'r') as f:
                phone_numbers = [line.strip() for line in f if line.strip()]
            
            if last_index >= len(phone_numbers) - 1:
                logger.info("All numbers have already been processed.")
                return
            
            remaining_numbers = phone_numbers[last_index+1:]
            
            logger.info(f"\nResuming from index {last_index+1}, {len(remaining_numbers)} numbers remaining")
            logger.info(f"Using {workers} parallel workers")
            logger.info(f"Output directory: {output_dir}")
            
            confirm = input("\nPress Enter to resume or Ctrl+C to cancel...")
            
            processor = BatchProcessor(api_client, output_dir, workers)
            output_files = processor.process_phone_numbers(remaining_numbers)
            
            logger.info("\nProcessing complete!")
            logger.info(f"Results saved to:")
            for key, path in output_files.items():
                logger.info(f"- {key}: {path}")
                
        except Exception as e:
            logger.error(f"Error resuming from checkpoint: {str(e)}")
        
    elif mode == "4":
        host = input("Enter host to bind to (default is 0.0.0.0): ").strip()
        host = host if host else "0.0.0.0"
        
        port = input("Enter port to bind to (default is 5000): ").strip()
        port = int(port) if port and port.isdigit() else 5000
        
        logger.info(f"\nStarting web server on {host}:{port}...")
        
        server = WebServer(api_client, host, port)
        server.run()
        
    else:
        logger.error("Invalid choice. Please run the script again.")

def main():
    """Main function to run the script"""
    try:
        args = parse_arguments()
        
        # Initialize token manager
        token_manager = None
        
        if args.access_token and args.refresh_token:
            token_manager = TokenManager(args.access_token, args.refresh_token)
        elif args.url:
            token_manager = TokenManager.from_redirect_url(args.url)
        elif args.env:
            token_manager = TokenManager.from_env()
        
        # If no valid token manager from args, and not in interactive mode, show error
        if not token_manager and args.mode != 'interactive' and args.mode is not None:
            logger.error("No valid tokens provided. Use --access-token and --refresh-token, --url, or --env")
            return
        
        # Run in the selected mode
        if args.mode == 'interactive' or args.mode is None:
            interactive_mode()
        elif args.mode == 'single':
            api_client = APIClient(token_manager)
            result = api_client.check_single_number_api(args.phone)
            
            if result["is_registered"]:
                logger.info(f"✅ {args.phone} is REGISTERED")
                if "referred_by" in result:
                    logger.info(f"   Referred by: {result['referred_by']}")
            elif result["status"] == "not_registered":
                logger.info(f"❌ {args.phone} is NOT REGISTERED")
            elif result["status"] == "invalid_number":
                logger.info(f"⚠️ {args.phone} is INVALID")
            else:
                logger.info(f"⚠️ Error checking {args.phone}: {result['message']}")
        elif args.mode == 'file':
            api_client = APIClient(token_manager)
            
            try:
                with open(args.input_file, 'r') as f:
                    phone_numbers = [line.strip() for line in f if line.strip()]
            except Exception as e:
                logger.error(f"Error reading input file: {str(e)}")
                return
            
            processor = BatchProcessor(api_client, args.output_dir, args.workers)
            output_files = processor.process_phone_numbers(phone_numbers, args.checkpoint)
            
            logger.info("\nProcessing complete!")
            logger.info(f"Results saved to:")
            for key, path in output_files.items():
                logger.info(f"- {key}: {path}")
        elif args.mode == 'resume':
            api_client = APIClient(token_manager)
            
            try:
                with open(args.checkpoint_file, 'r') as f:
                    last_index = int(f.read().strip())
                
                with open(args.input_file, 'r') as f:
                    phone_numbers = [line.strip() for line in f if line.strip()]
                
                if last_index >= len(phone_numbers) - 1:
                    logger.info("All numbers have already been processed.")
                    return
                
                remaining_numbers = phone_numbers[last_index+1:]
                
                logger.info(f"Resuming from index {last_index+1}, {len(remaining_numbers)} numbers remaining")
                
                processor = BatchProcessor(api_client, args.output_dir, args.workers)
                output_files = processor.process_phone_numbers(remaining_numbers)
                
                logger.info("\nProcessing complete!")
                logger.info(f"Results saved to:")
                for key, path in output_files.items():
                    logger.info(f"- {key}: {path}")
                    
            except Exception as e:
                logger.error(f"Error resuming from checkpoint: {str(e)}")
        elif args.mode == 'server':
            api_client = APIClient(token_manager)
            server = WebServer(api_client, args.host, args.port)
            server.run()
    
    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user. Exiting...")
    except Exception as e:
        logger.error(f"\nAn unexpected error occurred: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())

if __name__ == "__main__":
    main()
