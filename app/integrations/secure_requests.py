"""
Secure HTTP Request Utilities

Provides SSL verification with fallback for forensic analysis of potentially
malicious sites with self-signed certificates.
"""

import requests
import logging
import time
import urllib3
from typing import Optional, Dict, Any, Union, Tuple

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default headers for stealthy scanning
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}


def secure_get(url: str,
               headers: Optional[Dict[str, str]] = None,
               timeout: Union[int, Tuple[int, int]] = (5, 10),
               allow_redirects: bool = True,
               enable_ssl_fallback: bool = True,
               **kwargs) -> requests.Response:
    """
    Make a secure GET request with SSL verification.
    
    For forensic analysis of potentially malicious sites, if SSL verification fails
    and enable_ssl_fallback is True, it will retry with verification disabled
    and log a warning.
    
    Args:
        url: The URL to request
        headers: Optional custom headers (merges with defaults)
        timeout: Request timeout in seconds
        allow_redirects: Whether to follow redirects
        enable_ssl_fallback: If True, retry with verify=False on SSL errors
        **kwargs: Additional arguments to pass to requests.get()
        
    Returns:
        Response object
        
    Raises:
        requests.RequestException: If the request fails
    """
    # Merge headers with defaults
    merged_headers = DEFAULT_HEADERS.copy()
    if headers:
        merged_headers.update(headers)
    
    # First try with SSL verification enabled
    try:
        response = requests.get(
            url,
            headers=merged_headers,
            timeout=timeout,
            verify=True,
            allow_redirects=allow_redirects,
            **kwargs
        )
        return response
        
    except requests.exceptions.SSLError as ssl_err:
        if enable_ssl_fallback:
            logging.warning(f"[SECURE_REQUESTS] SSL verification failed for {url}, retrying with verification disabled for forensic analysis")
            try:
                response = requests.get(
                    url,
                    headers=merged_headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=allow_redirects,
                    **kwargs
                )
                # Add a flag to indicate SSL verification was bypassed
                response.ssl_verification_bypassed = True
                return response
            except Exception as e:
                logging.error(f"[SECURE_REQUESTS] Request failed even with SSL verification disabled: {e}")
                raise
        else:
            logging.error(f"[SECURE_REQUESTS] SSL verification failed for {url} and fallback is disabled")
            raise
            
    except requests.exceptions.Timeout as e:
        logging.warning(f"[SECURE_REQUESTS] Timeout for {url}: {e}")
        raise
    except Exception as e:
        logging.warning(f"[SECURE_REQUESTS] Request failed for {url}: {type(e).__name__}")
        raise


def secure_post(url: str,
                data: Optional[Any] = None,
                json_data: Optional[Dict] = None,
                headers: Optional[Dict[str, str]] = None,
                timeout: int = 10,
                enable_ssl_fallback: bool = True,
                **kwargs) -> requests.Response:
    """
    Make a secure POST request with SSL verification.
    
    Similar to secure_get but for POST requests.
    """
    merged_headers = DEFAULT_HEADERS.copy()
    if headers:
        merged_headers.update(headers)
    
    # Remove content-type if data is form-encoded to let requests handle it
    if data and not json_data and 'Content-Type' in merged_headers:
        if 'application/x-www-form-urlencoded' in merged_headers['Content-Type']:
            del merged_headers['Content-Type']
    
    try:
        if json_data:
            response = requests.post(
                url,
                json=json_data,
                headers=merged_headers,
                timeout=timeout,
                verify=True,
                **kwargs
            )
        else:
            response = requests.post(
                url,
                data=data,
                headers=merged_headers,
                timeout=timeout,
                verify=True,
                **kwargs
            )
        return response
        
    except requests.exceptions.SSLError as ssl_err:
        if enable_ssl_fallback:
            logging.warning(f"[SECURE_REQUESTS] SSL verification failed for POST {url}, retrying with verification disabled")
            try:
                if json_data:
                    response = requests.post(
                        url,
                        json=json_data,
                        headers=merged_headers,
                        timeout=timeout,
                        verify=False,
                        **kwargs
                    )
                else:
                    response = requests.post(
                        url,
                        data=data,
                        headers=merged_headers,
                        timeout=timeout,
                        verify=False,
                        **kwargs
                    )
                response.ssl_verification_bypassed = True
                return response
            except Exception as e:
                logging.error(f"[SECURE_REQUESTS] POST failed even with SSL verification disabled: {e}")
                raise
        else:
            logging.error(f"[SECURE_REQUESTS] SSL verification failed for POST {url} and fallback is disabled")
            raise
            
    except Exception as e:
        logging.error(f"[SECURE_REQUESTS] POST failed for {url}: {e}")
        raise


def check_ssl_status(url: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Check the SSL certificate status of a URL without making a full request.
    
    Returns:
        Dict with ssl_valid, ssl_issuer, ssl_expiry, etc.
    """
    result = {
        "ssl_valid": False,
        "ssl_issuer": None,
        "ssl_expiry": None,
        "ssl_error": None,
        "verified": False
    }
    
    try:
        import ssl
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        hostname = parsed.netloc.split(':')[0]
        port = parsed.port or 443
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                result["ssl_valid"] = True
                result["verified"] = True
                result["ssl_version"] = version
                result["ssl_cipher"] = cipher[0] if cipher else None
                
                if cert:
                    issuer = cert.get('issuer')
                    if issuer:
                        for part in issuer:
                            for key, value in part:
                                if key == 'organizationName':
                                    result["ssl_issuer"] = value
                                    break
                    
                    not_after = cert.get('notAfter')
                    if not_after:
                        result["ssl_expiry"] = not_after
                        
    except ssl.SSLError as e:
        result["ssl_error"] = f"SSL Error: {str(e)}"
    except Exception as e:
        result["ssl_error"] = str(e)
    
    return result
