import warnings
import logging
import urllib3

def setup_hacker_console():
    """Wipes out annoying warnings and formats the terminal logs cleanly."""
    
    # 1. Suppress SSL / Insecure warnings from requests library
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 2. Suppress generic FutureWarnings from external libraries
    warnings.filterwarnings("ignore")
    warnings.filters.insert(0, ('ignore', None, None, None, 0))
    
    # 3. Setup Corporate SOC Terminal Logging Format
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S',
        force=False
    )
    
    logging.getLogger().warning("[+] TERMINAL CLEANUP: All insecure warnings suppressed.")
    logging.getLogger().warning("[+] SYSTEM: Initializing Phishing Sentinel Core Services...")