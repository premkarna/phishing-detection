import unittest
import warnings
import logging
import urllib3
import io
import sys
import re
from app.utils.console_cleaner import setup_hacker_console  # noqa: still in app/utils/

class TestConsoleCleanup(unittest.TestCase):

    def test_log_formatting_and_cleanup_message(self):
        """Verify log format and presence of initialization messages."""
        # Setup the hacker console
        setup_hacker_console()
        
        # We need to capture the output that logging.basicConfig directs to stderr by default
        with self.assertLogs(level='INFO') as cm:
            logging.info("Test Log Message")
            
            # check if initialization messages were sent to the same logger
            # setup_hacker_console is called again to trigger messages inside assertLogs
            setup_hacker_console()
            
            # Verify messages exist in the log records
            self.assertTrue(any("TERMINAL CLEANUP" in r.getMessage() for r in cm.records))
            self.assertTrue(any("Initializing Phishing Sentinel" in r.getMessage() for r in cm.records))
            self.assertTrue(any("Test Log Message" in r.getMessage() for r in cm.records))

    def test_warning_suppression_config(self):
        """Verify that warning filters are correctly set to 'ignore'."""
        setup_hacker_console()
        
        # Check if any filter exists that ignores everything (warnings.filterwarnings("ignore"))
        # Or specifically check the InsecureRequestWarning suppression via urllib3
        
        # Check global filters
        found_ignore_all = False
        for f in warnings.filters:
            if f[0] == 'ignore' and f[2] is None: # action='ignore', category=None (all)
                found_ignore_all = True
                break
        
        self.assertTrue(found_ignore_all, "Global warning ignore filter not found.")

if __name__ == '__main__':
    unittest.main(verbosity=2)
