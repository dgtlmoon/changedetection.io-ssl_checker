"""SSL Certificate Processor Plugin for ChangeDetection.io"""
import hashlib
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from OpenSSL import crypto
from changedetectionio.processors.pluggy_interface import hookimpl
from changedetectionio.content_fetchers.base import Fetcher
from wtforms import BooleanField, validators


class SSLCertificateFetcher(Fetcher):
    """Custom fetcher that retrieves SSL certificate information from websites"""

    def run(self, url, timeout, request_headers, request_body, request_method, ignore_status_codes, 
            current_include_filters, is_binary, empty_pages_are_a_change):
        # Parse the URL to get the hostname
        parsed_url = urllib.parse.urlparse(url)
        hostname = parsed_url.netloc
        
        # If the URL doesn't include a port, use 443 (default HTTPS)
        if ':' in hostname:
            hostname, port = hostname.split(':')
            port = int(port)
        else:
            port = 443
            
        # Remove www. if present to avoid certificate mismatch issues
        if hostname.startswith('www.'):
            hostname = hostname[4:]
        
        try:
            from . import cert
            cert_details = cert.get_certificate_details(hostname)
            self.content = cert.format_certificate_info(cert_details).encode('utf-8')


        except Exception as e:
            error_message = f"SSL certificate fetch error: {str(e)}"
            self.content = error_message.encode('utf-8')
            self.status_code = 500
            self.headers = {
                'X-SSL-Error': str(e)
            }

    def quit(self):
        # Nothing to clean up
        pass

class SSLProcessor(object):
    """Processor for SSL certificate information"""
    
    datastore = None
    fetcher = None
    watch = None
    
    def __init__(self, *args, datastore, watch_uuid, **kwargs):
        super().__init__(*args, **kwargs)
        self.datastore = datastore
        self.watch = datastore.data['watching'].get(watch_uuid)
        self.fetcher = SSLCertificateFetcher()
    
    def call_browser(self, preferred_proxy_id=None):
        """Perform the SSL certificate lookup"""
        # No proxy support needed for SSL lookups
        url = self.watch.link
        
        # Get custom settings from the processor-specific settings
        show_days_remaining = self.watch.get('ssl_show_days_remaining', True)
        
        # Custom headers to pass settings to the fetcher
        headers = {'X-Show-Days-Remaining': str(show_days_remaining).lower()}
        
        # We use the same params as the original method but ignore most of them
        self.fetcher.run(
            url=url,
            timeout=30,  # SSL certificate checks usually don't need long timeouts
            request_headers=headers,
            request_body=None,  # Not applicable for SSL checks
            request_method='GET',  # Not applicable for SSL checks
            ignore_status_codes=False,
            current_include_filters=None,
            is_binary=False,
            empty_pages_are_a_change=False
        )
    
    def run_changedetection(self, watch):
        """Check if SSL certificate information has changed"""
        update_obj = {'last_notification_error': False, 'last_error': False}
        
        # Check if we have content from the fetcher
        ssl_content = self.fetcher.content
        if not ssl_content:
            ssl_content = b''
        
        # Calculate MD5 of the content
        current_md5 = hashlib.md5(ssl_content).hexdigest()
        
        # Compare with previous MD5 if it exists
        previous_md5 = watch.get('previous_md5', '')
        update_obj["previous_md5"] = current_md5
        
        # Detect if there's a change
        changed_detected = previous_md5 != current_md5 and previous_md5 != ''
        
        # Convert bytes to string - this is more consistent with text_json_diff processor
        ssl_text = ssl_content.decode('utf-8') if ssl_content else ''
        
        return changed_detected, update_obj, ssl_text

#class SSLCertificateForm(forms.processor_text_json_diff_form):
#    """SSL Certificate processor settings form"""
#    ssl_show_days_remaining = BooleanField(
#        'Show days remaining of validity',
#        default=True,
#        validators=[validators.Optional()]
#    )

class SSLPlugin:
    """Plugin for SSL certificate monitoring in changedetection.io"""
    
    @hookimpl
    def get_processor_name(self):
        return "ssl_certificate"
    
    @hookimpl
    def get_processor_description(self):
        return "SSL Certificate Information and Expiry Monitoring"
        
    @hookimpl
    def get_processor_version(self):
        return "0.1.0"
    
    @hookimpl
    def perform_site_check(self, datastore, watch_uuid):
        watch = datastore.data['watching'].get(watch_uuid)
        if watch and watch.get('processor') == 'ssl_certificate':
            return SSLProcessor(datastore=datastore, watch_uuid=watch_uuid)
        return None
    
#    @hookimpl
#    def get_form_class(self, processor_name):
#        if processor_name == 'ssl_certificate':
#            from changedetectionio import forms
#            return SSLCertificateForm
#        return None
    
    @hookimpl
    def get_watch_model_class(self, processor_name):
        if processor_name == 'ssl_certificate':
            # Return default Watch model
            from changedetectionio.model import Watch
            return Watch.model
        return None

# Create a plugin instance for the entry point to use
plugin_instance = SSLPlugin()