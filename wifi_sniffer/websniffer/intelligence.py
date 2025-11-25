import requests
import json
import os
from config import Config
import logging
import geoip2.database

class ThreatIntelligence:
    def __init__(self):
        self.virustotal_api_key = Config.VIRUSTOTAL_API_KEY
        self.abuseipdb_api_key = Config.ABUSEIPDB_API_KEY
        self.shodan_api_key = Config.SHODAN_API_KEY
        self.geoip_db_path = Config.GEOIP_DB_PATH
        
        # Initialize GeoIP reader if database exists
        self.geoip_reader = None
        if os.path.exists(self.geoip_db_path):
            try:
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                logging.info("GeoIP database loaded successfully")
            except Exception as e:
                logging.error(f"Error loading GeoIP database: {e}")
        else:
            logging.warning(f"GeoIP database not found at {self.geoip_db_path}")
            
    def get_ip_info(self, ip):
        """Get information about an IP address."""
        result = {
            'ip': ip,
            'location': None,
            'threat_info': None
        }
        
        # Get GeoIP information
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                result['location'] = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude
                }
            except Exception as e:
                logging.error(f"Error getting GeoIP info for {ip}: {e}")
        
        # Get threat intelligence information
        try:
            result['threat_info'] = self._get_threat_info(ip)
        except Exception as e:
            logging.error(f"Error getting threat info for {ip}: {e}")
        
        return result
    
    def _get_threat_info(self, ip):
        """Get threat intelligence information for an IP address."""
        threat_info = {
            'virustotal': None,
            'abuseipdb': None
        }
        
        # Check VirusTotal if API key is available
        if Config.VIRUSTOTAL_API_KEY:
            try:
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {'apikey': Config.VIRUSTOTAL_API_KEY, 'ip': ip}
                response = requests.get(url, params=params)
                if response.status_code == 200:
                    threat_info['virustotal'] = response.json()
            except Exception as e:
                logging.error(f"Error querying VirusTotal: {e}")
        
        # Check AbuseIPDB if API key is available
        if Config.ABUSEIPDB_API_KEY:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Key': Config.ABUSEIPDB_API_KEY,
                    'Accept': 'application/json'
                }
                params = {'ipAddress': ip}
                response = requests.get(url, headers=headers, params=params)
                if response.status_code == 200:
                    threat_info['abuseipdb'] = response.json()
            except Exception as e:
                logging.error(f"Error querying AbuseIPDB: {e}")
        
        return threat_info
    
    def get_domain_info(self, domain):
        """Get information about a domain."""
        result = {
            'domain': domain,
            'threat_info': None
        }
        
        # Get threat intelligence information
        try:
            result['threat_info'] = self._get_domain_threat_info(domain)
        except Exception as e:
            logging.error(f"Error getting domain threat info for {domain}: {e}")
        
        return result
    
    def _get_domain_threat_info(self, domain):
        """Get threat intelligence information for a domain."""
        threat_info = {
            'virustotal': None
        }
        
        # Check VirusTotal if API key is available
        if Config.VIRUSTOTAL_API_KEY:
            try:
                url = f"https://www.virustotal.com/vtapi/v2/domain/report"
                params = {'apikey': Config.VIRUSTOTAL_API_KEY, 'domain': domain}
                response = requests.get(url, params=params)
                if response.status_code == 200:
                    threat_info['virustotal'] = response.json()
            except Exception as e:
                logging.error(f"Error querying VirusTotal for domain: {e}")
        
        return threat_info
            
    def __del__(self):
        """Clean up resources when the object is destroyed."""
        if hasattr(self, 'geoip_reader') and self.geoip_reader:
            try:
                self.geoip_reader.close()
            except Exception as e:
                logging.error(f"Error closing GeoIP reader: {e}") 