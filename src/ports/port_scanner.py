"""
Port Scanner Module
Performs non-intrusive port scanning on discovered assets.
"""

import socket
import logging
from typing import List, Dict, Any, Set
from datetime import datetime
import concurrent.futures
import json

logger = logging.getLogger(__name__)


class PortScanner:
    """Port scanner for discovered hosts."""
    
    # Common ports to scan
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        9200: 'Elasticsearch',
        27017: 'MongoDB'
    }
    
    def __init__(self, timeout: int = 2, max_workers: int = 10):
        """
        Initialize port scanner.
        
        Args:
            timeout: Socket timeout in seconds
            max_workers: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []
    
    def scan_host(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """
        Scan ports on a single host.
        
        Args:
            host: Target hostname or IP
            ports: List of ports to scan (default: common ports)
            
        Returns:
            Dictionary containing scan results
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())
        
        logger.info(f"Scanning {len(ports)} ports on {host}")
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self._check_port, host, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        port_info = {
                            'port': port,
                            'service': self.COMMON_PORTS.get(port, 'Unknown'),
                            'banner': banner
                        }
                        open_ports.append(port_info)
                        logger.info(f"[+] {host}:{port} - {port_info['service']}")
                except Exception as e:
                    logger.debug(f"Error scanning {host}:{port} - {str(e)}")
        
        result = {
            'host': host,
            'timestamp': datetime.utcnow().isoformat(),
            'open_ports': sorted(open_ports, key=lambda x: x['port']),
            'total_open': len(open_ports)
        }
        
        return result
    
    def _check_port(self, host: str, port: int) -> tuple:
        """
        Check if a port is open.
        
        Args:
            host: Target host
            port: Port number
            
        Returns:
            Tuple of (is_open, banner)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        banner = ""
        
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    # Try to grab banner
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass
                return (True, banner)
        except:
            pass
        finally:
            sock.close()
        
        return (False, "")
    
    def scan_multiple_hosts(self, hosts: List[str], ports: List[int] = None) -> List[Dict[str, Any]]:
        """
        Scan multiple hosts.
        
        Args:
            hosts: List of hostnames/IPs
            ports: List of ports to scan
            
        Returns:
            List of scan results
        """
        results = []
        
        for host in hosts:
            try:
                result = self.scan_host(host, ports)
                if result['total_open'] > 0:
                    results.append(result)
            except Exception as e:
                logger.error(f"Error scanning {host}: {str(e)}")
        
        self.results = results
        return results
    
    def save_results(self, output_path: str):
        """
        Save scan results to JSON file.
        
        Args:
            output_path: Path to output file
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            logger.info(f"Port scan results saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of scan results.
        
        Returns:
            Dictionary containing summary statistics
        """
        if not self.results:
            return {}
        
        total_hosts = len(self.results)
        total_open_ports = sum(r['total_open'] for r in self.results)
        
        # Count services
        service_counts = {}
        for result in self.results:
            for port_info in result['open_ports']:
                service = port_info['service']
                service_counts[service] = service_counts.get(service, 0) + 1
        
        return {
            'total_hosts_scanned': total_hosts,
            'total_open_ports': total_open_ports,
            'services_found': service_counts
        }
