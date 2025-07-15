#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Accurate Cyber Defense Bot Terminal 
Version: 1.0
Author: Ian Carter Kulani
Description: A command-line tool for monitoring cyber security threats using IP addresses
             with Telegram integration for remote access and alerts.
"""

import os
import sys
import time
import socket
import subprocess
import requests
import json
import threading
from datetime import datetime
import readline  # For better command line input handling
import ipaddress
import dns.resolver
import platform
import shlex
import re
from typing import Optional, Dict, List, Tuple, Union

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    DARK_GREEN = '\033[32m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    PURPLE = '\033[95m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Configuration settings
class Config:
    TELEGRAM_TOKEN = ""  # Your Telegram bot token
    TELEGRAM_CHAT_ID = ""  # Your Telegram chat ID
    MONITORING_INTERVAL = 300  # 5 minutes in seconds
    MAX_LOG_SIZE = 10000  # Max lines in log file
    LOG_FILE = "Accurate.log"
    CONFIG_FILE = "config.json"
    VERSION = "10.0"
    AUTHOR = "Ian Cartre Kulani"
    BANNER = f"""{Colors.GREEN}
   _____      _               _____                  _   _       _ _   _____         _   
   / ____|    | |             / ____|                | | | |     (_) | |  __ \       | |  
  | |    _   _| |__  ___ _ __| (___   ___ ___ _ __ ___| | | |_ __ _| |_| |__) |____ _| |_ 
  | |   | | | | '_ \/ _ \ '__\___ \ / __/ _ \ '__/ _ \ | | | '__| | __|  _  // _ \ | __|
  | |___| |_| | |_) |  __/ |  ____) | (_|  __/ | |  __/ |_| | 
  \__,_|_.__/ \___|_| |_____/ \___\___|_|  \___|\___/|_|  |_|\__|_|  \_\___|  \__|
                                                                                         
{Colors.END}{Colors.DARK_GREEN}Version: {VERSION} | Author: {AUTHOR}{Colors.END}
"""

# Global variables
monitoring_active = False
current_monitoring_ip = ""
telegram_bot_active = False
command_history = []

# Utility functions
def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the tool banner"""
    clear_screen()
    print(Config.BANNER)

def validate_ip(ip: str) -> bool:
    """Validate an IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def log_message(message: str, level: str = "INFO"):
    """Log messages to file and print to console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    
    # Print to console with colors
    if level == "ERROR":
        print(f"{Colors.RED}{log_entry}{Colors.END}", end='')
    elif level == "WARNING":
        print(f"{Colors.YELLOW}{log_entry}{Colors.END}", end='')
    elif level == "SUCCESS":
        print(f"{Colors.GREEN}{log_entry}{Colors.END}", end='')
    else:
        print(log_entry, end='')
    
    # Write to log file
    try:
        with open(Config.LOG_FILE, 'a') as f:
            f.write(log_entry)
        
        # Rotate log if too large
        with open(Config.LOG_FILE, 'r') as f:
            lines = f.readlines()
            if len(lines) > Config.MAX_LOG_SIZE:
                with open(Config.LOG_FILE, 'w') as f:
                    f.writelines(lines[-Config.MAX_LOG_SIZE:])
    except IOError as e:
        print(f"{Colors.RED}Error writing to log file: {e}{Colors.END}")

def save_config():
    """Save configuration to file"""
    config = {
        'telegram_token': Config.TELEGRAM_TOKEN,
        'telegram_chat_id': Config.TELEGRAM_CHAT_ID,
        'monitoring_interval': Config.MONITORING_INTERVAL
    }
    try:
        with open(Config.CONFIG_FILE, 'w') as f:
            json.dump(config, f)
        log_message("Configuration saved successfully", "SUCCESS")
    except IOError as e:
        log_message(f"Error saving configuration: {e}", "ERROR")

def load_config():
    """Load configuration from file"""
    try:
        if os.path.exists(Config.CONFIG_FILE):
            with open(Config.CONFIG_FILE, 'r') as f:
                config = json.load(f)
                Config.TELEGRAM_TOKEN = config.get('telegram_token', "")
                Config.TELEGRAM_CHAT_ID = config.get('telegram_chat_id', "")
                Config.MONITORING_INTERVAL = config.get('monitoring_interval', 300)
            log_message("Configuration loaded successfully", "SUCCESS")
        else:
            log_message("No configuration file found, using defaults", "WARNING")
    except (IOError, json.JSONDecodeError) as e:
        log_message(f"Error loading configuration: {e}", "ERROR")

def send_telegram_message(message: str):
    """Send a message via Telegram bot"""
    if not Config.TELEGRAM_TOKEN or not Config.TELEGRAM_CHAT_ID:
        log_message("Telegram token or chat ID not configured", "WARNING")
        return False
    
    url = f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}/sendMessage"
    payload = {
        'chat_id': Config.TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    
    try:
        response = requests.post(url, data=payload)
        if response.status_code == 200:
            log_message("Telegram message sent successfully", "SUCCESS")
            return True
        else:
            log_message(f"Failed to send Telegram message: {response.text}", "ERROR")
            return False
    except requests.RequestException as e:
        log_message(f"Error sending Telegram message: {e}", "ERROR")
        return False

def telegram_bot_listener():
    """Listen for Telegram commands"""
    global telegram_bot_active, monitoring_active, current_monitoring_ip
    
    if not Config.TELEGRAM_TOKEN:
        log_message("Telegram token not configured", "ERROR")
        return
    
    log_message("Starting Telegram bot listener...", "INFO")
    offset = 0
    
    while telegram_bot_active:
        try:
            url = f"https://api.telegram.org/bot{Config.TELEGRAM_TOKEN}/getUpdates?offset={offset}"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                if data['ok'] and data['result']:
                    for update in data['result']:
                        offset = update['update_id'] + 1
                        message = update.get('message', {})
                        chat_id = message.get('chat', {}).get('id')
                        text = message.get('text', '').strip()
                        
                        if chat_id == Config.TELEGRAM_CHAT_ID:
                            log_message(f"Received Telegram command: {text}", "INFO")
                            
                            # Process commands
                            if text.startswith('/'):
                                command = text.split()[0].lower()
                                args = text.split()[1:] if len(text.split()) > 1 else []
                                
                                if command == '/help':
                                    help_message = """
*Available Commands:*
`/help` - Show this help message
`/start_monitoring <ip>` - Start monitoring an IP address
`/stop` - Stop monitoring
`/ping <ip>` - Ping an IP address
`/nslookup <ip/domain>` - Perform DNS lookup
`/netstat <ip>` - Show network statistics for IP
`/tracert <ip>` - Trace route to IP
`/status` - Show current monitoring status
"""
                                    send_telegram_message(help_message)
                                
                                elif command == '/start_monitoring' and args:
                                    ip = args[0]
                                    if validate_ip(ip):
                                        current_monitoring_ip = ip
                                        monitoring_active = True
                                        send_telegram_message(f"Started monitoring IP: `{ip}`")
                                    else:
                                        send_telegram_message("Invalid IP address format")
                                
                                elif command == '/stop':
                                    monitoring_active = False
                                    send_telegram_message("Monitoring stopped")
                                
                                elif command == '/ping' and args:
                                    ip = args[0]
                                    if validate_ip(ip):
                                        result = ping_ip(ip)
                                        send_telegram_message(f"Ping results for `{ip}`:\n```\n{result}\n```")
                                    else:
                                        send_telegram_message("Invalid IP address format")
                                
                                elif command == '/nslookup' and args:
                                    target = args[0]
                                    result = perform_nslookup(target)
                                    send_telegram_message(f"DNS lookup for `{target}`:\n```\n{result}\n```")
                                
                                elif command == '/netstat' and args:
                                    ip = args[0]
                                    if validate_ip(ip):
                                        result = get_netstat_info(ip)
                                        send_telegram_message(f"Network statistics for `{ip}`:\n```\n{result}\n```")
                                    else:
                                        send_telegram_message("Invalid IP address format")
                                
                                elif command == '/tracert' and args:
                                    ip = args[0]
                                    if validate_ip(ip):
                                        result = trace_route(ip)
                                        send_telegram_message(f"Trace route to `{ip}`:\n```\n{result}\n```")
                                    else:
                                        send_telegram_message("Invalid IP address format")
                                
                                elif command == '/status':
                                    status = "Active" if monitoring_active else "Inactive"
                                    message = f"*Monitoring Status:* `{status}`\n"
                                    if monitoring_active:
                                        message += f"*Current IP:* `{current_monitoring_ip}`\n"
                                    message += f"*Telegram Bot:* `{'Active' if telegram_bot_active else 'Inactive'}`"
                                    send_telegram_message(message)
                                
                                else:
                                    send_telegram_message("Unknown command. Use `/help` for available commands.")
            
            time.sleep(5)
        
        except requests.RequestException as e:
            log_message(f"Telegram API error: {e}", "ERROR")
            time.sleep(30)
        except Exception as e:
            log_message(f"Unexpected error in Telegram listener: {e}", "ERROR")
            time.sleep(30)

# Monitoring functions
def ping_ip(ip: str, count: int = 4) -> str:
    """Ping an IP address and return results"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(count), ip]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Ping failed:\n{result.stderr if result.stderr else result.stdout}"
    except Exception as e:
        return f"Error executing ping: {str(e)}"

def perform_nslookup(target: str) -> str:
    """Perform DNS lookup for a domain or IP"""
    try:
        if validate_ip(target):
            # Reverse DNS lookup
            try:
                hostname, _, _ = socket.gethostbyaddr(target)
                return f"Reverse DNS for {target}:\nHostname: {hostname}"
            except socket.herror:
                return f"No reverse DNS record found for {target}"
        else:
            # Forward DNS lookup
            result = []
            try:
                answers = dns.resolver.resolve(target, 'A')
                for rdata in answers:
                    result.append(f"A Record: {rdata.address}")
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                return f"Domain {target} does not exist"
            except Exception as e:
                return f"DNS lookup error: {str(e)}"
            
            try:
                answers = dns.resolver.resolve(target, 'MX')
                for rdata in answers:
                    result.append(f"MX Record: {rdata.exchange} (Priority: {rdata.preference})")
            except dns.resolver.NoAnswer:
                pass
            
            try:
                answers = dns.resolver.resolve(target, 'TXT')
                for rdata in answers:
                    for txt_string in rdata.strings:
                        result.append(f"TXT Record: {txt_string.decode()}")
            except dns.resolver.NoAnswer:
                pass
            
            if not result:
                return f"No DNS records found for {target}"
            return "\n".join(result)
    except Exception as e:
        return f"Error performing DNS lookup: {str(e)}"

def get_netstat_info(ip: str = "") -> str:
    """Get network statistics, optionally filtered by IP"""
    try:
        if platform.system().lower() == 'windows':
            command = ['netstat', '-ano']
        else:
            command = ['netstat', '-tulnp']
        
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode != 0:
            return f"Error executing netstat: {result.stderr}"
        
        lines = result.stdout.split('\n')
        if ip:
            filtered_lines = [line for line in lines if ip in line]
            return "\n".join(filtered_lines) if filtered_lines else f"No connections found for IP: {ip}"
        else:
            return result.stdout
    except Exception as e:
        return f"Error getting network statistics: {str(e)}"

def trace_route(ip: str) -> str:
    """Perform a traceroute to an IP address"""
    try:
        if platform.system().lower() == 'windows':
            command = ['tracert', ip]
        else:
            command = ['traceroute', ip]
        
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Trace route failed:\n{result.stderr if result.stderr else result.stdout}"
    except Exception as e:
        return f"Error executing trace route: {str(e)}"

def check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open on an IP address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def monitor_ip(ip: str):
    """Monitor an IP address for security threats"""
    global monitoring_active
    
    log_message(f"Starting security monitoring for IP: {ip}", "INFO")
    if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
        send_telegram_message(f"🚨 *Security Monitoring Started* 🚨\nIP: `{ip}`")
    
    previous_ports = set()
    previous_ping_result = ""
    previous_dns_result = ""
    
    while monitoring_active and current_monitoring_ip == ip:
        try:
            # Check for open ports
            open_ports = []
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
            
            for port in common_ports:
                if check_port(ip, port):
                    open_ports.append(port)
            
            current_ports = set(open_ports)
            
            # Detect new open ports
            new_ports = current_ports - previous_ports
            if new_ports:
                message = f"🚨 New open ports detected on {ip}: {', '.join(map(str, new_ports))}"
                log_message(message, "WARNING")
                if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
                    send_telegram_message(message)
            
            # Detect closed ports
            closed_ports = previous_ports - current_ports
            if closed_ports:
                message = f"⚠️ Ports closed on {ip}: {', '.join(map(str, closed_ports))}"
                log_message(message, "WARNING")
                if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
                    send_telegram_message(message)
            
            previous_ports = current_ports
            
            # Ping monitoring
            current_ping = ping_ip(ip)
            if "100% packet loss" in current_ping:
                message = f"🚨 Ping failed to {ip} (100% packet loss)"
                log_message(message, "ERROR")
                if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
                    send_telegram_message(message)
            
            # DNS monitoring
            current_dns = perform_nslookup(ip)
            if current_dns != previous_dns_result and previous_dns_result:
                message = f"⚠️ DNS change detected for {ip}:\nPrevious:\n{previous_dns_result}\nCurrent:\n{current_dns}"
                log_message(f"DNS change detected for {ip}", "WARNING")
                if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
                    send_telegram_message(message)
            
            previous_ping_result = current_ping
            previous_dns_result = current_dns
            
            # Network connections monitoring
            netstat_info = get_netstat_info(ip)
            suspicious_connections = []
            
            for line in netstat_info.split('\n'):
                if ip in line and "ESTABLISHED" in line:
                    suspicious_connections.append(line)
            
            if suspicious_connections:
                message = f"⚠️ Suspicious connections to {ip}:\n" + "\n".join(suspicious_connections)
                log_message(message, "WARNING")
                if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
                    send_telegram_message(message)
            
            # Wait for next monitoring cycle
            for _ in range(Config.MONITORING_INTERVAL):
                if not monitoring_active or current_monitoring_ip != ip:
                    break
                time.sleep(1)
        
        except Exception as e:
            log_message(f"Error during monitoring: {str(e)}", "ERROR")
            time.sleep(30)

# Command processing
def process_command(command: str) -> bool:
    """Process user commands"""
    global monitoring_active, current_monitoring_ip, telegram_bot_active
    
    parts = shlex.split(command)
    if not parts:
        return True
    
    cmd = parts[0].lower()
    args = parts[1:] if len(parts) > 1 else []
    
    if cmd == "help":
        print(f"""{Colors.GREEN}
Available Commands:
{Colors.DARK_GREEN}help{Colors.END} - Show this help message
{Colors.DARK_GREEN}start_monitoring <ip>{Colors.END} - Start monitoring an IP address
{Colors.DARK_GREEN}stop{Colors.END} - Stop monitoring
{Colors.DARK_GREEN}ping <ip>{Colors.END} - Ping an IP address
{Colors.DARK_GREEN}nslookup <ip/domain>{Colors.END} - Perform DNS lookup
{Colors.DARK_GREEN}netstat [ip]{Colors.END} - Show network statistics (optionally filtered by IP)
{Colors.DARK_GREEN}tracert <ip>{Colors.END} - Trace route to IP
{Colors.DARK_GREEN}telegram <token> <chat_id>{Colors.END} - Configure Telegram bot
{Colors.DARK_GREEN}start_bot{Colors.END} - Start Telegram bot listener
{Colors.DARK_GREEN}stop_bot{Colors.END} - Stop Telegram bot listener
{Colors.DARK_GREEN}status{Colors.END} - Show current monitoring status
{Colors.DARK_GREEN}config{Colors.END} - Show current configuration
{Colors.DARK_GREEN}clear{Colors.END} - Clear the screen
{Colors.DARK_GREEN}exit{Colors.END} - Exit the program
""")
    
    elif cmd == "start_monitoring" and args:
        ip = args[0]
        if validate_ip(ip):
            monitoring_active = True
            current_monitoring_ip = ip
            monitoring_thread = threading.Thread(target=monitor_ip, args=(ip,), daemon=True)
            monitoring_thread.start()
            log_message(f"Started monitoring IP: {ip}", "SUCCESS")
        else:
            log_message("Invalid IP address format", "ERROR")
    
    elif cmd == "stop":
        monitoring_active = False
        log_message("Monitoring stopped", "SUCCESS")
    
    elif cmd == "ping" and args:
        ip = args[0]
        if validate_ip(ip):
            result = ping_ip(ip)
            print(f"{Colors.CYAN}Ping results for {ip}:{Colors.END}\n{result}")
        else:
            log_message("Invalid IP address format", "ERROR")
    
    elif cmd == "nslookup" and args:
        target = args[0]
        result = perform_nslookup(target)
        print(f"{Colors.CYAN}DNS lookup for {target}:{Colors.END}\n{result}")
    
    elif cmd == "netstat":
        ip = args[0] if args else ""
        result = get_netstat_info(ip)
        print(f"{Colors.CYAN}Network statistics{' for ' + ip if ip else ''}:{Colors.END}\n{result}")
    
    elif cmd == "tracert" and args:
        ip = args[0]
        if validate_ip(ip):
            result = trace_route(ip)
            print(f"{Colors.CYAN}Trace route to {ip}:{Colors.END}\n{result}")
        else:
            log_message("Invalid IP address format", "ERROR")
    
    elif cmd == "telegram" and len(args) >= 2:
        Config.TELEGRAM_TOKEN = args[0]
        Config.TELEGRAM_CHAT_ID = args[1]
        save_config()
        log_message("Telegram configuration updated", "SUCCESS")
    
    elif cmd == "start_bot":
        if not telegram_bot_active:
            if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
                telegram_bot_active = True
                bot_thread = threading.Thread(target=telegram_bot_listener, daemon=True)
                bot_thread.start()
                log_message("Telegram bot listener started", "SUCCESS")
            else:
                log_message("Telegram token and chat ID must be configured first", "ERROR")
        else:
            log_message("Telegram bot is already running", "WARNING")
    
    elif cmd == "stop_bot":
        telegram_bot_active = False
        log_message("Telegram bot listener stopped", "SUCCESS")
    
    elif cmd == "status":
        status = "Active" if monitoring_active else "Inactive"
        print(f"{Colors.GREEN}Monitoring Status:{Colors.END} {status}")
        if monitoring_active:
            print(f"{Colors.GREEN}Current IP:{Colors.END} {current_monitoring_ip}")
        print(f"{Colors.GREEN}Telegram Bot:{Colors.END} {'Active' if telegram_bot_active else 'Inactive'}")
    
    elif cmd == "config":
        print(f"{Colors.GREEN}Current Configuration:{Colors.END}")
        print(f"Telegram Token: {'Configured' if Config.TELEGRAM_TOKEN else 'Not configured'}")
        print(f"Telegram Chat ID: {'Configured' if Config.TELEGRAM_CHAT_ID else 'Not configured'}")
        print(f"Monitoring Interval: {Config.MONITORING_INTERVAL} seconds")
    
    elif cmd == "clear":
        clear_screen()
        print_banner()
    
    elif cmd == "exit":
        monitoring_active = False
        telegram_bot_active = False
        log_message("Exiting Accurate Cyber Defense Monitoring Bot", "INFO")
        return False
    
    else:
        log_message("Unknown command. Type 'help' for available commands.", "ERROR")
    
    return True

def main():
    """Main program loop"""
    global telegram_bot_active
    
    # Initialize
    print_banner()
    load_config()
    
    # Start Telegram bot if configured
    if Config.TELEGRAM_TOKEN and Config.TELEGRAM_CHAT_ID:
        telegram_bot_active = True
        bot_thread = threading.Thread(target=telegram_bot_listener, daemon=True)
        bot_thread.start()
        log_message("Telegram bot listener started automatically", "INFO")
    
    # Command loop
    try:
        running = True
        while running:
            try:
                command = input(f"{Colors.GREEN}cyber_monitor>{Colors.END} ").strip()
                if command:
                    command_history.append(command)
                    running = process_command(command)
            except KeyboardInterrupt:
                print()  # New line after ^C
                log_message("Type 'exit' to quit or 'help' for commands", "INFO")
            except EOFError:
                running = False
                log_message("Exiting...", "INFO")
    except Exception as e:
        log_message(f"Fatal error: {str(e)}", "ERROR")
    finally:
        monitoring_active = False
        telegram_bot_active = False
        log_message("Accurate Cyber Defense Security Monitoring Bot shutdown complete", "INFO")

if __name__ == "__main__":
    main()