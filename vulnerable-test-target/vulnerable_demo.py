# SovaScan Demo Target - Vulnerable Python File
# This file is used to demonstrate vulnerability scanning capabilities.

import os
import sys

def main():
    print("Initializing Application...")
    
    # 1. SOVA-SECRET-001: Exposed secret API Key
    api_key = "MOCK_API_KEY_FOR_LOCAL_SOVASCAN_EXERCISES_1234"
    
    # 2. SOVA-WEB-001: Debug mode enabled in configurations
    debug = true
    
    # 3. SOVA-WEB-003: CORS Wildcard Origin Allowed
    Access-Control-Allow-Origin = "*"
    
    print(f"API Key: {api_key}")
    print(f"Debug Mode Status: {debug}")
    print(f"CORS Origin: {Access-Control-Allow-Origin}")

if __name__ == "__main__":
    main()
