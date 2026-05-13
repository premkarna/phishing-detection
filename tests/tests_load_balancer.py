import concurrent.futures
import requests
import time
import json
import logging

# Simulation Settings
BASE_URL = "http://127.0.0.1:5000"
CONCURRENT_REQUESTS = 50 # Boss, 50 users okesari scan chesthe ela untundi ani simulation
TOTAL_REQUESTS = 200

def simulate_user_request(request_id):
    """Simulates a single user scanning a URL."""
    payload = {
        "payload": f"test-site-{request_id}.com",
        "vector": "url"
    }
    try:
        start_time = time.time()
        response = requests.post(f"{BASE_URL}/analyze", json=payload, timeout=10)
        end_time = time.time()
        
        status = response.status_code
        latency = end_time - start_time
        
        if status == 200:
            return True, latency
        else:
            return False, latency
    except Exception as e:
        return False, 0

def run_load_test():
    print(f"\n[🚀] INITIATING SOC LOAD BALANCING SIMULATION...")
    print(f"[*] Targeting: {BASE_URL}")
    print(f"[*] Concurrent Users: {CONCURRENT_REQUESTS}")
    print(f"[*] Total Requests: {TOTAL_REQUESTS}")
    
    success_count = 0
    latencies = []
    
    start_test = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_REQUESTS) as executor:
        # Submit all requests
        future_to_id = {executor.submit(simulate_user_request, i): i for i in range(TOTAL_REQUESTS)}
        
        for future in concurrent.futures.as_completed(future_to_id):
            success, latency = future.result()
            if success:
                success_count += 1
                latencies.append(latency)
            else:
                print(f"[!] Request {future_to_id[future]} Failed!")

    end_test = time.time()
    total_time = end_test - start_test
    
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    throughput = success_count / total_time if total_time > 0 else 0

    print("\n" + "="*40)
    print("       SOC LOAD TEST RESULTS")
    print("="*40)
    print(f"Total Time:         {total_time:.2f}s")
    print(f"Successful Scans:   {success_count}/{TOTAL_REQUESTS}")
    print(f"Avg Latency:        {avg_latency:.4f}s")
    print(f"Throughput:         {throughput:.2f} requests/sec")
    print("="*40)

    if success_count == TOTAL_REQUESTS:
        print("\n[✅] MISSION SUCCESS: System handled high traffic without crashing!")
        if avg_latency < 1.0:
            print("[⚡] PERFORMANCE: System response is elite (< 1s under load).")
    else:
        print("\n[🛑] ALERT: System dropped requests under pressure!")

if __name__ == "__main__":
    # Make sure main.py is running before executing this
    try:
        requests.get(BASE_URL, timeout=2)
        run_load_test()
    except:
        print(f"[!] ERROR: Boss, server ({BASE_URL}) run avvatledhu. 'python main.py' start chesi malli try cheyandi.")
