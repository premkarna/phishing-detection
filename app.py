# app.py
from src.predict import predict_url

def main():
    print("==================================================")
    print("🛡️  ADVANCED PHISHING DETECTOR v2.0 (PRO)  🛡️")
    print("==================================================")
    
    while True:
        # Ask user for input
        user_input = input("\nEnter a URL to scan (or 'exit' to quit): ").strip()
        
        if user_input.lower() == 'exit':
            print("Shutting down... Stay safe!")
            break
            
        if user_input == "":
            print("Please enter a valid URL.")
            continue
            
        # 💡 THE FIX: Auto-formatting the URL!
        # If the user is lazy and doesn't type http/https, we add it for them.
        if not user_input.startswith(('http://', 'https://')):
            scan_url = 'http://' + user_input
            print(f"[*] Auto-formatted URL to: {scan_url}")
        else:
            scan_url = user_input
            
        # Send to our prediction brain
        result, reasons = predict_url(scan_url)
        
        # Print the final verdict
        print(f"\n>>> RESULT: {result}")
        
        # Print EXACTLY why it gave that verdict
        if result == "⚠️ PHISHING DETECTED" and reasons:
            print("🚩 Red Flags Triggered:")
            for r in reasons:
                print(f"   - {r}")
                
        elif result == "✅ SAFE URL" and reasons:
            # Even if safe, we warn about minor things like missing HTTPS
            print("ℹ️ Note: Even though AI classified it as safe, we noticed:")
            for r in reasons:
                print(f"   - {r}")

if __name__ == "__main__":
    main()
    