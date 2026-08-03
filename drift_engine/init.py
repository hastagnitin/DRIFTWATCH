from remediation import process_remediation
from tf_parser import run_drift_detection

def main():
    print("🚀 Starting DriftWatch Security Engine...")
    
    drift_results = run_drift_detection() 
    
    if not drift_results:
        print("✅ No drift detected. Infrastructure is synced with IaC.")
    else:
        print(f"⚠️ Detected {len(drift_results)} drifted resources. Initiating policy check...")
        process_remediation(drift_results)

if __name__ == "__main__":
    main()