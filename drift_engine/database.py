import os
import json
import psycopg2

def save_drift_to_db(drift_results: list):
    if not drift_results:
        return

    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_name = os.environ.get("DB_NAME", "driftwatch")
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = os.environ.get("DB_PORT", "5432")

    # Security Fix: Check if credentials exist before connecting
    if not db_user or not db_password:
        print("⚠️ DB_USER or DB_PASSWORD not found in environment. Skipping database save.")
        return
        
    try:
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port
        )
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS drift_history (
                id SERIAL PRIMARY KEY,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resource_type VARCHAR(255),
                resource_id VARCHAR(255),
                resource_name VARCHAR(255),
                drift_type VARCHAR(50),
                diff_details TEXT
            )
        ''')

        for r in drift_results:
            diff_json = json.dumps(r.diff) if r.diff else "{}"
            cursor.execute('''
                INSERT INTO drift_history (resource_type, resource_id, resource_name, drift_type, diff_details)
                VALUES (%s, %s, %s, %s, %s)
            ''', (r.resource_type, r.resource_id, r.resource_name, r.drift_type.value, diff_json))

        conn.commit()
        cursor.close()
        conn.close()
        print("✅ Drift history saved to PostgreSQL database.")
    except Exception as e:
        print(f"❌ Database error: {e}")