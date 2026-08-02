import os
import json
import psycopg2

def save_drift_to_db(drift_results: list):
    if not drift_results:
        return
        
    try:
        conn = psycopg2.connect(
            dbname=os.environ.get("DB_NAME", "driftwatch"),
            user=os.environ.get("DB_USER", "admin"),
            password=os.environ.get("DB_PASSWORD", "admin"),
            host=os.environ.get("DB_HOST", "localhost"),
            port=os.environ.get("DB_PORT", "5432")
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