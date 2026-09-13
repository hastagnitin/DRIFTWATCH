import os
import json
from contextlib import contextmanager

_db_pool = None

def _get_or_create_pool(psycopg2_module, db_name, db_user, db_password, db_host, db_port):
    global _db_pool
    if _db_pool is None:
        try:
            if hasattr(psycopg2_module, "pool") and hasattr(psycopg2_module.pool, "ThreadedConnectionPool"):
                _db_pool = psycopg2_module.pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=10,
                    dbname=db_name,
                    user=db_user,
                    password=db_password,
                    host=db_host,
                    port=db_port
                )
        except Exception:
            _db_pool = None
    return _db_pool

def close_db_pool():
    global _db_pool
    if _db_pool is not None:
        try:
            _db_pool.closeall()
        except Exception:
            pass
        _db_pool = None

@contextmanager
def get_db_connection(db_name, db_user, db_password, db_host, db_port):
    try:
        import psycopg2
    except ImportError:
        raise ImportError("psycopg2 is not installed")

    pool = _get_or_create_pool(psycopg2, db_name, db_user, db_password, db_host, db_port)
    conn = None
    is_pooled = False

    if pool is not None:
        try:
            conn = pool.getconn()
            is_pooled = True
        except Exception:
            conn = None

    if conn is None:
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host,
            port=db_port
        )

    try:
        yield conn
    finally:
        if is_pooled and pool is not None:
            try:
                pool.putconn(conn)
            except Exception:
                pass
        else:
            try:
                conn.close()
            except Exception:
                pass

def save_drift_to_db(drift_results: list):
    if not drift_results:
        return

    db_user = os.environ.get("DB_USER")
    db_password = os.environ.get("DB_PASSWORD")
    db_name = os.environ.get("DB_NAME", "driftwatch")
    db_host = os.environ.get("DB_HOST", "localhost")
    db_port = os.environ.get("DB_PORT", "5432")

    if not db_user or not db_password:
        print("⚠️ DB_USER or DB_PASSWORD not found in environment. Skipping database save.")
        return

    try:
        import psycopg2
    except ImportError:
        print("⚠️ PostgreSQL credentials provided, but 'psycopg2' is not installed. Run 'pip install driftwatch-cli[postgres]' to enable database logging.")
        return

    try:
        with get_db_connection(db_name, db_user, db_password, db_host, db_port) as conn:
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

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_drift_resource_id ON drift_history(resource_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_drift_scan_time ON drift_history(scan_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_drift_type ON drift_history(drift_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_drift_resource_type ON drift_history(resource_type)')

            for r in drift_results:
                diff_json = json.dumps(r.diff) if r.diff else "{}"
                cursor.execute('''
                    INSERT INTO drift_history (resource_type, resource_id, resource_name, drift_type, diff_details)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (r.resource_type, r.resource_id, r.resource_name, r.drift_type.value, diff_json))

            conn.commit()
            cursor.close()
            print("✅ Drift history saved to PostgreSQL database.")
    except Exception as e:
        print(f"❌ Database error: {e}")
