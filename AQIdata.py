import sqlite3
import os


BASE_DIR = r"C:\\Users\\tejas\\Python Projects\\Google Maps Projects\\Air Quality Google maps Webapp\\Air_Quality 3"
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

AIR_QUALITY_DB_PATH= os.path.join(DATA_DIR, "locations.db")

# Path to the air quality database

def read_stored_aqi():
    
    conn = sqlite3.connect(AIR_QUALITY_DB_PATH)
    c = conn.cursor()
    
    c.execute("SELECT name, latitude, longitude, response FROM air_quality_index")
    print(c.fetchall())
    


# Example usage
if __name__ == "__main__":
    read_stored_aqi()
