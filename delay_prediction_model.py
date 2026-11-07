import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
import joblib

def train_delay_model():
    # 1. Contoh Data Sintetik (Gantikan dengan data sebenar anda)
    data = pd.DataFrame({
        'hour': [7, 8, 9, 12, 17, 18, 21],
        'weather_code': [0, 1, 0, 0, 2, 1, 0], # 0: Cerah, 1: Hujan, 2: Ribut
        'delay_minutes': [2, 12, 5, 1, 15, 8, 0]
    })
    
    X = data[['hour', 'weather_code']]
    y = data['delay_minutes']
    
    # 2. Latih Model
    model = RandomForestRegressor(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # 3. Simpan Model
    joblib.dump(model, '../app/models/delay_model.pkl')
    print("Model kelewatan berjaya dilatih dan disimpan!")

if __name__ == "__main__":
    train_delay_model()

    