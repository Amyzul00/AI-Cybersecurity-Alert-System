import pandas as pd

# Load the parquet file from the data folder
df = pd.read_parquet("data/DDoS-Friday-no-metadata.parquet")

print("Dataset loaded successfully from data folder!")
print(f"Total rows and columns: {df.shape}")
print(df.head())