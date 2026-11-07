import os
import warnings
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import RandomOverSampler

warnings.filterwarnings('ignore')

# -------------------------------------------------------------------
# 1. CONFIGURATION, PATHS & DEVICE SETUP
# -------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "DDoS-Friday-no-metadata.parquet")

SEQ_LEN = 5          # Temporal sequence window size
EPOCHS = 30          # Training epochs for loss convergence
BATCH_SIZE = 32      # Batch size for generalization
LEARNING_RATE = 0.001

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[+] Using device: {device}")

# -------------------------------------------------------------------
# 2. LOAD & CLEAN DATASET (USING TARGET FEATURES)
# -------------------------------------------------------------------
if not os.path.exists(DATA_PATH):
    fallback_path = os.path.join(BASE_DIR, "data", "cicids2017.csv")
    if os.path.exists(fallback_path):
        DATA_PATH = fallback_path
        print(f"[!] Parquet dataset not found. Using CSV fallback: {DATA_PATH}")
    else:
        raise FileNotFoundError(f"[!] Dataset file not found at: {DATA_PATH}")

print(f"[+] Loading dataset from: {DATA_PATH}...")
if DATA_PATH.endswith('.parquet'):
    df = pd.read_parquet(DATA_PATH)
else:
    df = pd.read_csv(DATA_PATH)

# Clean column names
df.columns = df.columns.str.strip().str.replace('"', '').str.replace("'", "")

target_features = [
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Fwd Packet Length Max',
    'Flow Bytes/s',
    'Flow Packets/s'
]

column_mapping = {}
for feat in target_features:
    for col in df.columns:
        if col.lower() == feat.lower():
            column_mapping[col] = feat
            break

df = df.rename(columns=column_mapping)
matched_features = list(column_mapping.values())

label_col = [c for c in df.columns if c.lower() == 'label']
if not label_col:
    raise KeyError("[!] 'Label' column not found in dataset.")

LABEL_NAME = label_col[0]
cols_to_use = matched_features + [LABEL_NAME]

df_clean = df[cols_to_use].replace([np.inf, -np.inf], np.nan).dropna()
print(f"[+] Dataset cleaned successfully: {len(df_clean)} records.")

X = df_clean[matched_features].values
y = df_clean[LABEL_NAME].values

# Encode labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)

# Scale features using MinMaxScaler
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Handle class imbalance using RandomOverSampler
ros = RandomOverSampler(random_state=42)
X_resampled, y_resampled = ros.fit_resample(X_scaled, y_encoded)
print(f"[+] Oversampled dataset from {len(X_scaled)} to {len(X_resampled)} samples.")

# -------------------------------------------------------------------
# 3. CREATE SLIDING WINDOW SEQUENCES
# -------------------------------------------------------------------
def create_sequences(features, labels, seq_len=5):
    xs, ys = [], []
    for i in range(len(features) - seq_len):
        xs.append(features[i:i + seq_len])
        ys.append(labels[i + seq_len])
    return np.array(xs), np.array(ys)

print(f"[+] Constructing temporal sequence data (Window Size = {SEQ_LEN})...")
X_seq, y_seq = create_sequences(X_resampled, y_resampled, seq_len=SEQ_LEN)

X_train, X_test, y_train, y_test = train_test_split(
    X_seq, y_seq, test_size=0.2, random_state=42, stratify=y_seq
)

train_dataset = TensorDataset(
    torch.tensor(X_train, dtype=torch.float32), 
    torch.tensor(y_train, dtype=torch.long)
)
test_dataset = TensorDataset(
    torch.tensor(X_test, dtype=torch.float32), 
    torch.tensor(y_test, dtype=torch.long)
)

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

# Compute class weights
class_weights_np = compute_class_weight(
    class_weight='balanced',
    classes=np.unique(y_train),
    y=y_train
)
adjusted_weights = np.sqrt(class_weights_np)
class_weights_tensor = torch.tensor(adjusted_weights, dtype=torch.float32).to(device)

# -------------------------------------------------------------------
# 4. DEEP LSTM ARCHITECTURE
# -------------------------------------------------------------------
class DeepLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes):
        super(DeepLSTM, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        
        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2 if num_layers > 1 else 0
        )
        
        self.fc1 = nn.Linear(hidden_size, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, num_classes)

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
        
        out, _ = self.lstm(x, (h0, c0))
        out = self.fc1(out[:, -1, :])
        out = self.relu(out)
        out = self.fc2(out)
        return out

input_size = len(matched_features)
hidden_size = 64
num_layers = 2
num_classes = len(label_encoder.classes_)

model = DeepLSTM(input_size, hidden_size, num_layers, num_classes).to(device)

criterion = nn.CrossEntropyLoss(weight=class_weights_tensor)
optimizer = optim.Adam(model.parameters(), lr=LEARNING_RATE, weight_decay=1e-4)
scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', factor=0.5, patience=3)

# -------------------------------------------------------------------
# 5. TRAINING LOOP
# -------------------------------------------------------------------
print(f"\n[+] Starting Deep LSTM model training for {EPOCHS} epochs...")

for epoch in range(EPOCHS):
    model.train()
    total_loss = 0
    for X_batch, y_batch in train_loader:
        X_batch, y_batch = X_batch.to(device), y_batch.to(device)
        
        optimizer.zero_grad()
        outputs = model(X_batch)
        loss = criterion(outputs, y_batch)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        
    avg_loss = total_loss / len(train_loader)
    scheduler.step(avg_loss)
    print(f"Epoch [{epoch+1}/{EPOCHS}] - Loss: {avg_loss:.4f}")

# -------------------------------------------------------------------
# 6. EVALUATION
# -------------------------------------------------------------------
print("\n[+] Evaluating model performance on Test Set...")
model.eval()
all_preds = []
all_targets = []

with torch.no_grad():
    for X_batch, y_batch in test_loader:
        X_batch = X_batch.to(device)
        outputs = model(X_batch)
        preds = torch.argmax(outputs, dim=1).cpu().numpy()
        all_preds.extend(preds)
        all_targets.extend(y_batch.numpy())

print("\n--- Confusion Matrix ---")
print(confusion_matrix(all_targets, all_preds))

print("\n--- Classification Report ---")
print(classification_report(all_targets, all_preds, target_names=label_encoder.classes_))

# -------------------------------------------------------------------
# 7. SAVE ARTIFACTS
# -------------------------------------------------------------------
model_path = os.path.join(BASE_DIR, 'model_lstm.pth')
scaler_path = os.path.join(BASE_DIR, 'scaler_lstm.pkl')
encoder_path = os.path.join(BASE_DIR, 'label_encoder.pkl')
features_path = os.path.join(BASE_DIR, 'features.pkl')

torch.save(model.state_dict(), model_path)
joblib.dump(scaler, scaler_path)
joblib.dump(label_encoder, encoder_path)
joblib.dump(matched_features, features_path)

print("\n[✓] Training Complete!")
print(f"    - Model saved to         : {model_path}")
print(f"    - Scaler saved to        : {scaler_path}")
print(f"    - Label Encoder saved to : {encoder_path}")
print(f"    - Features saved to      : {features_path}")