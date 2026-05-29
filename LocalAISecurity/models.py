import torch.nn as nn


class SecurityBehaviorCNN(nn.Module):
    """安全行为识别CNN — 32维进程特征 → 4分类（正常/流氓/木马/勒索）"""
    def __init__(self, dropout=0.3):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 16, 3, padding=1)
        self.bn1 = nn.BatchNorm1d(16)
        self.conv2 = nn.Conv1d(16, 32, 3, padding=1)
        self.bn2 = nn.BatchNorm1d(32)
        self.pool = nn.MaxPool1d(2)
        self.fc1 = nn.Linear(32 * 16, 64)
        self.fc2 = nn.Linear(64, 4)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        x = nn.functional.relu(self.bn1(self.conv1(x)))
        x = nn.functional.relu(self.bn2(self.conv2(x)))
        x = self.pool(x)
        x = x.view(x.size(0), -1)
        x = self.dropout(nn.functional.relu(self.fc1(x)))
        x = self.fc2(x)
        return x


class FileClassifyCNN(nn.Module):
    """C盘文件分类CNN — 18维文件特征 → 5分类（系统核心/软件缓存/可删/冗余/用户重要）"""
    def __init__(self, dropout=0.3):
        super().__init__()
        self.conv1 = nn.Conv1d(1, 16, 3, padding=1)
        self.bn1 = nn.BatchNorm1d(16)
        self.conv2 = nn.Conv1d(16, 32, 3, padding=1)
        self.bn2 = nn.BatchNorm1d(32)
        self.conv3 = nn.Conv1d(32, 64, 3, padding=1)
        self.bn3 = nn.BatchNorm1d(64)
        self.pool = nn.MaxPool1d(2)
        self.fusion = nn.Linear(64 * 9, 128)
        self.fc = nn.Linear(128, 5)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        x = nn.functional.relu(self.bn1(self.conv1(x)))
        x = nn.functional.relu(self.bn2(self.conv2(x)))
        x = nn.functional.relu(self.bn3(self.conv3(x)))
        x = self.pool(x)
        x = x.view(x.size(0), -1)
        x = self.dropout(nn.functional.relu(self.fusion(x)))
        x = self.fc(x)
        return x
