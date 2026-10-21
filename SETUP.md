# Python 开发环境配置

本项目运行在 Debian Linux 云端 VM 上，当前系统默认 Python 版本为 **Python 3.13.5**。

项目使用 Python 虚拟环境 `.venv`，避免直接修改系统 Python 环境。

---

## 1. 安装 Python 虚拟环境支持

Debian 13 默认使用 Python 3.13。

```bash
sudo apt update
sudo apt install -y python3.13-venv python3-pip
```

---

## 2. 进入项目目录

```bash
cd ~/cs410_project
```

---

## 3. 如果之前创建虚拟环境失败，先删除旧环境

```bash
rm -rf .venv
```

---

## 4. 创建 Python 虚拟环境

```bash
python3 -m venv .venv
```

---

## 5. 激活虚拟环境

```bash
source .venv/bin/activate
```

激活成功后，终端前面会显示：

```text
(.venv)
```

---

## 6. 检查 Python 版本和路径

```bash
python --version
which python
```

预期结果类似：

```text
Python 3.13.5
/home/feiyun/cs410_project/.venv/bin/python
```

Heather 的路径会类似：

```text
/home/heather/cs410_project/.venv/bin/python
```

---

## 7. 更新 pip

```bash
python -m pip install --upgrade pip
```

---

## 8. 安装项目依赖

### 数据清洗和数据处理

```bash
pip install \
  pandas \
  numpy \
  tqdm \
  python-dotenv \
  pyarrow
```

### Information Retrieval 和模型相关

```bash
pip install \
  scikit-learn \
  rank-bm25 \
  torch \
  sentence-transformers
```

### 后续 API 开发使用

如果后面需要建立 API：

```bash
pip install \
  fastapi \
  uvicorn
```

---

## 9. 测试环境是否安装成功

```bash
python -c "import pandas, numpy, sklearn, torch, sentence_transformers; print('Environment OK')"
```

如果输出：

```text
Environment OK
```

说明主要依赖已经安装成功。

---

## 10. 每次重新连接 VM 后激活环境

每次 SSH 或 VS Code Remote 重新连接后，都需要重新激活 `.venv`：

```bash
cd ~/cs410_project
source .venv/bin/activate
```

---

## 11. 退出虚拟环境

```bash
deactivate
```

---

# 项目共享数据目录

项目数据统一存放在：

```text
/home/data/
├── raw/
│   ├── cwe/
│   └── nvd/
├── processed/
├── embeddings/
└── results/
```

其中：

- `raw/`：原始下载数据，不修改
- `processed/`：清洗后的 CVE / CWE 数据
- `embeddings/`：后续 MiniLM 等模型生成的 embedding
- `results/`：模型评估结果和实验输出

---

# 当前主要数据文件

原始 CWE 数据：

```text
/home/data/raw/cwe/CWE_comprehensive_view.csv
```

原始 NVD CVE 数据：

```text
/home/data/raw/nvd/nvdcve-2.0-2023.json
/home/data/raw/nvd/nvdcve-2.0-2024.json
/home/data/raw/nvd/nvdcve-2.0-2025.json
```

清洗后的数据：

```text
/home/data/processed/cwe_clean.csv
/home/data/processed/cve_clean.csv
```

---

# 注意事项

- 不要使用 `sudo pip install`
- 不要使用 `--break-system-packages`
- 不要直接修改系统 Python 环境
- Feiyun 和 Heather 各自在自己的 Git repository 中创建自己的 `.venv`
- 两个人尽量保持相同的 Python 和 package 版本
- `/home/data/` 是共享数据目录
- Git repository 主要保存代码，不需要提交完整原始 dataset
