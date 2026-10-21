# 当前项目进度 Summary

目前已经完成了 CVE → CWE 项目的基础环境和数据准备工作。

## 已完成内容

- 已在 Debian VM 上配置 Python 3.13.5
- 已创建 Python 虚拟环境 `.venv`
- 已安装项目需要的主要 Python libraries
- 已建立共享数据目录 `/home/data/`
- 已下载并保存 NVD 2023–2025 CVE 数据
- 已下载并保存 MITRE CWE 数据
- 已完成 CWE 数据清洗
- 已完成 CVE 数据清洗

## 当前数据情况

清洗后的 CWE 数据：

```text
/home/data/processed/cwe_clean.csv