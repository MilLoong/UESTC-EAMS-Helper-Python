# UESTC 教务系统助手 —— Python 脚本

**UESTC 教务系统助手**，**Python 脚本**，支持 **课表信息、考试时间、考试成绩** 查询，**2026 最新**

由于以前的 **关于 课表 的 爬虫项目** 基本都用不了了，貌似是 你电 更新了一个 **二次验证**？所以我重新写了一个

>  本项目 是 **提供获取 课表信息、考试时间、考试成绩 的 JSON** 的 方法
>
> 至少截止目前（**2026/5/25**）是能用的，要是不能用可以在 **Issue** 提一下，我看看能不能解决（
>
> 需要注意的是 **不要过多地登录 统一身份认证**，不然会 **冻结账号**，所以我把能用的 **Cookie** 保存到本地了，下次使用就大概率 **不用重新登录**

## 环境要求

- Python **3.10+**
- 依赖：

```bash
pip install -r requirements.txt
```

## 快速开始

在脚本所在目录运行：

```bash
python uestc_eams_helper.py
```

1. **首次运行**：按提示输入 **学号、密码**（统一身份认证）。
2. **之后运行**：自动读取同目录下的 `session_cookies.json`，一般可 **免输密码**。
3. **选择功能**：**课表 / 成绩 / 考试 / 全部**

查询结果会打印到终端，并写入当前目录 JSON 文件：

| 功能 | 文件 |
|------|------|
| 课表 | `timetable.json` |
| 成绩 | `grades.json` |
| 考试 | `exam.json` |
| 全部 | `all.json` |

登录成功后，Cookie 会写入**当前目录**的 `session_cookies.json`。上述 JSON 均在 `.gitignore` 中，**请勿提交到 Git**。

若 Cookie 过期，脚本会自动删除 `session_cookies.json` 并重新登录（最多重试一次）；也可手动删除该文件后重跑。

## 非交互 / 自动化

无 `session_cookies.json` 且无法 stdin 交互时，需设置：

- `UESTC_USERNAME` / `UESTC_PASSWORD` — 学号、密码
- `UESTC_EAMSAPP_MODE` — `课表` / `成绩` / `考试` / `全部`
- `UESTC_REAUTH_DYNAMIC_CODE` — 短信二次认证验证码（若需要）

示例（PowerShell）：

```powershell
$env:UESTC_USERNAME = "学号"
$env:UESTC_PASSWORD = "密码"
$env:UESTC_EAMSAPP_MODE = "课表"
python uestc_eams_helper.py
```

## 可选环境变量

| 变量 | 作用 |
|------|------|
| `PRETTY_JSON=0` | 终端输出改为单行紧凑 JSON（默认带缩进） |
| `UESTC_EAMSAPP_MODE` | 课表 / 成绩 / 考试 / 全部 |
| `UESTC_FRESH_LOGIN=1` | 忽略快照，强制重新登录 |
| `UESTC_SKIP_SESSION_SNAPSHOT=1` | 不读写 `session_cookies.json` |
| `UESTC_DISABLE_COOKIE_RETRY=1` | 禁用 Cookie 失效后自动清缓存重登 |
| `UESTC_REAUTH_TRUST_DEVICE=1` | 二次认证时信任设备 |
| `UESTC_EAMSAPP_SEMESTER` / `WEEK` 等 | 课表、考试参数（一般可省略） |

## 后续计划

- 基于 **本脚本导出的 JSON**，做 **安卓端 App** 展示（**课表 / 成绩 / 考试分栏、样式优化** 等）
- 有想法可先开 **Issue** 讨论，不必一开始就写代码

## 参与开发（欢迎 Fork）

本仓库当前是 **Python 脚本**；若你是 **UESTC 在校生**，有兴趣参与 **安卓 App** 或脚本改进，欢迎 Fork。

### 建议流程

1. 在 **GitHub** 点击 **Fork**，得到你自己的 **副本仓库**。
2. **Clone 到本地** 开发；勿提交 `session_cookies.json`、`timetable.json` 等含个人信息的文件。
3. 较大改动前先发 **Issue**（简述技术栈、界面思路），避免方向差太远。
4. 完成后向本仓库提 **Pull Request**，或在 **Issue** 里继续讨论。

### 可参考的方向

- **读取 / 展示** `timetable.json`、`grades.json`、`exam.json`
- **课表周视图、教室 / 教师信息、成绩与考试** 分 tab
- 与现有 **登录 / 缓存 流程** 衔接（须遵守学校相关规定）

**维护者** 业余维护，**课业优先**，回复可能不及时。

## 许可与免责

仅供学习与个人便利使用。请遵守学校相关规定，勿用于爬取、转发他人数据或任何违规用途。作者不对使用后果负责。
