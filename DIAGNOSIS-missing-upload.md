# 诊断：截图里那条上传，数据库里为什么找不到

日期：2026-09-21
对象：`POST /api/v1/files` 返回 `201`，但该 `file_id` 在本机任何数据库中都不存在

> **本文档已为公开发布脱敏。** 报告涉及的凭据 —— 密钥明文片段、`key_id`
> 与它的 SHA-256 片段 —— 一律替换为占位符（`sk_<redacted>`、
> `key_xxxxxxxxxxxx`）。文中的命令示例因此**不能直接复制执行**，
> 需要先用 `scripts.keys list` 查出你自己的 `key_id`。
> 脱敏不改变任何结论；所有判定所依据的证据都保留在原处。

---

## 一、结论

**截图里那条记录从未写进本机这个数据库。**

不是被软删除、也不是被清理器硬删除 —— 是**从来没有落过盘**。它没有任何痕迹：

| 检查位置 | 结果 |
|---|---|
| `files` 表按 `file_id` 精确查 | 0 行 |
| `files` 表按 `file_id` 前缀 `V5orJ` 查 | 0 行 |
| `files` 表按 `sha256` 前缀 `2b93da0e` 查 | 0 行 |
| `files` 表按 `size_bytes = 14705` 查 | 0 行 |
| `files` 表 10 KB–20 KB 区间（全表） | **一条都没有** |
| `audit_log` 按 `file_id` 查 | 0 行 |
| `data/blobs/2b/` 目录 | 不存在 |
| `data/thumbs/` 下 `2b93da0e*` | 不存在 |
| **`host.db` 原始字节里 grep `V5orJ` / `2b93da0e` / `Clipboard_Screenshot`** | **0 次** |

最后一项是关键：SQLite 硬删除（`purge_hashes` 用的是 `DELETE`）不会擦除页内字节，
被删的行会留在空闲页里直到 `VACUUM`。搜不到，说明它**没被写过**，而不是被删过。

**方法本身经过对照验证**（否则"搜不到"毫无意义）：

```
probe.txt      count=1        ← 我 13:53 上传的探针
photo.png      count=60       ← 脚本上传
B6xCj          count=3        ← 13:48:26 那条
key_           count=1239     ← 主键
```

---

## 二、确认"看的确实是同一个库"

这一层必须先钉死，否则上面所有"找不到"都可能只是查错了文件。

1. `app/config.py`：`data_dir: Path = PROJECT_ROOT / "data"` —— **绝对路径**，
   不受启动时工作目录影响。`db_path` 由它派生。
2. 全盘扫了 **1870 个** `.db/.sqlite` 文件（项目、`D:\tmp`、`%TEMP%`），
   带 `files` 表的全部列出，目标记录无一命中。
3. 运行中的服务（`127.0.0.1:8000`，PID 26412）**实测写入的就是这个库**：
   我在 13:53:09 上传了一个探针文件，`files` 行数从 230 → 231，
   新行 `ZQDhb4gMy1eVzMeAwbClpw` 落在 `data/host.db`，mtime 同步更新。
4. 该库自 10:49 起未被替换：审计流从 **11:03:27 连续到今天**，
   中间只有请求空档（最长一段 `12:53:40 → 13:41:12`，47.5 分钟无请求），
   没有"换库"留下的断点。

---

## 三、真实原因：两个我自己引入的缺陷

### 缺陷 A（严重）：README 里写着**一把真实可用的密钥**

`README.md:610` 的"示例输出"块里放的不是占位符，而是**明文密钥**
（下面已打码；本文档刻意不写出完整值，理由见本节末）：

```
  key_id : key_xxxxxxxxxxxx
  api key: sk_<redacted>         ← 完整值曾写在 README 里，已移除
```

验证方式：对 README 里那串明文算 SHA-256，得 `e92c4afc…`（完整值已脱敏），
与 `api_keys` 表里 `key_xxxxxxxxxxxx` 的 `key_hash` **完全一致** ——
也就是说它不是示例，是一把真能通过校验的密钥。

后果：任何读到这份 README 的人（包括本机上的你）都拿到了一把能用的凭据。
审计日志证实：`key_xxxxxxxxxxxx` 在 13:41–13:48 之间被用来上传了 5 次 ——
**你照 README 操作时，Authorize 用的正是这把泄露的密钥，而且它成功了。**

> **更正（本文档初版把这一点写错了，必须改掉）**
>
> 初版写的是「`README.md` 是**受版本控制**的文件（`git check-ignore` 未命中）」。
> 这是错的。`D:\ImageAndTextHosting` **根本不是 git 仓库**：
> `git rev-parse --is-inside-work-tree` 和 `git status` 都返回
> `fatal: not a git repository (or any of the parent directories)`，
> 没有任何父目录是仓库。当时那条 `git check-ignore -v README.md`
> 实际以 **exit 128** 失败、且无任何输出 —— 我把「命令没跑起来」
> 读成了「答案是否」。
>
> 这个更正把严重性**降了一档**：密钥从未被提交、从未被推送。
> 暴露面是**本机这份文件本身**，以及任何会整目录复制的途径
> （备份、同步盘、打包发人）。它依然是泄露，但性质不是「已经进了远端历史」。
> 项目里确实有 `.gitignore`（为将来 `git init` 准备，已正确忽略
> `data/`、`.env`、`*.key`），只是仓库还没初始化。

> 本文档不写出完整明文，是为了在它**将来被提交时**不重蹈覆辙。
> 写这份报告时我一度把完整密钥贴了进来（三处），等于把同一个错误又犯了一遍 ——
> 可见"从真实终端复制粘贴"这个习惯有多顽固。要复现验证，
> 从 `api_keys` 表按 `key_id` 取 `key_hash`，与 README 修订前的版本对照即可
> （本机没有 git 历史，见上文更正）。

### 缺陷 B（体验）：`mintkey` 的参数含义没写清楚

13:38:27 / 13:38:41 / 13:38:58，`api_keys` 表里连增三条记录，
`name` 字段全都是那串 `sk_<redacted>`（与缺陷 A 同一把密钥）。

即：**把 README 里那把示例密钥当成 `label` 参数传给了 `mintkey`**，连传三次。
这三把密钥各 0 条审计记录 —— 从没用过，纯粹是被"每跑一次就多一把"坑出来的。

README 原文只写了「type a label」，紧接着就是示例输出块，没有任何一句说明
"参数是给你自己记账用的名字，不是密钥"。这个歧义是文档造成的，不是操作失误。

---

## 四、已经改了什么

| 文件 | 改动 |
|---|---|
| `README.md` | 删掉真实密钥，换成 `key_xxxxxxxxxxxx` / `sk_<43 随机字符>` 占位符 |
| `README.md` | 新增说明：参数是 **label**；把 `sk_...` 当 label 传只会再造新密钥，不会导入任何东西 |
| `README.md` | 新增警告：**不要把真实密钥写进会被别人看到的文件**，并说明本文件曾经犯过这个错（措辞已按上文更正调整：本机并非 git 仓库） |
| `README.md` | `/docs` 走查新增引用块：**`201` 不等于记录还在**，要用 `GET /api/v1/files/{id}` 复核；浏览器标签页里的历史响应不会自己失效 |
| `README.md` | 新增 `### Rotating a leaked key`：吊销**下一个请求即生效、无需重启**；附实测的 `200 → disable → 401` 输出 |
| `README.md` | 目录树补 `scripts/keys.py` |
| `MANUAL_TESTING.md` | 故障排查表新增 2 行（"201 但后来 404"、"mintkey 之后多出一堆同名记录"） |
| `MANUAL_TESTING.md` | 验证清单新增 1 项：上传后**立刻**取元数据确认 200 |
| `app/db.py` | 新增 `list_api_keys()`、`set_key_enabled()`、`audit_rows_for_key()`、`delete_unused_key()` —— 原来**没有任何吊销入口** |
| `scripts/keys.py` | **新增**：`list` / `disable` / `enable` / `purge`，支持按 `key_id` 或 `--label` |
| `scripts/mintkey.py` | 标签以 `sk_` 开头时**拒绝执行**（这正是上面连错三次的操作），`--force` 可覆盖 |
| `.vscode/tasks.json` | 新增 `maintenance: list API keys`、`maintenance: revoke API key`（14 tasks / 2 inputs） |
| `tests/test_db.py` | 新增 10 项：吊销即时且可逆、吊销保留行、未知 id 返回 False、列表倒序且不含 hash、同秒创建排序、purge 只删未用过的、purge 拒绝有历史的、purge 拒绝未知 id、先 disable 再 purge、审计计数按 key 隔离 |

**为什么顺手补了吊销工具**：诊断发现"能铸不能销" —— 唯一的办法是手开 sqlite3。
凭据无法吊销就等于不可轮换，而"以后再说"实际会变成"永远不做"。

`disable` 与 `purge` 刻意分开：前者保留行（审计仍能解析 `key_id`），
后者只删**从未被审计引用**的密钥。守卫写在 SQL 里而不是先查后删：

```sql
DELETE FROM api_keys WHERE key_id = ?
  AND NOT EXISTS (SELECT 1 FROM audit_log WHERE key_id = ?)
```

被拒绝时会出声，不静默跳过：

```
$ python -m scripts.keys purge key_xxxxxxxxxxxx
  kept:      key_xxxxxxxxxxxx  (12 audit row(s) reference it -- disable it instead)
```

回归：`pytest 200 passed`（190 → 200；后随清理器改动增至 **206**）；
4 个 `.vscode` JSONC 全部解析通过；
README 代码围栏配平；新增的每条命令、**每个退出码**都实跑过
（无参数 → 2、坏 id → 1、坏标签 → 2、`mintkey sk_` → 2、`--label` 多命中 → 全部停用、
`enable` → 成功翻转、`purge` 有历史 → 被拒）。

---

## 五、现在怎么复测（3 分钟）

```bash
# 1. 铸一把自己的密钥（label 随便起，比如 dev）
.venv\Scripts\python.exe -m scripts.mintkey dev

# 2. 记下打印出的 sk_...，在 /docs 右上角 Authorize 里粘贴（只粘密钥本身）

# 3. POST /api/v1/files → Try it out → 选一个文件 → ttl / retain 都留空 → Execute
#    期望 201

# 4. 立刻用返回的 file_id 复核 —— 这一步才是"真的存下来了"的证据
curl --noproxy '*' http://127.0.0.1:8000/api/v1/files/<file_id> \
     -H "Authorization: Bearer <你的 sk_...>"
#    期望 200；404 说明记录已经不在了
```

> `--noproxy '*'` 不是装饰：本机环境设了 `HTTP_PROXY` 但没设 `NO_PROXY`，
> `curl` 和 `httpx` 默认都会把回环流量送去代理。

---

## 六、遗留

**已处理**

- 3 把垃圾密钥（13:38 那三把，label 是密钥串，0 次使用）—— **已 `disable`**。
  它们同样**可以 `purge`**（无审计引用），那会顺带把泄露的密钥串从 `name`
  列里彻底去掉。这一步是不可逆的，留给你决定 —— 用 `key_id` 指定即可，
  不必把那个密钥串再打一遍：

  ```bash
  # 先用 `scripts.keys list` 查出这三把的 key_id（此处已脱敏），再：
  .venv\Scripts\python.exe -m scripts.keys purge <key_id> <key_id> <key_id>
  ```

- 探针密钥 `key_xxxxxxxxxxxx`（`diag-probe`）—— **已 `disable`**，
  并且正是用它验证了"吊销对运行中的服务立即生效"（`200 → 401`，未重启）。
- 我在验证新工具时造的 3 把测试密钥 —— **已 `purge`**，`api_keys` 回到 53 行。

**等你决定**

- **泄露的 `key_xxxxxxxxxxxx` 仍然有效。** README 已改成占位符，但密钥本身没作废 ——
  因为你当前 `/docs` 会话正在用它。若这份仓库曾经推送过、或给过别人，
  应当作废并另铸一把：

  ```bash
  .venv\Scripts\python.exe -m scripts.keys disable key_xxxxxxxxxxxx
  ```

  作废后当前 `/docs` 的 Authorize 会立即失效，重新铸一把并粘贴即可。
- **我的探针记录** `ZQDhb4gMy1eVzMeAwbClpw`（30 B，`probe.txt`）还在 `files` 表里。
  没删，是因为它和这个库里另外 230 条脚本产物性质相同，单独删它没有意义。
- **开发库本身很脏**：`files` 里 230+ 条几乎全是脚本产物（全表只有 8 种不同
  内容，`dup1.png`/`dup2.png` 各 88 条），`api_keys` 53 把（4 把已停用）。
  想清干净的话，最省事的是**停服后重置 `data/`**，再铸一把新密钥 ——
  这一步是破坏性的，需要你确认，我没有动。

---

## 七、后续更正与补充

写完之后复查，发现本文档有两处**我自己写错的事实**，以及一个独立的新发现。

### 更正 1：本机不是 git 仓库（第三节已就地改正）

初版说 `README.md`「**受版本控制**」，依据是 `git check-ignore` 没命中。
实际上 `git rev-parse --is-inside-work-tree` 和 `git status` 都返回
`fatal: not a git repository` —— 那条 `git check-ignore` 是以 **exit 128
失败**、输出为空，我把「命令没跑起来」读成了「答案是否」。

> **教训**：空输出 + 非零退出码 ≠ 否。任何用来当证据的命令，
> 都要先确认它**真的跑成功了**，再看它的输出。`2>/dev/null` 会把
> 这类失败藏得干干净净。

严重性因此**降一档**：密钥从未提交、从未推送，暴露面是本机文件本身。

### 更正 2：`data_dir` 可以被环境变量覆盖

我一度判断「没有环境变量能改 `data_dir`，它写死成 `PROJECT_ROOT / "data"`」。
错的。`settings.data_dir` 是 pydantic 字段，`BaseSettings` 会自动把
**`DATA_DIR`** 映射上去（隐式、大小写不敏感），`tests/conftest.py` 和
`scripts/_isolate.py` 都靠它做隔离。我当时用小写 `data_dir` 去 grep，
自然漏掉了大写形式。

> **教训**：pydantic-settings 的字段可以用 `SCREAMING_CASE` 环境变量覆盖，
> 而代码里**搜不到** `os.environ`。判断「某配置能否被覆盖」时，
> 要搜字段名的大写形式，或直接读 `BaseSettings` 的字段表。

### 新发现：`data/host.db` 被外部进程反复还原

验证清理器改动时，我插入的临时记录**三次**在几分钟内消失，且每次计数都
**退回同一个旧值**（`231` 行 / `184` live）。排查过程与证据：

| 检查 | 结果 |
|---|---|
| 90 秒看门狗轮询（每 5 秒一次） | 记录**稳定存活**，无自发删除 |
| `pytest` 前后对比真实库 | 计数**完全不变** → 测试隔离有效，被排除 |
| 全库搜 `DELETE FROM files` | 只有 `purge_hashes`，且带 `deleted_at IS NOT NULL` 守卫，不可能删存活行 |
| `app/main.py` 后台任务 | 无（无 lifespan 清扫、无定时器） |
| `data/host.db` 的 `mtime` | `14:52:31` —— **不是我任何命令的写入时刻** |
| `data/host.db` 的 `ctime` | `2026-09-18`，**未变** → 原地改写，不是被整体替换 |
| 新写的 blob | **仍在盘上**，变成孤儿 |

结论：有一个**外部进程**在把 `host.db` 还原成旧快照。
行没了、但快照之后新写的 blob 还在 —— 于是产生孤儿。
我无法从沙箱内确认是哪个进程（`schtasks` 被安全策略拦截，也无法审计
其他进程的文件句柄）。**需要你在本机确认**：是否有备份/同步/还原类工具
（或另一个会话）在动 `D:\ImageAndTextHosting\data\`。

这也解释了本会话更早的一个谜题：为什么某次 `201` 上传的记录「查无此记录」——
如果 `host.db` 被反复还原，那么任何**在两次还原之间**写入的记录都会这样消失，
而 `data/blobs/` 里的字节还在。这与第四节「`201` 只说明写成功过」是同一类现象，
只是这次有了外部原因。

**由此新增的能力**：`scripts/verify_blobs.py` 增加了第 3 项检查
（孤儿 blob）。这类字节对清理器**结构性不可见**——孤儿回收是从 `files`
表出发找「无存活引用的 hash」，没有行就找不到——所以必须有一个从磁盘
反向比对的检查，否则它们占着磁盘且没有任何记录。

**收尾**：本次会话为验证而造的所有记录与 blob 均已清理，
`verify_blobs.py` 三项检查全 0，`pytest 206 passed`。
