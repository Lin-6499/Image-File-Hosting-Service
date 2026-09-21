# 手动验证手册（Manual Testing Runbook）

本手册供你亲手逐条验证服务行为。所有命令均在 `D:\ImageAndTextHosting`
项目根目录下、Git Bash 中执行，且**每条都已实测通过**。

约定：

- 项目根目录：`D:\ImageAndTextHosting`（下文简写为「根目录」）
- Python 解释器：`.venv/Scripts/python.exe`（项目自带的虚拟环境，**不要用全局 python**）
- 服务地址：`http://127.0.0.1:8000`（与 `.env` 中 `BASE_URL` 一致）
- 每条 curl 后面括号里的「期望」就是该验证点的判定标准

> **重要前提：返回的链接端口取自 `.env` 的 `BASE_URL`。**
> 若你改用其它端口启动服务，返回的链接仍会指向 8000，`curl` 就会失败。
> 这不是缺陷，是配置漂移。手动验证请始终用 8000，或同步改 `.env`。

---

## 第 0 步：确认环境就绪

```bash
cd /d/ImageAndTextHosting
.venv/Scripts/python.exe -c "import fastapi, PIL, uvicorn; print('deps ok')"
```

期望输出 `deps ok`。

---

## 第 1 步：先跑一键演示（30 秒建立整体印象）

这一步不需要你手动做任何事，脚本会自己铸密钥、上传、验证、统计。

```bash
# 终端 A：启动服务
.venv/Scripts/python.exe -m scripts.dev
```

看到下面这样的横幅就说明起来了，**保持这个终端不要关**：

```
====================================================================
  Image & Text Hosting Service -- development server
====================================================================
  Base URL : http://127.0.0.1:8000
  Docs     : http://127.0.0.1:8000/docs
  ...
```

```bash
# 终端 B：跑演示
cd /d/ImageAndTextHosting
.venv/Scripts/python.exe -m scripts.demo
```

期望看到（实测输出）：

```
[1] health  : {'status': 'ok'}
[2] upload  : POST /api/v1/files  (4286 bytes)
    file_id        : f72tHbZqqa1nvOj1dATxnQ
    mime / size    : image/png / 4286
    sha256         : 3acaca23e6182c2abd23dbae6d693d45...
    downloads in   : 300s
[3] signed download
    GET download_url   -> 200  (4286 bytes)
    purpose tampered   -> 403  (expected 403)
    forced expiry      -> 410  (expected 410)
[4] image display
    GET image_url      -> 200  image/webp  cache=public, max-age=31536000, immutable
[5] re-issue link
    POST /links        -> 200  expires_in=60s
[6] stats
    {'total_records': ..., 'live_records': ..., 'total_bytes': ...}
Demo complete. Open the image_url in a browser to view it.
```

**关键判据**：`purpose tampered -> 403` 和 `forced expiry -> 410` 这两行。
它们证明链接的时效性与权限绑定真实生效，而不是摆设。

---

## 第 2 步：铸造你自己的 API Key

演示脚本每次自己铸密钥，手动验证需要你持有一把。

```bash
# 终端 B
.venv/Scripts/python.exe -m scripts.mintkey manual-test
```

期望输出：

```
====================================================================
  key_id : key_xxxxxxxxxxxx
  api key: sk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
====================================================================
The plaintext key is shown once and stored only as a SHA-256 hash.
Store it now; it cannot be recovered later.
```

**把 `sk_` 开头那串复制下来**，下文用 `$KEY` 指代。先存进 shell 变量：

```bash
KEY=sk_把你复制的密钥粘贴到这里
```

> 明文密钥只显示这一次，库里只存 SHA-256。丢了就重新铸一把，无法找回。

---

## 第 3 步：准备测试素材

```bash
mkdir -p scratch

# 一张 800x480 的 PNG
.venv/Scripts/python.exe -c "
from PIL import Image, ImageDraw
img = Image.new('RGB', (800, 480), (28, 30, 40))
d = ImageDraw.Draw(img)
for i in range(0, 800, 40): d.line([(i,0),(i,480)], fill=(50,55,70))
for i in range(0, 480, 40): d.line([(0,i),(800,i)], fill=(50,55,70))
d.rectangle([60,60,740,420], outline=(120,180,255), width=4)
d.text((300,230), 'MANUAL TEST', fill=(230,235,245))
img.save('scratch/photo.png')
print('ok')
"

# 一个纯文本文件
printf 'hello from the hosting service\n' > scratch/notes.txt
```

---

## 第 4 步：健康检查与文档

```bash
curl -s http://127.0.0.1:8000/healthz   # 期望 {"status":"ok"}
curl -s http://127.0.0.1:8000/readyz    # 期望 {"status":"ready","storage_writable":true}
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/docs   # 期望 200
```

`/healthz` 与 `/readyz` 的区别值得注意：前者只说明进程活着，
后者额外验证了**存储目录可写**。磁盘满或挂载掉线时，`/healthz` 仍会返回
`ok` 而 `/readyz` 会失败——生产环境做存活探针要用后者。

---

## 第 5 步：鉴权边界

```bash
# 不带密钥（期望 401）
curl -s -X POST http://127.0.0.1:8000/api/v1/files -F "file=@scratch/notes.txt"

# 密钥无效（期望 401）
curl -s -X POST http://127.0.0.1:8000/api/v1/files \
  -H "Authorization: Bearer sk_not-a-real-key" -F "file=@scratch/notes.txt"

# 漏了 Bearer 前缀（期望 401）
curl -s -X POST http://127.0.0.1:8000/api/v1/files \
  -H "Authorization: $KEY" -F "file=@scratch/notes.txt"
```

三次都应返回 `{"error":{"code":"unauthorized",...}}` 且 HTTP 401。

---

## 第 6 步：核心链路——上传 → 下载 → 展示

```bash
# 上传，把响应存进变量
RESP=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files \
  -H "Authorization: Bearer $KEY" \
  -F "file=@scratch/photo.png" -F "ttl=300")

# 从响应里取出三个关键字段
DL=$(echo  "$RESP" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['download_url'])")
IMG=$(echo "$RESP" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['image_url'])")
FID=$(echo "$RESP" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['file_id'])")

echo "download_url = $DL"
echo "image_url    = $IMG"
echo "file_id      = $FID"
```

上传响应全文（实测；`file_id`、`sha256` 与签名值已脱敏）：

```json
{
    "file_id": "<redacted>",
    "mime_type": "image/png",
    "size_bytes": 3784,
    "sha256": "<redacted>",
    "is_image": true,
    "download_url": "http://127.0.0.1:8000/d/<file_id>?exp=1789957743&p=dl&sig=<redacted>",
    "download_expires_at": 1789957743,
    "download_expires_in": 300,
    "image_url": "http://127.0.0.1:8000/i/<file_id>/<sha8>.webp",
    "deduplicated": false,
    "created_at": 1789957443,
    "scan_status": "skipped",
    "scan_detail": null,
    "servable": true
}
```

注意 `download_url` 的三个查询参数——这就是时效性与权限绑定的全部机制：

| 参数 | 含义 |
|---|---|
| `exp` | 过期时间戳（Unix 秒） |
| `p` | 用途，`dl`=下载 / `img`=展示 |
| `sig` | 对 `file_id + exp + p` 的 HMAC-SHA256 |

**`p` 参与签名计算**，所以把 `dl` 改成 `img` 会让签名失效——这是第 7 步要验证的。

```bash
# 下载：字节应与原文件完全一致
curl -s -o scratch/downloaded.png -w 'HTTP %{http_code}  bytes=%{size_download}\n' "$DL"
cmp scratch/photo.png scratch/downloaded.png && echo "字节完全一致 ✓"

# 图片展示：默认给缩略图（webp，体积更小）
curl -s -D - -o /dev/null "$IMG" | grep -iE 'HTTP/|content-type|cache-control'
```

期望：

```
HTTP/1.1 200 OK
cache-control: public, max-age=31536000, immutable
content-type: image/webp
```

```bash
# 想要原图：把扩展名换成 .png
curl -s -D - -o /dev/null "${IMG%.webp}.png" | grep -iE 'HTTP/|content-type'
# 期望 content-type: image/png
```

```bash
# 下载链接带 attachment 头，浏览器会触发下载而非内联显示
curl -s -D - -o /dev/null "$DL" | grep -i 'content-disposition'
# 期望 content-disposition: attachment; filename="photo.png"
```

这两条响应头的差异就是「下载链接」与「展示链接」的语义分工：
`attachment` 强制下载，`image/webp` + `immutable` 让浏览器/CDN 长期缓存。

### 附：验证内容寻址不变量（`sha256` 必须能校验下载内容）

这一条容易被忽略，但它是**去重、完整性、不可猜测路径**三项能力的共同前提：
blob 的文件名必须等于其内容的 SHA-256。

而 EXIF 剥离会**重写**文件。若重写发生在 blob 落盘之后，文件就不再匹配自己的
文件名——服务返回的 `sha256` 无法校验下载内容，`size_bytes` 也会偏大。
下面用一张带 GPS 的 JPEG 来验证这个顺序是对的。

```bash
# 构造一张带 GPS 的 JPEG 并上传，然后核对三个数字
.venv/Scripts/python.exe -c "
import io, json, hashlib, urllib.request
from PIL import Image
from PIL.TiffImagePlugin import IFDRational

buf = io.BytesIO()
im = Image.new('RGB', (120, 90), (200, 60, 60))
exif = im.getexif(); gps = exif.get_ifd(0x8825)
gps[1]='N'; gps[2]=(IFDRational(39,1), IFDRational(54,1), IFDRational(26,1))
im.save(buf, format='JPEG', exif=exif)
raw = buf.getvalue()

KEY='$KEY'; BASE='http://127.0.0.1:8000'; b='----b'
body=(f'--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"geo.jpg\"\r\n'
      f'Content-Type: image/jpeg\r\n\r\n').encode()+raw+f'\r\n--{b}--\r\n'.encode()
up=json.load(urllib.request.urlopen(urllib.request.Request(BASE+'/api/v1/files', data=body,
    method='POST', headers={'Authorization':f'Bearer {KEY}',
    'Content-Type':f'multipart/form-data; boundary={b}'})))

dl = urllib.request.urlopen(up['download_url']).read()
print(f'  上传 {len(raw)}B  ->  存储并下发 {len(dl)}B  (剥离 EXIF 后变小)')
print('  size_bytes 与实际下载一致 :', up['size_bytes'] == len(dl))
print('  sha256 可校验下载内容     :', up['sha256'] == hashlib.sha256(dl).hexdigest())

im2 = Image.open(io.BytesIO(dl))
print('  GPS 已剥离                :', dict(im2.getexif().get_ifd(0x8825)) == {})
"
```

期望三项全为 `True`，且体积因剥离而变小：

```
  上传 910B  ->  存储并下发 822B  (剥离 EXIF 后变小)
  size_bytes 与实际下载一致 : True
  sha256 可校验下载内容     : True
  GPS 已剥离                : True
```

**两个性质必须同时成立**：隐私（GPS 没了）与完整性（哈希仍能校验）。
只验证前者会漏掉这类缺陷——本项目的历史版本正是如此：GPS 确实被剥掉了，
但 `sha256` 和 `size_bytes` 描述的是剥离**之前**的文件。

---

## 第 7 步：签名安全验证（本服务的安全核心）

这一步最值得亲手做。**每一条都必须被拒绝。**

```bash
echo "=== 篡改测试 ==="

# 1) 交换用途 dl -> img（签名会失配）
curl -s -o /dev/null -w 'purpose 交换        -> %{http_code}  (期望 403)\n' \
  "$(echo "$DL" | sed 's/p=dl/p=img/')"

# 2) 改掉签名最后一位
curl -s -o /dev/null -w '签名末位改掉      -> %{http_code}  (期望 403)\n' \
  "$(echo "$DL" | sed 's/\(sig=.*\).$/\1X/')"

# 3) 把过期时间改到过去
curl -s -o /dev/null -w 'exp 改成过去      -> %{http_code}  (期望 410)\n' \
  "$(echo "$DL" | sed 's/exp=[0-9]*/exp=1/')"

# 4) 整个签名换成垃圾
curl -s -o /dev/null -w '签名替换为垃圾    -> %{http_code}  (期望 403)\n' \
  "http://127.0.0.1:8000/d/$FID?exp=9999999999&p=dl&sig=deadbeef"

# 5) 未知 file_id
curl -s -o /dev/null -w '未知 file_id      -> %{http_code}  (期望 403)\n' \
  "http://127.0.0.1:8000/d/NOTAREALID?exp=9999999999&p=dl&sig=deadbeef"

# 6) 图片路由的 sha8 校验
curl -s -o /dev/null -w '图片 sha8 不匹配  -> %{http_code}  (期望 404)\n' \
  "http://127.0.0.1:8000/i/$FID/deadbeef.webp"
```

实测结果：

```
purpose 交换        -> 403  (期望 403)
签名末位改掉        -> 403  (期望 403)
exp 改成过去        -> 410  (期望 410)
签名替换为垃圾      -> 403  (期望 403)
未知 file_id        -> 403  (期望 403)
图片 sha8 不匹配    -> 404  (期望 404)
```

**为什么第 3 条是 410 而不是 403？** 这是刻意设计的顺序：先校验过期、
再校验签名。好处是快速失败，并且**不泄露「你猜的签名对不对」**。
若把两者顺序颠倒，攻击者就能用过期的链接当作签名预言机来爆破。

想反证「签名确实被校验、没有被过期分支短路」，做这个实验：

```bash
# exp 是未来（未过期），但签名是另一份载荷的签名 → 必须 403
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
import time
from app.config import settings
from app.signing import sign
fid='$FID'
future=int(time.time())+600
# 故意签一个错误载荷（purpose=img），却拿去当 dl 用
print(sign(fid, future, 'img', settings.secret_key))
"
# 把上面输出的签名填进去，exp 用 future，p 用 dl → 期望 403
```

---

## 第 8 步：链接续期与 TTL 钳制

```bash
# 重新签发一个 60 秒的下载链接
curl -s -X POST "http://127.0.0.1:8000/api/v1/files/$FID/links" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"ttl":60}' | .venv/Scripts/python.exe -m json.tool
```

期望：

```json
{
    "url": "http://127.0.0.1:8000/d/...&exp=...&p=dl&sig=...",
    "expires_at": 1789957543,
    "expires_in": 60,
    "purpose": "dl"
}
```

```bash
# 申请一个荒谬的超长 TTL，应被钳制到 MAX_TTL=604800（7 天）
curl -s -X POST "http://127.0.0.1:8000/api/v1/files/$FID/links" \
  -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"ttl":99999999}' \
  | .venv/Scripts/python.exe -c "import sys,json;print('expires_in =',json.load(sys.stdin)['expires_in'],'(期望 604800)')"
```

**为什么要钳制**：调用方（比如 Codex）可以随意传 `ttl`。若不设上限，
一次传参失误就可能签出十年有效的链接，而签名的优势在于「可失效」，
长期有效的签名等于把无状态的优势抵消掉了。

---

## 第 9 步：元数据、Markdown 嵌入、列表与统计

```bash
# 单文件元数据
curl -s "http://127.0.0.1:8000/api/v1/files/$FID" \
  -H "Authorization: Bearer $KEY" | .venv/Scripts/python.exe -m json.tool
```

期望（实测）：

```json
{
    "file_id": "2iqVHBIw7rwdv1eOh6YxmA",
    "sha256": "8b035b22a49d522bfa166773ad20d0bec8fa1f6de0ca00a4cd041555363598d5",
    "size_bytes": 3784,
    "mime_type": "image/png",
    "orig_name": "photo.png",
    "is_image": true,
    "width": 800,
    "height": 480,
    "uploader": "key_69b03eccde1c",
    "created_at": 1789957481,
    "expires_at": null,
    "scan_status": "skipped",
    "scan_detail": null,
    "scanned_at": null,
    "servable": true
}
```

`width`/`height` 是服务端解析出来的，不是客户端声明的——`is_image` 同理，
基于魔数字节判定，不信客户端 `Content-Type`。

```bash
# 直接可粘贴进 Markdown 的图片片段
curl -s "http://127.0.0.1:8000/api/v1/files/$FID/image" \
  -H "Authorization: Bearer $KEY" \
  | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['embedded_markdown'])"
# 期望： ![image](http://127.0.0.1:8000/i/<file_id>/<sha8>.webp)

# 列表
curl -s "http://127.0.0.1:8000/api/v1/files?limit=3" -H "Authorization: Bearer $KEY" \
  | .venv/Scripts/python.exe -m json.tool | head -30

# 统计
curl -s http://127.0.0.1:8000/api/v1/stats -H "Authorization: Bearer $KEY"
# 期望： {"total_records":..,"live_records":..,"total_bytes":..,"disk_usage_ratio":..}
```

---

## 第 10 步：内容去重

```bash
A=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/photo.png")
B=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/photo.png")

echo "$A" | .venv/Scripts/python.exe -c "import sys,json;d=json.load(sys.stdin);print('第1次 file_id=',d['file_id'],'deduplicated=',d['deduplicated'])"
echo "$B" | .venv/Scripts/python.exe -c "import sys,json;d=json.load(sys.stdin);print('第2次 file_id=',d['file_id'],'deduplicated=',d['deduplicated'])"
```

**判据有讲究，容易误读**：`deduplicated` 表示「该内容**已经存在于存储中**」，
而不是「这是本次会话的第 2 次上传」。

- 若这张图之前上传过，**第 1 次就会是 `true`**（我实测时就是这样）。
- 想看到干净的 `false → true` 对比，用一个从未上传过的**新**文件：

```bash
head -c 100000 /dev/urandom > scratch/unique.bin
C=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/unique.bin")
D=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/unique.bin")
echo "$C" | .venv/Scripts/python.exe -c "import sys,json;d=json.load(sys.stdin);print('首次 deduplicated=',d['deduplicated'],'(期望 False)')"
echo "$D" | .venv/Scripts/python.exe -c "import sys,json;d=json.load(sys.stdin);print('再次 deduplicated=',d['deduplicated'],'(期望 True)')"
```

两次的 `file_id` 必须不同——去重的是**字节**，不是记录。
每条上传记录有自己独立的生命周期（可单独删除、单独签链接）。

---

## 第 11 步：非图片文件

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/files \
  -H "Authorization: Bearer $KEY" -F "file=@scratch/notes.txt" \
  | .venv/Scripts/python.exe -c "
import sys,json; d=json.load(sys.stdin)
print('mime_type =',d['mime_type'])   # 期望 application/octet-stream
print('is_image  =',d['is_image'])    # 期望 False
print('image_url =',d['image_url'])   # 期望 None
"
```

期望 `application/octet-stream` / `False` / `None`。

**注意 `.txt` 得到的是 `application/octet-stream` 而非 `text/plain`**：
服务端只对「能识别出魔数的格式」给具体 MIME，其余一律用最保守的
`octet-stream`。这样下载时不会诱导浏览器把未知内容当 HTML 渲染——
配合 `X-Content-Type-Options: nosniff`，堵住了存储型 XSS 的一条常见路径。

---

## 第 12 步：软删除

```bash
RESP=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/notes.txt")
FID2=$(echo "$RESP" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['file_id'])")
DL2=$(echo  "$RESP" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['download_url'])")

curl -s -o /dev/null -w '删除前元数据    -> %{http_code}  (期望 200)\n' "http://127.0.0.1:8000/api/v1/files/$FID2" -H "Authorization: Bearer $KEY"
curl -s -w '\n' -X DELETE "http://127.0.0.1:8000/api/v1/files/$FID2" -H "Authorization: Bearer $KEY"
curl -s -o /dev/null -w '删除后元数据    -> %{http_code}  (期望 404)\n' "http://127.0.0.1:8000/api/v1/files/$FID2" -H "Authorization: Bearer $KEY"
curl -s -o /dev/null -w '删除后下载链接  -> %{http_code}  (期望 404)\n' "$DL2"
curl -s -o /dev/null -w '重复 DELETE     -> %{http_code}  (期望 404)\n' -X DELETE "http://127.0.0.1:8000/api/v1/files/$FID2" -H "Authorization: Bearer $KEY"
```

实测结果：

```
删除前元数据    -> 200  (期望 200)
{"file_id":"6IJQDOdkZds8kUJZUW-yFw","deleted":true,"message":"marked for deletion; blob reclaimed by the cleanup sweep"}
删除后元数据    -> 404  (期望 404)
删除后下载链接  -> 404  (期望 404)
重复 DELETE     -> 404  (期望 404)
```

**删除是软删除**：只标记 `deleted_at`，blob 由清理器在宽限期后回收。
原因在「去重」——同一份字节可能被多条记录引用，删除单条记录时
不能直接删文件，否则会连带打挂其他记录。响应里的 `message` 明确说了这一点。

`重复 DELETE` 返回 404 而非 200：删除是幂等的，但**重复删除一个不存在的
资源**语义上仍是 404，与 `GET` 保持一致。这个细节之前是个不一致点，已修。

---

## 第 13 步：病毒扫描门禁（需切换配置）

前面各步 `.env` 里是 `AV_BACKEND=none`，上传记为 `skipped`。
要验证门禁，用 stub 后端重启服务。

```bash
# 终端 A：Ctrl+C 停掉，然后用 stub 后端重启
cd /d/ImageAndTextHosting
AV_BACKEND=stub .venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

启动日志应出现警告（这条警告本身就是要验证的点之一）：

```
WARNING host: AV_BACKEND=stub is a TEST double, not malware protection;
              flagging content containing: MALWARE_MARKER
```

```bash
# 终端 B
printf 'malware test payload MALWARE_MARKER end\n' > scratch/evil.bin

echo "=== 干净文件 ==="
curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" \
  -F "file=@scratch/notes.txt" \
  | .venv/Scripts/python.exe -c "import sys,json;d=json.load(sys.stdin);print('scan_status=',d['scan_status'],'servable=',d['servable'])"

echo "=== 含恶意标记的文件 ==="
R=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/evil.bin")
echo "$R" | .venv/Scripts/python.exe -c "
import sys,json; d=json.load(sys.stdin)
print('scan_status =',d['scan_status'])    # 期望 infected
print('scan_detail =',d['scan_detail'])    # 期望 stub matched 'MALWARE_MARKER'
print('servable    =',d['servable'])       # 期望 False
"
BADDL=$(echo "$R" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['download_url'])")

echo "=== 尝试下载被拦截的文件 ==="
curl -s -w '\nHTTP %{http_code}  (期望 403)\n' "$BADDL"
```

实测结果：

```
=== 干净文件 ===
scan_status= clean servable= True
=== 含恶意标记的文件 ===
scan_status = infected
scan_detail = stub matched 'MALWARE_MARKER'
servable    = False
=== 尝试下载被拦截的文件 ===
{"error":{"code":"forbidden","message":"file failed malware scan and will not be served"}}
HTTP 403  (期望 403)
```

三个值得注意的设计点：

1. **上传仍返回 201**，不是拒绝上传。行被创建出来是为了**留下审计痕迹**——
   恶意文件的上传尝试本身是安全事件，需要可追溯。被拦截的是「下发」，
   不是「入库」。
2. **stub 按文件内容匹配，不按文件名**。因为 blob 是内容寻址的，
   存盘路径就是 SHA-256，永远不含原始文件名。若按文件名匹配，
   这个 stub 在生产中永远不会命中。
3. **启动日志明确声明 stub 不是真实防护**。这条警告是有意为之：
   「扫描已启用」与「扫描已关闭」行为一致是最危险的失败模式。

验证完记得切回：

```bash
# 终端 A：Ctrl+C，然后不带环境变量重启（回到 .env 的 AV_BACKEND=none）
.venv/Scripts/python.exe -m scripts.dev
```

---

## 第 14 步：浏览器验证（最直观）

浏览器打开 `http://127.0.0.1:8000/docs`，这是自动生成的 Swagger UI。

1. 点右上角 **Authorize**，填 `Bearer sk_你的密钥`（注意要带 `Bearer ` 前缀）
2. 展开 `POST /api/v1/files` → **Try it out** → 选 `scratch/photo.png` → **Execute**
3. 从响应体里复制 `image_url`，**直接粘到地址栏回车**

你应该看到那张 800×480 的网格图。这一步验证的是「图片链接用于直接展示」
这个原始需求——不需要任何鉴权，纯公开可访问，且路径不可猜测。

再试 `download_url`：浏览器会**下载**文件而不是显示，因为响应带了
`Content-Disposition: attachment`。

---

## 第 15 步：落盘检查（确认不是内存里跑假的）

```bash
# blob 按 SHA-256 前两位分片存放
find data/blobs -type f | head -5
find data/blobs -type f | wc -l

# 缩略图
find data/thumbs -type f | head -3

# 核对：文件名应等于该文件内容的 SHA-256
.venv/Scripts/python.exe -c "
import hashlib, pathlib
p = sorted(pathlib.Path('data/blobs').rglob('*'))
p = [x for x in p if x.is_file()][0]
actual = hashlib.sha256(p.read_bytes()).hexdigest()
print('文件名  =', p.name)
print('实际哈希=', actual)
print('一致    =', p.name == actual)
print('分片目录=', p.parent.name, '= 哈希前两位', actual[:2])
"

# 数据库内容
.venv/Scripts/python.exe -c "
import sqlite3
c = sqlite3.connect('data/host.db')
for (n,) in c.execute(\"SELECT name FROM sqlite_master WHERE type='table' ORDER BY name\"):
    print(f'  {n:16s} {c.execute(f\"SELECT COUNT(*) FROM {n}\").fetchone()[0]:5d} 行')
"
```

期望：blob 文件名与自身内容的 SHA-256 完全一致，且所在目录名等于哈希前两位。
这是内容寻址的两个直接推论——**完整性自校验**与**目录分片**。

### 用审计脚本一次性核对全部

手工抽查一个文件说明原理，全量核对交给脚本：

```bash
.venv/Scripts/python.exe scripts/verify_blobs.py
```

期望：

```
-- [1] store integrity (filename == sha256 of content) --
   blobs checked : N
   mismatches    : 0

-- [2] row consistency (live rows vs files on disk) --
   live rows     : N
   inconsistent  : 0

-- [3] orphans (blobs on disk that no row references) --
   blobs on disk : N
   orphans       : 0

====================================================================
  store and rows are consistent
====================================================================
```

它做三项**独立**的检查，因为三者会分别失效：blob 自身一致，但它对应的
数据库行可能已经过时；反之亦然；而孤儿 blob 对前两项和清理器**都不可见**。

- **store integrity**：重新哈希每个 blob，与文件名比对。
- **row consistency**：每条存活记录指向的文件是否存在、`size_bytes` 是否与磁盘一致。
- **orphans**：磁盘上有、但**任何**行（含已软删除的）都不引用的 blob。

第二条不是冗余检查。本服务早期版本曾在 blob 提交**之后**才剥离 EXIF，
导致文件被重写、不再匹配自己的文件名，于是响应里的 `sha256` 无法校验下载内容、
`size_bytes` 也偏大。若审计报出「`db` 比 `disk` 大」且涉及 JPEG/TIFF，
那就是该缺陷的签名特征。重新上传这些文件即可修复，遗留 blob 由
`scripts/cleanup.py` 回收。

第三条最容易被忽略，因为**它永远不会自己消失**。`scripts/cleanup.py`
的孤儿回收是从 `files` 表出发找「没有存活引用的 hash」——
没有行，就什么都找不到。所以这类字节占着磁盘，却没有任何东西记得它们存在。
常见的产生方式是：数据库被从旧快照还原（新插入的行没了、但新写的 blob 还在）、
有人手工 `DELETE` 了行、或进程在「写完 blob」与「插入行」之间被杀掉。
这类问题只能手工清理，前提是先确认这些内容确实不再需要。

**建议把它加进日常巡检**：它同时覆盖位翻转、写入中断和元数据漂移。

---

## 第 16 步：清理器与兜底回收

```bash
# 清理器：先给排队中的文件补判决，再兜底回收软删除 blob、清理超龄 tmp 碎片
.venv/Scripts/python.exe scripts/cleanup.py
# 期望： cleanup: scan_resolved=0 scan_released=0 marked=0 blobs_removed=0 hashes_purged=0 tmp_removed=0
```

六个计数器都要看。**只盯 `marked` 是不够的**：一个每次跑都全 0 的清理器，
和一个根本没在跑的清理器，输出长得一模一样。所以每个计数器都有名字。

| 计数器 | 含义 | 非 0 时说明什么 |
|---|---|---|
| `scan_resolved` | 本次给多少个排队文件补上了真实判决 | 有上传在「写库」与「扫描」之间死掉了，现在被救回来了 |
| `scan_released` | 多少个仍卡在 `pending` 的被兜底判为 `error` | 扫描器不可用；或第 1 步批次跑满而推迟（日志里会有 `hit its batch limit`） |
| `marked` | 多少条记录过了保留期被标记删除 | 正常 |
| `blobs_removed` | 多少个 blob 已无存活引用、过了宽限期被删 | 正常 |
| `hashes_purged` | 多少条悬空的软删除行被清掉 | 正常 |
| `tmp_removed` | 多少个上传碎片被回收 | 有请求中断过 |

**验证第 1 步真的在干活**（造一个「上传被打断」的文件）：

```bash
# 上传一个文件，然后手动把它的行改回 pending 并调老，
# 模拟「请求在 insert 与 scan 之间死掉」
.venv/Scripts/python.exe - <<'PY'
import sys, time; sys.path.insert(0, '.')
from app.db import db
from app.storage import blob_path
import hashlib

data = b'interrupted upload payload'
sha = hashlib.sha256(data).hexdigest()
rec, _ = db.insert_file(sha256=sha, size_bytes=len(data), mime_type='text/plain',
                        orig_name='interrupted.txt', is_image=False, width=None,
                        height=None, uploader='manual', expires_at=None,
                        scan_status='pending')
blob_path(sha).parent.mkdir(parents=True, exist_ok=True)
blob_path(sha).write_bytes(data)
with db.connect() as c:
    c.execute('UPDATE files SET created_at=? WHERE file_id=?',
              (int(time.time()) - 100000, rec.file_id))
print('造好了:', rec.file_id, '| 判决前 scan_status =', db.get_file(rec.file_id).scan_status)
print('可服务吗:', db.get_file(rec.file_id).is_servable)
PY

.venv/Scripts/python.exe scripts/cleanup.py
# 期望： scan_resolved=1（而不是 scan_released=1）
```

**这条才是关键区别**：旧版清理器只会把这条记录判成 `error`，
而 `error` 不可服务 —— 一个完全干净的文件就这样永久下载不了，
同时一个好好的扫描器从没被问过。现在它先问扫描器，
拿到 `skipped`（`AV_BACKEND=none` 时）或 `clean`，文件可下载。

```bash
# 复核：判决已落库，且可服务
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from app.db import db
r = db.get_file('<上一步输出的 file_id>')
print(r.scan_status, r.scan_detail, r.is_servable)
"
```

想看它真的会回收，可以手动制造垃圾：

```bash
# 造一个超龄的 tmp 碎片
printf 'stale fragment' > data/tmp/up_stale.part

# 默认阈值 24h，新文件不会被删（这是正确行为）
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from app.storage import sweep_tmp
print('默认阈值回收了', sweep_tmp(), '个（新文件应保留）')
"

# 把阈值调成 0，模拟「碎片已经足够老」
.venv/Scripts/python.exe -c "
import sys; sys.path.insert(0,'.')
from app.storage import sweep_tmp
print('阈值 0 回收了', sweep_tmp(max_age_seconds=0), '个')
"
ls -A data/tmp/
```

**这一步验证的是一条重要的设计不变量**：清理失败绝不能让请求失败。
删除临时文件时如果抛异常（Windows 上被杀毒软件占用句柄、
或运行时的删除垫片拦截），代码会降级为「留着不管」，
由 `sweep_tmp()` 后续回收，而不是把一次成功的上传变成 500。

---

## 第 17 步：重启后链接失效（验证签名密钥的行为）

`.env` 里 `SECRET_KEY` 是空的，此时**每次重启都会生成新的随机密钥**。

```bash
# 拿一个当前有效的下载链接
RESP=$(curl -s -X POST http://127.0.0.1:8000/api/v1/files -H "Authorization: Bearer $KEY" -F "file=@scratch/notes.txt")
DL3=$(echo "$RESP" | .venv/Scripts/python.exe -c "import sys,json;print(json.load(sys.stdin)['download_url'])")
curl -s -o /dev/null -w '重启前 -> %{http_code}  (期望 200)\n' "$DL3"

# 现在去终端 A 按 Ctrl+C，再重新 .venv/Scripts/python.exe -m scripts.dev

# 重启后重试同一个链接
curl -s -o /dev/null -w '重启后 -> %{http_code}  (期望 403)\n' "$DL3"
```

重启后同一个链接变成 403——这正是无状态签名的特性：**没有任何服务端状态
需要清理，密钥一换，全部在途链接立即失效**。

这也说明生产部署的硬性要求：`SECRET_KEY` 必须固定。

```bash
# 生成一个稳定的密钥
.venv/Scripts/python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

把它填进 `.env` 的 `SECRET_KEY=`，重启后链接就能跨重启存活。

---

## 第 18 步：自动化回归（随时可跑，不需要服务）

手动验证完之后，跑一遍自动化套件确认没有回归：

```bash
cd /d/ImageAndTextHosting

.venv/Scripts/python.exe -m pytest -q                    # 期望 190 passed
.venv/Scripts/python.exe scripts/smoke_test.py           # 期望 all checks passed
.venv/Scripts/python.exe scripts/scan_demo.py            # 期望 all checks passed
.venv/Scripts/python.exe scripts/verify_blobs.py         # 期望 store and rows are consistent

# 真实 HTTP 层（需要服务在跑）
.venv/Scripts/python.exe scripts/e2e_local.py  http://127.0.0.1:8000   # 期望 all 47 checks passed
AV_BACKEND=stub .venv/Scripts/python.exe scripts/av_e2e.py http://127.0.0.1:8000  # 期望 all 20 checks passed
```

> `e2e_local.py` 和 `av_e2e.py` 会自己铸 API 密钥，无需手工准备。

### 关于脚本写到哪里（重要，避免误判）

| 脚本 | 传输方式 | 写入位置 |
|---|---|---|
| `pytest` | 内进程 ASGI | 临时目录（隔离） |
| `smoke_test.py` | 内进程 ASGI | 临时目录（隔离） |
| `scan_demo.py` | 内进程 ASGI | 临时目录（隔离） |
| `demo.py` | 真实 HTTP | 真实 `data/` |
| `e2e_local.py` | 真实 HTTP | 真实 `data/` |
| `av_e2e.py` | 真实 HTTP | 真实 `data/` |

前三者是测试，会把 `DATA_DIR` 重定向到临时目录，**不会污染你的运行时数据**，
启动时会打印一行 `data dir : ... (isolated; ...)` 供确认。

后三者通过 HTTP 与正在运行的服务通信，而服务本身合法地拥有 `data/`，
所以它们会写入真实目录——这也是为什么跑完 `e2e_local.py` 后，
你的文件列表里会多出若干条目。

若确实想让内进程脚本写进真实目录（例如你想用它们预热数据），
设 `HOST_SCRIPT_NO_ISOLATE=1` 即可。

---

## 收尾：停止服务与清理测试数据

```bash
# 终端 A：Ctrl+C

# 清掉手动测试产生的素材
rm -rf scratch/

# 如果想彻底重置（会删掉全部上传内容，谨慎）
# rm -f data/host.db*
# rm -rf data/blobs data/thumbs data/tmp
```

---

## 故障排查

| 现象 | 原因与处理 |
|---|---|
| `curl` 返回 404 但链接看着没问题 | 服务不在 8000 端口，或 `BASE_URL` 与监听端口不一致。链接是绝对地址，端口取自 `BASE_URL` |
| 上传返回 500 | 看终端 A 的异常栈。检查 `data/` 目录可写、磁盘未满 |
| 服务启动后静默卡住无输出 | 这是已修复的历史问题（WAL 日志模式在部分 Windows 卷上挂死）。确认 `.env` 里 `DB_JOURNAL_MODE=TRUNCATE` |
| 链接突然全部失效 | `SECRET_KEY` 为空时每次重启换密钥。填一个固定值即可 |
| `curl -o /dev/null` 后 shell 报 exit code 23 | 本环境下写 `/dev/null` 的噪音，**不影响结果**。介意就改成 `-o scratch/throwaway.bin` |
| 下载得到 `application/octet-stream` | 该格式未识别出魔数，服务端用最保守的 MIME。属预期行为 |
| `AV_BACKEND=stub` 却什么都没拦 | 确认 `AV_STUB_MARKERS` 里的标记串真的出现在**文件内容**里（不是文件名） |
| `sha256` 校验下载内容失败、`size_bytes` 偏大 | 若涉及 JPEG/TIFF，说明该实例跑过「提交后才剥离 EXIF」的旧版本。跑 `scripts/verify_blobs.py` 确认，重新上传这些文件即可修复 |
| 跑完脚本后列表里多出陌生文件 | `smoke_test.py`/`scan_demo.py` 已隔离；`e2e_local.py`/`av_e2e.py` 会写入真实 `data/`（属预期，见第 18 步的对照表） |
| 响应里明明是 `201`，过一会儿 `GET /files/{file_id}` 却是 404 | **201 只说明「写成功过」，不说明「现在还在」。** 记录可能已被删除、或 `retain` 到期被清理器回收。也可能这条响应是浏览器里**停留在旧标签页上的历史响应** —— 它不会自己消失，看着一直有效。核对 `audit_log` 与 `data/blobs/`：两处都没有 = 该请求从未落进当前这个 `data/`（多半是重启前、或 `data/` 被重置前的旧响应）。重新执行一次上传并**立刻**取元数据即可确认链路正常 |
| `mintkey` 之后密钥用不了，`api_keys` 里多出一堆同名记录 | `mintkey` 的参数是**标签（随便起的名）**，不是密钥。把 `sk_...` 当标签传进去只会**再造一把新密钥**，不会导入或恢复任何东西。正确用法：`python -m scripts.mintkey dev`，然后把打印出来的 `sk_...` 填进 `/docs` 的 Authorize。多余的记录可置 `enabled=0` 作废 |
| 自己刚插入的记录过几分钟就消失，`files` 里查不到 | 先排除外部进程：本机若有备份/同步/还原类工具在动 `D:\ImageAndTextHosting\data\`，它会把 `host.db` 还原成旧快照，于是新行消失。特征：**计数会退回同一个旧值**（不是随机丢失），且 `host.db` 的 `ctime` 不变（说明是原地改写、不是被替换），而新写的 blob 还留在盘上变成孤儿。核对方法：`scripts/verify_blobs.py` 会报出这些孤儿；再比对 `host.db` 的 `mtime` 与你自己的写入时刻是否对得上 |
| `verify_blobs.py` 报出 orphans（有 blob 没有对应行） | **清理器永远收不了它们** —— 孤儿回收是从 `files` 表出发找「无存活引用的 hash」，没有行就找不到。只能手工清理，前提是先确认内容确实不再需要。常见成因：数据库被从旧快照还原、手工 `DELETE` 了行、或进程在「写完 blob」与「插入行」之间被杀掉 |

---

## 验证清单（可勾选）

- [ ] `/healthz`、`/readyz`、`/docs` 均 200
- [ ] 无密钥 / 错密钥 / 缺 Bearer 前缀 → 401
- [ ] 上传返回 `download_url` + `image_url`
- [ ] 上传后**立刻** `GET /api/v1/files/{file_id}` 返回 200（`201` 本身不证明记录仍在）
- [ ] 下载字节与原文件一致，带 `attachment`
- [ ] 图片链接返回 `image/webp` + `immutable`
- [ ] 6 项签名篡改全部被拒（403/410/404）
- [ ] TTL 被钳制到 604800
- [ ] `deduplicated` 语义正确（用新文件看 `false → true`）
- [ ] 非图片不产生 `image_url`
- [ ] 软删除后元数据与链接均 404，重复删除也 404
- [ ] 病毒门禁：infected → 403，上传仍 201
- [ ] 浏览器能直接打开 `image_url` 看到图
- [ ] blob 文件名 == 自身 SHA-256
- [ ] 带 EXIF 的 JPEG：GPS 被剥离 **且** `sha256`/`size_bytes` 仍与下载内容一致
- [ ] `scripts/verify_blobs.py` 报 store and rows are consistent（三项检查全 0）
- [ ] 清理器可回收超龄 tmp 碎片
- [ ] 造一条「上传被打断」的 `pending` 记录，清理器把它判为 `skipped`（**不是** `error`），且文件可下载
- [ ] 空 `SECRET_KEY` 时重启使旧链接失效
- [ ] `pytest` 206 passed
