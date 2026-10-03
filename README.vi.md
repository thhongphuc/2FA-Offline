<div align="center">

# 🔐 2FA Offline

**Sinh mã TOTP hoàn toàn trong trình duyệt — không quảng cáo, không server, không gửi gì ra ngoài**

[![Dùng thử](https://img.shields.io/badge/d%C3%B9ng%20th%E1%BB%AD-totp.io.vn-2ea44f?style=flat-square&logo=vercel&logoColor=white)](https://totp.io.vn)
[![Sao](https://img.shields.io/github/stars/thhongphuc/2FA-Offline?style=flat-square&logo=github&logoColor=white&color=blue)](https://github.com/thhongphuc/2FA-Offline)
[![Giấy phép](https://img.shields.io/badge/gi%E1%BA%A5y%20ph%C3%A9p-MIT-yellow?style=flat-square)](LICENSE)
[![Dependency](https://img.shields.io/badge/dependency-0-brightgreen?style=flat-square)](#cấu-trúc)
[![Build](https://img.shields.io/badge/b%C6%B0%E1%BB%9Bc%20build-kh%C3%B4ng-brightgreen?style=flat-square)](#chạy-thế-nào)
[![JavaScript](https://img.shields.io/badge/JavaScript-thu%E1%BA%A7n-F7DF1E?style=flat-square&logo=javascript&logoColor=black)](#cấu-trúc)
[![PWA](https://img.shields.io/badge/PWA-ch%E1%BA%A1y%20offline-5A0FC8?style=flat-square)](#chạy-offline)
[![RFC 6238](https://img.shields.io/badge/RFC%206238-%C4%91%C3%A3%20%C4%91%E1%BB%91i%20chi%E1%BA%BFu-success?style=flat-square)](#về-web-crypto)
[![Vault](https://img.shields.io/badge/AES--256--GCM-m%C3%A3%20ho%C3%A1%20vault-informational?style=flat-square)](#mật-khẩu-chính-mã-hoá-vault)

*[English](README.md) · **Tiếng Việt***

</div>

Sinh mã TOTP (Google Authenticator / Authy compatible) chạy **hoàn toàn tại trình duyệt**.
Không quảng cáo, không server, không gửi bất kỳ request nào ra ngoài.

## Chạy thế nào

**Cách 1 — mở thẳng file** (nhanh nhất):

Nhấp đúp `index.html`. Chạy được ngay, kể cả khi rút mạng.

**Cách 2 — qua HTTP local** (khuyến nghị): cần thiết nếu muốn cài dạng app (PWA)
hoặc dùng secret SHA-512.

```bash
python -m http.server 8791
```

Rồi mở http://localhost:8791

## Deploy lên Vercel

Repo đã có sẵn [vercel.json](vercel.json). Không cần build step, không cần framework preset
— chọn **Other / No framework**, để trống Build Command và Output Directory.

```bash
npx vercel --prod
```

### Các lớp phòng thủ đã cấu hình

**CSP đặt trong `<meta>` của [index.html](index.html)** — đây là thứ đáng giá nhất:

```
default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
manifest-src 'self'; worker-src 'self'; connect-src 'none';
base-uri 'none'; form-action 'none'
```

`connect-src 'none'` khiến trang **không thể** gửi request đi đâu — trình duyệt cưỡng chế,
không phải lời hứa. Người dùng tự mở DevTools kiểm chứng được. Đã kiểm thử: `fetch`
(cả ngoài lẫn same-origin), `XMLHttpRequest`, `WebSocket`, `navigator.sendBeacon`, và
ảnh tới host ngoài — tất cả đều bị chặn.

CSP nằm ở `<meta>` chứ không ở HTTP header vì service worker **cần** `fetch` để cache
offline; `<meta>` chỉ áp cho document nên không vô hiệu hoá `sw.js`.

**Header trong `vercel.json`**: HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `Permissions-Policy` (tắt camera/mic/vị trí/thanh toán),
COOP/CORP, cùng `frame-ancestors 'none'` (chỉ thị này bị bỏ qua trong `<meta>` nên phải
đặt ở header). `sw.js` và `index.html` đặt `must-revalidate` để bản cập nhật tới được
người dùng.

### Điều bạn phải chấp nhận khi host công khai

Khi bạn host, **bạn trở thành bên được tin cậy**. Mỗi lần người dùng mở trang là trình
duyệt tải lại JS từ server bạn. Nếu server, tên miền, hay tài khoản Vercel của bạn bị
chiếm, kẻ tấn công đẩy được bản JS có thêm đoạn lấy cắp secret — người dùng không có
cách nào nhận ra, giao diện vẫn y hệt. Mã hoá bằng mật khẩu chính không cứu được, vì
code độc hại chạy ngay trong trang và đọc được mật khẩu lúc người dùng gõ.

Đây là hạn chế cố hữu của mọi công cụ crypto giao qua web. Giảm thiểu bằng cách:

- Công khai mã nguồn để người biết việc đối chiếu được
- Khuyến khích tải về chạy local (đã ghi trong phần rủi ro ngay trên trang)
- Bật 2FA cho chính tài khoản Vercel và tài khoản tên miền của bạn

Trang đã có sẵn mục **Hướng dẫn sử dụng** mở mặc định cho người mới, kèm 6 mục rủi ro.

## Chạy offline

Service worker cache sẵn cả 13 file và dùng stale-while-revalidate, nên bản cập nhật
vẫn tới được người dùng thay vì bị kẹt mãi ở phiên bản họ tải lần đầu.

Đã kiểm chứng bằng cách **tắt hẳn server** rồi tải lại trang: giao diện vẫn hiện, sinh
mã TOTP ra đúng kết quả mong đợi, lưu tài khoản được, và bật mã hoá AES-GCM được —
trong khi không có gì lắng nghe trên cổng đó.

## Định dạng nhập

Mỗi dòng một tài khoản, dán được nhiều dòng cùng lúc:

| Dạng | Ví dụ |
|---|---|
| `email\|password\|secret` | `abc@icloud.com\|Mk#123\|JBSWY3DPEHPK3PXP` |
| `email\|secret` | `abc@icloud.com\|JBSWY3DPEHPK3PXP` |
| `secret` | `JBSWY3DPEHPK3PXP` |
| otpauth URI | `otpauth://totp/GitHub:abc?secret=...&digits=8&period=60` |

Quy tắc tách: **phần đầu là email/nhãn, phần cuối là secret**, mọi thứ ở giữa là
mật khẩu. Nhờ vậy mật khẩu chứa ký tự `|` vẫn được giữ nguyên vẹn.

Secret không phân biệt hoa thường, tự bỏ khoảng trắng và dấu `=` đệm.

## Tính năng

- Sinh mã cho nhiều tài khoản cùng lúc, vòng đếm ngược theo từng chu kỳ
- Hiện sẵn **mã kế tiếp** — khỏi phải chờ khi còn 2 giây
- Lưu danh sách vào trình duyệt, tìm kiếm, sửa, xoá, **kéo thả đổi thứ tự**
- **Nhóm**: gán nhóm khi dán hàng loạt, thanh chip lọc kèm số đếm, chọn nhiều để
  gán lại / xoá hàng loạt, đổi tên và xoá nhóm
- Sửa được `digits` (6/7/8), `period`, thuật toán (SHA-1/256/512)
- **Mã hoá bằng mật khẩu chính** (AES-256-GCM), khoá màn hình, tự khoá khi không dùng
- Bấm để copy mã / email / secret / mật khẩu
- Xuất & nhập backup `.json` hoặc `.txt`, kèm **backup `.json` mã hoá** (AES-256-GCM,
  mật khẩu riêng cho từng file)
- Mở **nhiều tab** cùng lúc vẫn an toàn — thay đổi ở tab này hiện sang tab kia thay vì
  bị ghi đè âm thầm
- Che secret và mật khẩu mặc định, bật hiện trong Cài đặt
- Bù lệch đồng hồ (`timeOffset`) cho máy offline bị sai giờ
- **Song ngữ Việt / Anh** — lần đầu vào thì theo ngôn ngữ trình duyệt, đổi được
  bằng nút trên thanh công cụ, và nhớ lựa chọn cho lần sau
- Giao diện sáng/tối, chạy tốt trên điện thoại
- Cài được như app (PWA), dùng offline vĩnh viễn

## Nhóm

Danh sách nhóm **suy ra từ chính các tài khoản**, không lưu registry riêng — nhờ vậy
không bao giờ có nhóm mồ côi hay lệch trạng thái. Đổi tên nhóm nghĩa là cập nhật trường
`group` của mọi thành viên. Xoá nhóm **không** xoá tài khoản: chúng chuyển về
"Chưa phân nhóm".

Thanh chip lọc kết hợp **AND** với ô tìm kiếm. Trong chế độ chọn nhiều, nút
"Chọn hết đang hiện" chỉ lấy các thẻ **đang hiển thị**, nên bộ lọc luôn là thứ giới hạn
phạm vi thao tác.

Màu nhóm suy ra tất định từ tên nhóm bằng hash. Cố ý **không lưu bảng màu**: nếu lưu
trong `settings` thì tên nhóm sẽ nằm dạng văn bản thường ngay cả khi vault đã mã hoá,
đọc được mà không cần mở khoá.

Nhóm cố ý **không** trở thành trường thứ tư trong `email|password|secret` — quy tắc
"phần cuối luôn là secret" chính là thứ cho phép mật khẩu chứa ký tự `|`.

## Backup mã hoá

**Xuất .json mã hoá** bọc toàn bộ backup bằng đúng cơ chế vault đang dùng (AES-256-GCM +
PBKDF2 600.000 vòng), với mật khẩu bạn đặt lúc xuất. Mật khẩu này cố ý tách khỏi mật khẩu
chính: file để trên đám mây không làm lộ chìa khoá mở vault. **Nhập file** tự nhận ra định
dạng (`"format": "2fa-offline-backup"`) và hỏi mật khẩu. Vì tham số KDF giờ đến từ file
người khác có thể đưa cho bạn, số vòng ngoài khoảng 1.000–10.000.000 bị từ chối thay vì
để treo trình duyệt.

## Nhiều tab

Mỗi tab giữ danh sách trong RAM và ghi lại toàn bộ bản ghi mỗi lần lưu, nên nếu không phối
hợp thì tab lưu sau sẽ xoá mất thay đổi của tab kia. App lắng nghe sự kiện `storage` và
nạp lại (hoặc giải mã lại bằng khoá đang có trong RAM) khi tab khác ghi. Nếu tab khác bật
mã hoá hoặc đổi mật khẩu chính, khoá tab này đang giữ không còn dùng được nữa, nên nó tự
khoá và hỏi mật khẩu hiện tại.

## Kiểm tra dữ liệu nhập

File nhập có thể đến từ bất cứ đâu. Mỗi mục phải có secret Base32 hợp lệ; `digits` bị kẹp
về 6–8, `period` về 1–300 giây, thuật toán lạ rơi về SHA-1. Thông báo kết quả cho biết
bao nhiêu mục được thêm, bị bỏ vì trùng, và bị loại vì không hợp lệ. Sau khi lưu tài
khoản đầu tiên, app còn gọi `navigator.storage.persist()` để trình duyệt không tự dọn dữ
liệu khi ổ đĩa đầy; kết quả hiện trong Cài đặt.

## Song ngữ

Toàn bộ chuỗi nằm trong `js/i18n.js` dưới dạng hai từ điển, không tải gì lúc chạy nên
cam kết offline và `connect-src 'none'` vẫn nguyên vẹn. Chuỗi tĩnh đánh dấu bằng
`data-i18n` (textContent), `data-i18n-html` (chuỗi có `<b>`/`<code>`) và
`data-i18n-attr` (placeholder, title, aria-label); chuỗi động đi qua `t()`.

Chuỗi mặc định cố ý **không** ghi vào dữ liệu: tài khoản không có nhãn được lưu là chuỗi
rỗng, và hiển thị thành "Không tên" / "Untitled" ở tầng render. Nhờ vậy đổi ngôn ngữ thì
các bản ghi cũ cũng đổi theo.

## Hiệu ứng modal hướng dẫn

Phần hướng dẫn là một `<dialog>` bật vào theo đường cong `cubic-bezier(0.34, 1.56, 0.64, 1)`
trên nền mờ, các bước hiện lần lượt.

Animation mở đặt trong `@keyframes` gắn vào `.modal[open]` chứ không dùng
`@starting-style`: dialog chỉ được vẽ khi có `[open]` nên keyframes tự chạy đúng lúc, và
cách này hoạt động trên mọi trình duyệt hỗ trợ `<dialog>`. Khi đóng phải đợi animation
chạy xong rồi mới gọi `close()`, vì `close()` gỡ phần tử khỏi luồng vẽ ngay lập tức.
`prefers-reduced-motion` tắt toàn bộ chuyển động mà không đụng tới chức năng.

## Mật khẩu chính (mã hoá vault)

Mặc định **tắt**. Bật trong **Cài đặt → Mật khẩu chính → Bật mã hoá**.

Khi bật:

- Toàn bộ tài khoản được mã hoá **AES-256-GCM** trước khi ghi xuống `localStorage`
- Khoá dẫn xuất bằng **PBKDF2-HMAC-SHA256, 600.000 vòng** (mức OWASP khuyến nghị),
  salt ngẫu nhiên 16 byte, IV 12 byte mới cho **mỗi** lần ghi
- Khoá chỉ nằm trong RAM, không bao giờ ghi xuống đĩa
- Mở trang lên là gặp màn khoá; nhập sai mật khẩu thì AES-GCM tự từ chối
  (không cần lưu hash mật khẩu ở đâu cả)
- Tự khoá sau 1 / 5 / 15 / 60 phút không dùng — khi khoá, toàn bộ tài khoản
  bị xoá khỏi bộ nhớ và khỏi DOM
- Lúc khoá, giao diện phía sau bị **vô hiệu hoá thật** chứ không chỉ bị che: mọi
  control đặt `disabled`, `<main>`/`<footer>` đặt `inert`, và các hàm xử lý đều có
  guard riêng. Ba lớp độc lập nhau nên hỏng một lớp vẫn còn hai lớp
- `settings` (theme, bù giờ) vẫn để dạng thường để áp được giao diện trước khi mở khoá

### Mật khẩu này ở đâu ra?

**Bạn tự đặt.** App không có mật khẩu mặc định và **không có màn đăng nhập**. Mở trang
lên là dùng được ngay. Mật khẩu chính chỉ xuất hiện sau khi chính bạn bật nó trong
Cài đặt, và bạn tự nghĩ ra chuỗi đó (tối thiểu 8 ký tự). Nó không liên quan gì tới
mật khẩu của các tài khoản bạn lưu trong danh sách.

### Quên mật khẩu thì sao?

**Không khôi phục được, và đó là chủ đích của thiết kế.** Khoá AES được dẫn xuất
trực tiếp từ chuỗi bạn gõ qua PBKDF2 và không lưu ở bất kỳ đâu — không trên máy bạn,
không ở server nào. Không tồn tại "quên mật khẩu → gửi email đặt lại", vì không có
email, không có server, và không có bản sao khoá. Người làm ra trang này cũng không
mở hộ được.

Nếu quên:

- **Có file backup `.json`/`.txt`** — bấm **"Xoá toàn bộ dữ liệu và bắt đầu lại"** ngay
  trên màn khoá, rồi dùng **Nhập file** để khôi phục. Backup là văn bản thường nên
  không dính mật khẩu chính.
- **Không có backup** — secret key mất vĩnh viễn. Bạn phải vào từng dịch vụ, đăng nhập
  bằng mã dự phòng (backup code) hoặc email, rồi thiết lập lại 2FA để lấy secret mới.

Vì vậy: **xuất backup `.json` ngay sau khi lưu tài khoản, trước khi bật mã hoá.**

Tính năng này cần Web Crypto, nên phải chạy qua `http://localhost` nếu trình duyệt
của bạn không cấp `crypto.subtle` cho `file://`.

## Cấu trúc

```
index.html               UI
css/style.css
js/base32.js             giải mã Base32 (RFC 4648)
js/sha.js                SHA-1 / SHA-256 + HMAC thuần JS (đường dự phòng)
js/totp.js               TOTP (RFC 6238), ưu tiên Web Crypto
js/parser.js             đọc email|password|secret và otpauth://
js/crypto.js             AES-GCM + PBKDF2 cho vault
js/storage.js            đọc/ghi localStorage
js/app.js                render, đồng hồ, copy, nhóm, import/export
sw.js                    service worker (stale-while-revalidate)
tests/                   bộ test không dependency (không deploy)
```

## Kiểm thử

```bash
node tests/run-node.mjs          # Node 20+
```

hoặc mở `http://localhost:8791/tests/` trên trình duyệt. Bộ test nạp nguyên văn các file
`js/*.js` và phủ: toàn bộ test vector RFC 6238 (SHA-1/256/512), vector HMAC RFC 2202 / 4231
cho đường JS thuần, so sánh ngẫu nhiên đường JS thuần với Web Crypto, Base32 RFC 4648,
parser, làm sạch dữ liệu, và mã hoá vault/backup (khứ hồi, sai mật khẩu, ciphertext bị sửa,
tham số KDF độc hại). Bản chạy bằng Node còn kiểm tra mọi file trong `ASSETS` của `sw.js`
đều tồn tại.

Không có dependency, không có bước build, không tải gì từ CDN.

### Về Web Crypto

Mặc định dùng `crypto.subtle` của trình duyệt. Khi mở bằng `file://` mà trình duyệt
không cho phép `crypto.subtle`, app tự chuyển sang bản HMAC viết bằng JS thuần —
SHA-1 và SHA-256 vẫn cho kết quả đúng y hệt. Riêng SHA-512 bắt buộc phải chạy qua
`http://localhost`. Dòng chữ dưới chân trang cho biết đang chạy đường nào.

Cả hai đường đã được đối chiếu với **toàn bộ test vector của RFC 6238** (SHA-1,
SHA-256, SHA-512) và với `crypto` của Node.

## Lưu ý bảo mật

**Khi chưa bật mật khẩu chính**, secret key nằm dạng văn bản thường trong
`localStorage`. Nghĩa là ai dùng chung máy / chung profile trình duyệt đều đọc được,
và extension có quyền truy cập trang cũng đọc được.

**Kể cả khi đã bật mật khẩu chính**, vẫn còn những giới hạn cần biết:

- Lúc vault đang mở, secret nằm trong RAM và trong DOM — chỉ được xoá khi khoá lại
- File backup `.json` / `.txt` thường là văn bản thường — dùng **Xuất .json mã hoá** cho
  mọi file mang ra khỏi máy
- Mã hoá bảo vệ dữ liệu *lúc nằm yên trên đĩa*, không chống được keylogger
  hay extension độc hại đang chạy cùng lúc

Đây là đánh đổi cố hữu của mọi công cụ 2FA dạng web. Với tài khoản quan trọng —
ngân hàng, email chính — hãy dùng app điện thoại như Aegis, Ente Auth hay 2FAS.

Xoá sạch bằng nút **Xoá toàn bộ dữ liệu** trong Cài đặt.

## Chưa làm

- **Quét mã QR** — đã cân nhắc rồi bỏ. `BarcodeDetector` (bộ đọc QR có sẵn của
  trình duyệt) không tồn tại trên Chrome/Edge bản Windows, nên tính năng sẽ vô
  dụng đúng trên nền tảng đang dùng. Các lựa chọn còn lại là nhúng thư viện QR
  vào repo (phá vỡ cam kết zero-dependency) hoặc tự viết bộ giải mã QR
  (~800 dòng: dò finder pattern, biến đổi phối cảnh, Reed-Solomon trên GF(256)).
  Với định dạng `email|password|secret` đang dùng thì dán tay vẫn nhanh hơn.
- Đồng bộ giữa nhiều máy (cố ý không làm — sẽ cần server)

## Khối ủng hộ ở chân trang

Chân trang có sẵn một khối ủng hộ, nhưng **chỉ hiện khi tồn tại file
`icons/donate-qr.png`**. Chưa có file thì khối tự ẩn, không để lộ ảnh vỡ.

Cách thêm: tạo mã QR tại [vietqr.io](https://vietqr.io) hoặc app ngân hàng, lưu thành
`icons/donate-qr.png` rồi commit. Ảnh được đặt trên nền trắng nên vẫn quét được ở
giao diện tối.

File này cố ý **không** nằm trong danh sách `ASSETS` của `sw.js`: `cache.addAll()` thất
bại toàn bộ nếu bất kỳ file nào 404, nên thêm vào sẽ làm hỏng service worker với những
ai không có ảnh. Cơ chế stale-while-revalidate tự cache nó khi file tồn tại.

Cân nhắc trước khi thêm: trang công khai đồng nghĩa **số tài khoản trong mã QR cũng công
khai vĩnh viễn** — bot quét được, và có thể bị lợi dụng để dựng trang giả mạo.

## Giấy phép

[MIT](LICENSE) © Tống Huỳnh Hồng Phúc
