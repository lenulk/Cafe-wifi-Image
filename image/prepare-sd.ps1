# เตรียมการ์ดที่ flash Cafe-WiFi OS แล้ว (M6, docs/install-from-image.md ขั้น 1)
#
#   powershell -ExecutionPolicy Bypass -File prepare-sd.ps1
#   powershell -ExecutionPolicy Bypass -File prepare-sd.ps1 -ShopName "Baan Cafe" -SshKey $HOME\.ssh\id_ed25519.pub
#
# เขียน cafewifi.conf ลงไดรฟ์ bootfs (ชื่อร้าน, setup code, SSH key ของช่าง) แล้วแสดง setup code ให้จด
# Pi อ่านไฟล์นี้ตอนบูตครั้งแรกแล้วลบทิ้ง (ดู image/firstboot/cafe-wifi-firstboot.sh)
# ไม่แตะไดรฟ์อื่นนอกจากไดรฟ์ที่มี config.txt + cmdline.txt (ส่วน boot ของ Raspberry Pi)
param(
    [string]$Drive,
    [string]$ShopName,
    [string]$SshKey,
    [string]$TechUser = 'cafeadmin'
)
$ErrorActionPreference = 'Stop'

function Find-BootFs {
    Get-PSDrive -PSProvider FileSystem | Where-Object {
        $_.Root -and (Test-Path (Join-Path $_.Root 'config.txt')) -and (Test-Path (Join-Path $_.Root 'cmdline.txt'))
    }
}

# ---------- เลือกไดรฟ์ ----------
if ($Drive) {
    $root = ($Drive.TrimEnd(':\') + ':\')
    if (-not (Test-Path (Join-Path $root 'config.txt'))) { throw "ไดรฟ์ $root ไม่ใช่ bootfs ของ Raspberry Pi (ไม่มี config.txt)" }
} else {
    $found = @(Find-BootFs)
    if ($found.Count -eq 0) { throw 'ไม่พบไดรฟ์ bootfs -- เสียบการ์ดที่ flash แล้ว (ถอดแล้วเสียบใหม่ถ้า Imager เพิ่ง eject)' }
    if ($found.Count -gt 1) { throw ('พบ bootfs หลายไดรฟ์: ' + ($found.Root -join ', ') + ' -- ระบุด้วย -Drive E:') }
    $root = $found[0].Root
}
Write-Host "ไดรฟ์ bootfs: $root"

# ---------- ค่าจากช่าง ----------
if (-not $PSBoundParameters.ContainsKey('ShopName')) { $ShopName = Read-Host 'ชื่อร้าน (แสดงบนหน้า Wi-Fi ลูกค้า, Enter = Cafe-Guest)' }
$ShopName = $ShopName.Trim()
if ($ShopName -match "['`"\\``$]" -or $ShopName.Length -gt 64) { throw 'ชื่อร้านยาวไม่เกิน 64 ตัว และห้ามมี '' " \ ` $' }

$keyLine = ''
if (-not $PSBoundParameters.ContainsKey('SshKey')) {
    $default = Join-Path $HOME '.ssh\id_ed25519.pub'
    $ans = Read-Host "ไฟล์ SSH public key ของช่าง (Enter = $(if (Test-Path $default) { $default } else { 'ไม่ใส่' }))"
    $SshKey = if ($ans) { $ans } elseif (Test-Path $default) { $default } else { '' }
}
if ($SshKey) {
    $keyLine = (Get-Content -Raw -LiteralPath $SshKey).Trim()
    if ($keyLine -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]+( .*)?$') {
        throw "$SshKey ไม่ใช่ public key (.pub) -- ห้ามใช้ไฟล์ private key"
    }
    if ($keyLine -match "`n") { throw 'ใส่ได้ key เดียว' }
}
if ($TechUser -notmatch '^[a-z_][a-z0-9_-]{0,31}$') { throw "TechUser '$TechUser' ไม่ถูกต้อง" }

# ---------- setup code: 8 ตัว ไม่มี 0/O/1/I/L (ตรงกับ firstboot) ----------
$alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$buf = New-Object byte[] 1
$code = ''
while ($code.Length -lt 8) {
    $rng.GetBytes($buf)
    if ($buf[0] -lt 248) { $code += $alphabet[$buf[0] % 31] }   # 248 = 31*8 กัน modulo bias
}
$pretty = $code.Substring(0, 4) + '-' + $code.Substring(4)

# ---------- เขียนไฟล์ (UTF-8 ไม่มี BOM; Pi อ่านได้ทั้ง CRLF/LF) ----------
$lines = @(
    '# Cafe-WiFi first boot -- Pi อ่านแล้วลบไฟล์นี้ทิ้งเอง (สร้างโดย prepare-sd.ps1)',
    "GATEWAY_NAME=$ShopName",
    "SETUP_CODE=$code",
    "TECH_USER=$TechUser"
)
if ($keyLine) { $lines += "SSH_PUBKEY=$keyLine" }
$conf = Join-Path $root 'cafewifi.conf'
[System.IO.File]::WriteAllText($conf, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))
Remove-Item -ErrorAction SilentlyContinue (Join-Path $root 'SETUP-CODE.txt')

Write-Host ''
Write-Host '==============================================='
Write-Host "   SETUP CODE:  $pretty"
Write-Host '==============================================='
Write-Host 'จดไว้หรือติดสติกเกอร์ที่กล่อง Pi -- ใช้เข้า http://cafewifi.local ตอนติดตั้ง'
if (-not $keyLine) { Write-Host 'ไม่ได้ใส่ SSH key: เข้าเครื่องทาง SSH ไม่ได้ (ดูแลผ่านหน้าแอดมินอย่างเดียว)' }
Write-Host "เขียน $conf แล้ว -- Eject การ์ดก่อนถอด"
