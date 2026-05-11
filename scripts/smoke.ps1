param(
  [string]$ApiBase = "https://api.sgiptv.com.br",
  [string]$AdminUser,
  [string]$AdminPass,
  [string]$AdminToken,
  [switch]$SkipEmail,
  [switch]$SkipTelegram,
  [switch]$ContinueOnFail
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) {
  Write-Host ""
  Write-Host "==> $msg"
}

function Invoke-Json($method, $url, $headers = $null, $bodyObj = $null) {
  $bodyJson = $null
  if ($null -ne $bodyObj) { $bodyJson = ($bodyObj | ConvertTo-Json -Depth 10) }
  try {
    if ($null -eq $headers) { $headers = @{} }
    if (-not $headers.ContainsKey("Content-Type")) { $headers["Content-Type"] = "application/json" }
    if ($null -eq $bodyJson) {
      return Invoke-RestMethod -Method $method -Uri $url -Headers $headers
    }
    return Invoke-RestMethod -Method $method -Uri $url -Headers $headers -Body $bodyJson
  } catch {
    $resp = $_.Exception.Response
    $status = $null
    try { if ($resp) { $status = [int]$resp.StatusCode } } catch {}
    if ($resp -and $resp.GetResponseStream()) {
      $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
      $text = $reader.ReadToEnd()
      throw "HTTP error calling $method $url (status=$status)`n$text"
    }
    $details = $null
    try { $details = $_.ErrorDetails.Message } catch {}
    if ($details) { throw "HTTP error calling $method $url (status=$status)`n$details" }
    throw "HTTP error calling $method $url (status=$status)`n$($_.Exception.Message)"
  }
}

Write-Host "SGIPTV smoke test"
Write-Host "API: $ApiBase"

Write-Step "1) Health check (GET /)"
$health = Invoke-RestMethod -Method Get -Uri "$ApiBase/"
Write-Host "OK: $health"

$token = $null
if ($AdminToken) {
  $token = $AdminToken
} elseif ($env:SGIPTV_ADMIN_TOKEN) {
  $token = $env:SGIPTV_ADMIN_TOKEN
}
if (-not $token) {
  if (-not $AdminUser -or -not $AdminPass) {
    throw "Defina SGIPTV_ADMIN_TOKEN no ambiente OU passe -AdminUser e -AdminPass."
  }
  Write-Step "2) Admin login (POST /login) para obter token"
  $login = Invoke-Json Post "$ApiBase/login" $null @{ usuario = $AdminUser; senha = $AdminPass }
  if (-not $login.token) { throw "Login nao retornou token." }
  $token = $login.token
  Write-Host "Token obtido (nao exibido)."
} else {
  Write-Step "2) Usando SGIPTV_ADMIN_TOKEN do ambiente (nao exibido)"
}

$authHeaders = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

if (-not $SkipTelegram) {
  Write-Step "3) Telegram teste (POST /admin/telegram/teste)"
  try {
    $tg = Invoke-Json Post "$ApiBase/admin/telegram/teste" $authHeaders @{ tipo = "pix"; texto = "Smoke test Telegram (API)" }
    Write-Host ("OK: " + $tg.ok)
  } catch {
    Write-Host ("FALHOU: " + $_.Exception.Message) -ForegroundColor Yellow
    if (-not $ContinueOnFail) { throw }
  }
} else {
  Write-Step "3) Telegram teste (SKIP)"
}

if (-not $SkipEmail) {
  Write-Step "4) Email teste (POST /admin/email/teste)"
  try {
    $mail = Invoke-Json Post "$ApiBase/admin/email/teste" $authHeaders @{ assunto = "Smoke test Email - SGIPTV"; texto = "Email de teste enviado pelo smoke.ps1" }
    Write-Host ("OK: " + $mail.ok)
  } catch {
    Write-Host ("FALHOU: " + $_.Exception.Message) -ForegroundColor Yellow
    if (-not $ContinueOnFail) { throw }
  }
} else {
  Write-Step "4) Email teste (SKIP)"
}

Write-Step "5) Criar teste IPTV (POST /teste-iptv)"
$email = ("smoke+" + ([DateTimeOffset]::Now.ToUnixTimeSeconds()) + "@example.com")
$whats = ("11" + (Get-Random -Minimum 900000000 -Maximum 999999999))
try {
  $teste = Invoke-Json Post "$ApiBase/teste-iptv" $null @{ tipo = "completo"; email = $email; telefone = $whats }
  Write-Host ("Criado: " + ($teste.ok))
} catch {
  Write-Host ("FALHOU: " + $_.Exception.Message) -ForegroundColor Yellow
  if (-not $ContinueOnFail) { throw }
  # Sem teste IPTV, nao da para seguir com PIX
  throw
}
$testeLogin = $teste.login
if (-not $testeLogin -and $teste.usuario) { $testeLogin = $teste.usuario }
if (-not $testeLogin -and $teste.user) { $testeLogin = $teste.user }
$testeSenha = $teste.senha
if (-not $testeSenha -and $teste.password) { $testeSenha = $teste.password }
if (-not $testeSenha -and $teste.senha_iptv) { $testeSenha = $teste.senha_iptv }
if (-not $testeLogin -or -not $testeSenha) {
  Write-Host "Resposta /teste-iptv:" -ForegroundColor Yellow
  Write-Host ($teste | ConvertTo-Json -Depth 10)
  throw "Teste IPTV nao retornou login/senha (campos esperados: login/senha)."
}

Write-Step "6) Gerar PIX (POST /pix)"
$pix = Invoke-Json Post "$ApiBase/pix" $null @{ email = $email; telefone = $whats; plano = "Mensal - 1 Tela (R$ 30,00)"; valor = 30; login = $testeLogin; senha = $testeSenha }
if ($null -eq $pix.ok) {
  Write-Host "Resposta /pix:" -ForegroundColor Yellow
  Write-Host ($pix | ConvertTo-Json -Depth 10)
} else {
  Write-Host ("PIX ok: " + ($pix.ok))
}

Write-Step "7) Pagamentos do mes (GET /pagamentos/mes)"
$now = Get-Date
$mes = Invoke-Json Get "$ApiBase/pagamentos/mes?year=$($now.Year)&month=$($now.Month)" $authHeaders $null
Write-Host ("OK: " + $mes.ok + " | qtd=" + $mes.quantidade + " | total=" + $mes.total)

Write-Step "8) Confirmar pagamento manual (POST /pagamentos/dinheiro)"
$manual = Invoke-Json Post "$ApiBase/pagamentos/dinheiro" $authHeaders @{ plano = "Mensal - 1 Tela (R$ 30,00)"; valor = 30; data = ($now.ToString("yyyy-MM-ddTHH:mm:ss")) }
Write-Host ("OK: " + $manual.ok)

Write-Step "9) Listar clientes (GET /clientes)"
$clientes = Invoke-Json Get "$ApiBase/clientes" $authHeaders $null
$clientesOk = $clientes.ok
if ($null -eq $clientesOk -and $clientes.success) { $clientesOk = $clientes.success }
$lista = $clientes.clientes
if ($null -eq $lista -and $clientes.data) { $lista = $clientes.data }
if ($null -eq $lista -and $clientes.rows) { $lista = $clientes.rows }
if ($null -eq $lista) {
  Write-Host "Resposta /clientes (shape inesperado):" -ForegroundColor Yellow
  Write-Host ($clientes | ConvertTo-Json -Depth 10)
  Write-Host ("OK: " + $clientesOk + " | qtd=0")
} else {
  Write-Host ("OK: " + $clientesOk + " | qtd=" + ($lista | Measure-Object).Count)
}

Write-Step "10) Listar revendedores (GET /revendedores)"
$revs = Invoke-Json Get "$ApiBase/revendedores" $authHeaders $null
Write-Host ("OK: " + $revs.ok + " | qtd=" + ($revs.revendedores | Measure-Object).Count)

Write-Host ""
Write-Host "SMOKE OK"
