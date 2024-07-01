# read client id and secret from file Credentials_OAuthClient.json
$OAuthClient = Get-Content "Credentials_OAuthClient.json" | ConvertFrom-Json
$clientId = $OAuthClient.web.client_id
$clientSecret = $OAuthClient.web.client_secret
$redirectUri = $OAuthClient.web.redirect_uris[0]
$authUrl = $OAuthClient.web.auth_uri

# get the authorization code
$params = @{
    client_id = $clientId
    response_type = "code"
    redirect_uri = $redirectUri
    scope = "openid email https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/drive.activity https://www.googleapis.com/auth/drive.metadata https://www.googleapis.com/auth/photoslibrary https://www.googleapis.com/auth/photoslibrary.sharing https://www.googleapis.com/auth/photoslibrary.edit.appcreateddata"
    access_type = "offline"
}
# build the authorization URL
$query = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
foreach ($param in $params.GetEnumerator()) {
    $query.Add($param.Key, $param.Value)
}
$authUrlWithParams = "$authUrl"+"?$($query.ToString())"

# open the authorization URL in the default browser
Write-Host "Opening authorization URL: $authUrlWithParams"
Start-Process $authUrlWithParams

# listen for the authorization code
if ($redirectUri -match "localhost") {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($redirectUri+"/")
    $listener.Start()
    $asyncResult = $listener.BeginGetContext($null, $null)
    $success = $asyncResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromMinutes(5))
    if ($success) {
        $context = $listener.EndGetContext($asyncResult)
        $request = $context.Request
        $response = $context.Response
        $code = $request.QueryString["code"]
    } else {
        Write-Host "Timeout expired before a code was received."
    }
    $listener.Stop()
    $listener.close()
} else {
    $code = Read-host "Enter the authorization code"
}

# exchange the authorization code for a refresh token
$tokenRequestParams = @{
    code = $code
    client_id = $clientId
    client_secret = $clientSecret
    redirect_uri = $redirectUri
    grant_type = "authorization_code"
    access_type = "offline"
}
$tokenResponse = Invoke-RestMethod -Uri "https://oauth2.googleapis.com/token" -Method POST -Body $tokenRequestParams
$refreshtoken = $tokenResponse.refresh_token
$idtoken = $tokenResponse.id_token

if ($refreshtoken -eq $null) {
    Write-Host "Failed to retrieve refresh token."
    exit
}

# retrieve user email
$idTokenParts = $idtoken.Split('.')
$base64Payload = $idTokenParts[1] -replace "-", "+" -replace "_", "/"
switch ($base64Payload.Length % 4) {
    2 { $base64Payload += "==" }
    3 { $base64Payload += "=" }
}
$payloadJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Payload))
$payload = ConvertFrom-Json $payloadJson
$email = $payload.email

# save refresh token and email to Credentials_UsersRefreshTokens.json
$refreshTokens = @{}
if (Test-Path "Credentials_UsersRefreshTokens.json") {
    $refreshTokens = Get-Content "Credentials_UsersRefreshTokens.json" | ConvertFrom-Json
} else {
    New-Item "Credentials_UsersRefreshTokens.json" -ItemType File
}
if ($refreshTokens.PSObject.Properties.Name -notcontains $email) {
    $refreshTokens | Add-Member -Type NoteProperty -Name $email -Value $refreshtoken
} else {
    $refreshTokens.$email = $refreshtoken
}
$refreshTokens | ConvertTo-Json | Set-Content "Credentials_UsersRefreshTokens.json"
Write-Host "Saved refresh token for user $email"

# Encription
<# Generate keys
$key = New-Object Byte[] 32 # AES-256 requires a 32-byte key
$iv = New-Object Byte[] 16 # For AES, IV size is 16 bytes for AES-128, AES-192, and AES-256
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)
[Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($iv)
# encode the key and iv as base64 strings
$keyBase64 = [Convert]::ToBase64String($key)
$ivBase64 = [Convert]::ToBase64String($iv)
#>

$jsonContent = Get-Content -Path "Credentials_EncriptionKey.json" -Raw | ConvertFrom-Json
$keyBase64 = $jsonContent.keyBase64
$ivBase64 = $jsonContent.ivBase64
$key = [Convert]::FromBase64String($keyBase64)
$iv = [Convert]::FromBase64String($ivBase64)

$file = "Credentials_UsersRefreshTokens.json"
$content = Get-Content -Path $file -Raw
$encryptor = [System.Security.Cryptography.Aes]::Create()
$encryptor.Key = $key
$encryptor.IV = $iv
$ms = New-Object IO.MemoryStream
$cs = New-Object Security.Cryptography.CryptoStream $ms, $encryptor.CreateEncryptor(), ([System.Security.Cryptography.CryptoStreamMode]::Write)
$sw = New-Object IO.StreamWriter $cs
$sw.Write($content)
$sw.Close()
$encrypted = $ms.ToArray()
[System.IO.File]::WriteAllBytes(($file +".enc"), $encrypted)