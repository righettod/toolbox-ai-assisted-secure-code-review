$repoName = "toolbox-ai-assisted-secure-code-review"
$bundleLocation = "https://github.com/righettod/$repoName/archive/refs/heads/main.zip"
$archLocation = "$env:TEMP\work.zip"
Write-Host "🧑‍💻 Download and setup the skills to the current folder..." -ForegroundColor DarkYellow
Invoke-WebRequest -Uri "$bundleLocation" -OutFile "$archLocation"
Expand-Archive -Path "$archLocation" -DestinationPath "$env:TEMP" -Force
New-Item -ItemType Directory -Path ".claude\skills" -Force | Out-Null
Copy-Item -Path "$env:TEMP\$repoName-main\.claude\skills\*" -Destination ".claude\skills" -Recurse -Force
Write-Host "🧑‍💻 Cleanup temporary content..." -ForegroundColor DarkYellow
Remove-Item -Path "$archLocation"
Remove-Item -Path "$env:TEMP\$repoName-main" -Recurse -Force
Write-Host "🤖 Skills available:" -ForegroundColor DarkYellow
Get-ChildItem -Path ".claude\skills"