# read-only dump of issues + project #3, nothing gets edited
$ErrorActionPreference = "Stop"
$repo = "lauremhsn/detectforge"
$out = "board_dump"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "gh not found" }
New-Item -ItemType Directory -Force $out | Out-Null

gh issue list -R $repo --state all --limit 200 --json number,title,state,labels,assignees,milestone,body | Out-File -Encoding utf8 "$out\issues.json"
gh label list -R $repo --limit 100 --json name,color,description | Out-File -Encoding utf8 "$out\labels.json"
gh project field-list 3 --owner lauremhsn --format json | Out-File -Encoding utf8 "$out\project_fields.json"
gh project item-list 3 --owner lauremhsn --format json --limit 200 | Out-File -Encoding utf8 "$out\project_items.json"

Write-Host "done, upload the 4 files in $out"
