# blackduck-snippet-scanner

## Available Options
| Option name | Description | Default value | Environment variable | Required |
|-------------|-------------|---------------|----------|----------|
| blackduck_url | Baseurl for Black Duck Hub | - | BD_URL | false |
| blackduck_apiToken | BD Access Token | - | BD_TOKEN | true |
| github_url | GitHub Url, must be given if GH Enterprise in use | - | GIT_URL | false |
| github_apiToken | GitHub Access Token | - | GIT_TOKEN | true |
| github_pull_request_id | Pull request ID | - | - | false |
| github_repo | GitHub repository name | - | - | true |
| blackduck_outputFile | File for result json | blackduckSnippetFindings.json | - | false |
| github_prCommentGroupped | Will create only one groupped comment per file. | true | - | false |
| github_prComment | Will create Pull Request Comments, otherwise json exported. | false | - | false |
| github_sarif | Will create sarif format file. | false | - | false |
| github_toolNameforSarif | Tool name in Sarif json | Black Duck Snippet | - | false |

## Usage examples
```yaml
name: Pull Request snippet analysis

on:
  pull_request:
    branches: [ "main" ]
jobs:
  snippet_tests:
    runs-on: ubuntu-latest
    steps:
    - uses: synopsys-sig-community/blackduck-snippet-scanner@main
      with:
        blackduck_url: ${{secrets.BLACKDUCK_SERVER_URL}}
        blackduck_apiToken: ${{secrets.BLACKDUCK_ACCESS_TOKEN}}
        blackduck_outputFile: ${{github.workspace}}/blackduck-snippet.sarif.json
        blackduck_log_level: DEBUG
        github_url: ""
        github_apiToken: ${{secrets.GITHUB_TOKEN}}
        github_repo: ${{github.repository}}
        github_pull_request_id: ${{github.event.pull_request.number}}
        github_prComment: false
        github_prCommentGroupped: true
        github_sarif: true
    - name: Upload SARIF file
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: ${{github.workspace}}/blackduck-snippet.sarif.json
      continue-on-error: true
```