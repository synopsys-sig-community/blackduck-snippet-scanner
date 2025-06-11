# blackduck-snippet-scanner

## Available Options
| Option name | Description | Default value | Environment variable | Required |
|-------------|-------------|---------------|----------|----------|
| url | Baseurl for Black Duck Hub | - | BD_URL | false |
| token | BD Access Token | - | BD_TOKEN | true |
| log_level | "Will print more info | INFO | - | false |
| giturl | GitHub Url, must be given if GH Enterprise in use | - | GIT_URL | false |
| gittoken | GitHub Access Token | - | GIT_TOKEN | true |
| prID | Pull request ID | - | - | false |
| repo | GitHub repository name | - | - | true |
| action_path | Path where actions are downloaded | - | - | true |
| result_file | File for result json | blackduckSnippetFindings.json | - | false |
| group | Will create only one groupped comment per file. | true | - | false |
| prComment | Will create Pull Request Comments, otherwise json exported. | false | - | false |
| sarif | Will create sarif format file. | false | - | false |
| toolNameforSarif | Tool name in Sarif json | Black Duck Snippet | - | false |

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