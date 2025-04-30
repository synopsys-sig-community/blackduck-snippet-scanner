import logging
import sys
import github

__author__ = "Jouni Lehto"
__versionro__ = "0.0.1"

supportedFileExtensions = ["py", "c", "h", "java", "ccp", "js", "go", ""]

class GihubCommenter:

    def __init__(self, giturl:str, gittoken:str, repo:str, prID:int, changedFiles:bool, group:bool, log_level:str) -> None:
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.debug("Snippet Scanner -script, version: " + __versionro__)
        if not gittoken:
            logging.error("GitHub Access Token is not given. You need to give it with --gittoken")
            exit()
        self.token = gittoken
        auth = github.Auth.Token(token=gittoken)
        if giturl:
            # Github Enterprise with custom hostname
            self.giturl = giturl if not giturl.endswith("/") else giturl[:-1]
            self.github = github.Github(auth=auth, base_url=f"{giturl}/api/v3")
        else:
            # Public Web Github
            self.github = github.Github(auth=auth)
        self.group = group
        self.repo = self.github.get_repo(repo)
        self.pullRequest = self.repo.get_pull(int(prID))
        self.last_commit = self.pullRequest.get_commits()[self.pullRequest.commits - 1]
        if changedFiles:
            self.analysisFiles = self.__getChangedFiles()
        else:
            self.analysisFiles = self.__getAllFiles()

    def __getChangedFiles(self) -> list:
        files = []
        changedFiles = self.pullRequest.get_files()
        if changedFiles and changedFiles.totalCount > 0:
            for file in changedFiles:
                if file.filename.split('.')[-1] in supportedFileExtensions:
                    files.append(file.filename)
        return files

    def __getAllFiles(self) -> list:
        files = []
        contents = self.repo.get_contents("")
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(self.repo.get_contents(file_content.path))
            else:
                if file_content.path.split('.')[-1] in supportedFileExtensions:
                    files.append(file_content.path)
        return files

    def createMarkdownComment(self, file:str, snippetResult:str) -> None:
        if self.group:
            self.__createGroupMarkDownComment(file, snippetResult)
        else:
            self.__createSeparatedMarkdownComment(file, snippetResult)

    def __createSeparatedMarkdownComment(self, file:str, snippetResult:str) -> None:
        if snippetResult:
            for licenseFamily in snippetResult["snippetMatches"]:
                fileUrl = f"{self.repo.html_url}/blob/{self.last_commit.sha}/{file}"
                for snippet in snippetResult["snippetMatches"][licenseFamily]:
                    snippet_comment = f'**Snippet analysis has found following match from file: [{file}]({fileUrl})**\n\n'
                    snippet_comment += f'**License family:** {":warning:" if "RECIPROCAL" in licenseFamily or "UNKNOWN" in licenseFamily else ""}{licenseFamily}\n'
                    snippet_comment += f'**Name:** {snippet["projectName"]}\n'
                    snippet_comment += f'**Version:** {snippet["releaseVersion"]}\n'
                    snippet_comment += f'**License:** {snippet["licenseDefinition"]["licenseDisplayName"]}\n'
                    snippet_comment += f'**Matched file:** {snippet["matchedFilePath"]}\n'
                    snippet_comment += f'**Matched lines:** start: {snippet["regions"]["sourceStartLines"]}, end: {snippet["regions"]["sourceEndLines"]}'
                    self.__addSnippetComment(snippet_comment)

    def __createGroupMarkDownComment(self, file:str, snippetResult:str) -> None:
        if snippetResult:
            fileUrl = f"{self.repo.html_url}/blob/{self.last_commit.sha}/{file}"
            snippet_comment = f'**Snippet analysis has found following matches from file: [{file}]({fileUrl})**\n\n'
            snippet_comment += f'| License Family | Component | License | Match info |\n'
            snippet_comment += f'| -------------- | --------- | ------- | ---------- |\n'
            for licenseFamily in snippetResult["snippetMatches"]:
                for snippet in snippetResult["snippetMatches"][licenseFamily]:
                    snippet_comment += f'| {":warning:" if "RECIPROCAL" in licenseFamily or "UNKNOWN" in licenseFamily else ""}{licenseFamily} | '
                    snippet_comment += f'**Name:** {snippet["projectName"]}</br>**Version:** {snippet["releaseVersion"]} | '
                    snippet_comment += f'{snippet["licenseDefinition"]["licenseDisplayName"]} | '
                    snippet_comment += f'**Matched file:** {snippet["matchedFilePath"]}</br>'
                    snippet_comment += f'**Matched lines:** start: {snippet["regions"]["sourceStartLines"]}, end: {snippet["regions"]["sourceEndLines"]} |\n'
        self.__addSnippetComment(snippet_comment)

    def __addSnippetComment(self, comment:str) -> None:
        if self.pullRequest:
            self.pullRequest.create_issue_comment(comment)
            
    
