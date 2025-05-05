import logging
import sys
import github

__author__ = "Jouni Lehto"

supportedFileExtensions = ["py", "c", "h", "java", "ccp", "js", "go", ""]

class GihubCommenter:

    def __init__(self, giturl:str, gittoken:str, repo:str, prID:int, changedFiles:bool, group:bool, toolNameforSarif:str, log_level:str, version:str) -> None:
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        self.__version__= version
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
        self.toolNameforSarif = toolNameforSarif
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

    def createSarif(self, snippetResultJson:str, url:str) -> str:
        if snippetResultJson:
            sarif_json = self.__getSarifJsonHeader()
            snippets, rules = self.__getResults(snippetResultJson)
            results = {}
            results['results'] = snippets
            results['tool'] = self.__getSarifJsonFooter(rules, url)
            runs = []
            runs.append(results)
            sarif_json['runs'] = runs
            return sarif_json

    def __getResults(self, snippetResultsJson:dict) -> list:
        rules, results, ruleIds = [], [], []
        snippetResultsJson = dict(snippetResultsJson)
        for snippetResultFile in snippetResultsJson.keys():
            for licenseFamily in snippetResultsJson[snippetResultFile]["snippetMatches"]:
                for snippet in snippetResultsJson[snippetResultFile]["snippetMatches"][licenseFamily]:
                    locations = []
                    rule, result = {}, {}
                    ruleId = f'License/{snippet["licenseDefinition"]["name"]}/{licenseFamily}'                
                    ## Adding vulnerabilities as a rule
                    if not ruleId in ruleIds:
                        rule = {"id":ruleId, "name": "Snippet Match", "helpUri": snippetResultsJson[snippetResultFile]['_meta']['links'][0]["href"], "shortDescription":{"text":f'{snippet["licenseDefinition"]["licenseDisplayName"]}'}, 
                            "fullDescription":{"text":f'{snippet["licenseDefinition"]["name"]}', "markdown": f'{snippet["licenseDefinition"]["name"]}'},
                            "help":{"text":f'{snippet["licenseDefinition"]["name"]}', "markdown": f'{self.__createSnippetMarkdownRule(snippet, snippetResultFile, licenseFamily, None)}'}, 
                            "properties": {"security-severity": self.__nativeSeverityToNumber(licenseFamily.upper()), "tags": self.__addLicenseTags()},
                            "defaultConfiguration":{"level":self.__nativeSeverityToLevel(licenseFamily.upper())}}
                        rules.append(rule)
                        ruleIds.append(ruleId)
                    # ## Adding results for vulnerabilities
                    result['message'] = {"text":self.__addMessage(snippet, None)}
                    result['ruleId'] = ruleId
                    for idx, startLine in enumerate(snippet["regions"]["sourceStartLines"]):
                        locations.append({"location":{"physicalLocation":{"artifactLocation":{"uri": snippetResultFile},"region":{"startLine":int(startLine), 
                                        "endLine" :int(snippet["regions"]["sourceEndLines"][idx])}}, "message" : {"text": self.__addMessage(snippet, idx)}}})
                    
                    result['locations'] = [{"physicalLocation":{"artifactLocation":{"uri": snippetResultFile},"region":{"startLine":int(snippet["regions"]["matchedStartLines"][0])}}, 
                                            "message" : {"text": "Snippet match found."}}]
                    # result['partialFingerprints'] = {"primaryLocationLineHash": hashlib.sha256((f'{snippet["licenseDefinition"]["name"]}}{snippetResultFile}').encode(encoding='UTF-8')).hexdigest()}
                    codeFlowsTable, loctionsFlowsTable = [], []
                    threadFlows, loctionsFlows = {}, {}
                    loctionsFlows['locations'] = locations
                    loctionsFlowsTable.append(loctionsFlows)
                    threadFlows['threadFlows'] = loctionsFlowsTable
                    codeFlowsTable.append(threadFlows)
                    result['codeFlows'] = codeFlowsTable
                    results.append(result)
        return results, rules

    def __addMessage(self, snippet, idx) -> str:
        message = f'Snippet match found.\n'
        message += f'Matched OSS Library: {snippet["projectName"]}\n'
        message += f'Matched OSS Library version: {snippet["releaseVersion"]}\n'
        message += f'Matched OSS Library License: {snippet["licenseDefinition"]["licenseDisplayName"]}\n'
        message += f'Matched file: {snippet["matchedFilePath"]}\n'
        if idx:
            message += f'Matched lines in OSS file: start: {snippet["regions"]["matchedStartLines"][idx]}, end: {snippet["regions"]["matchedEndLines"][idx]}'
        return message

    def __addLicenseTags(self):
        tags = []
        tags.append("LICENSE_VIOLATION")
        tags.append("security")
        return tags

    # Changing the native severity into sarif defaultConfiguration level format
    def __nativeSeverityToLevel(self, argument): 
        if argument:
            if "RECIPROCAL" in argument:
                return "error"
            elif "UNKNOWN" in argument:
                return "error"
            elif "PERMISSIVE" in argument:
                return "note"
        return "note"

    # Changing the native severity into sarif security-severity format
    def __nativeSeverityToNumber(self, argument): 
        if argument:
            if "RECIPROCAL" in argument:
                return "9.1"
            elif "UNKNOWN" in argument:
                return "6.8"
            elif "PERMISSIVE" in argument:
                return "1.0"
        return "0.0"

    def __getSarifJsonHeader(self):
        return {"$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","version":"2.1.0"}

    def __getSarifJsonFooter(self, rules, url):
        return {"driver":{"name":self.toolNameforSarif,"informationUri": f'{url if url else ""}',"version":self.__version__,"organization":"Black Duck","rules":rules}}

    def __createSeparatedMarkdownComment(self, file:str, snippetResult:str) -> None:
        if snippetResult:
            for licenseFamily in snippetResult["snippetMatches"]:
                fileUrl = f"{self.repo.html_url}/blob/{self.last_commit.sha}/{file}"
                for snippet in snippetResult["snippetMatches"][licenseFamily]:
                    self.__addSnippetComment(self.__createSnippetMarkdown(snippet, file, licenseFamily, fileUrl))
    
    def __createSnippetMarkdown(self, snippet, file, licenseFamily, fileUrl, idx):
        if fileUrl:
            snippet_comment = f'**Snippet analysis has found following match from file: [{file}]({fileUrl})**\n\n'
        else:
            snippet_comment = f'## Snippet analysis has found following match**\n\n'
        snippet_comment += f'**License family:** {":warning:" if "RECIPROCAL" in licenseFamily or "UNKNOWN" in licenseFamily else ""}{licenseFamily}\n'
        snippet_comment += f'**Name:** {snippet["projectName"]}\n'
        snippet_comment += f'**Version:** {snippet["releaseVersion"]}\n'
        snippet_comment += f'**License:** {snippet["licenseDefinition"]["licenseDisplayName"]}\n'
        snippet_comment += f'**Matched file:** {snippet["matchedFilePath"]}\n'
        snippet_comment += f'**Matched lines:** start: {snippet["regions"]["sourceStartLines"][idx]}, end: {snippet["regions"]["sourceEndLines"][idx]}'
        return snippet_comment
    
    def __createSnippetMarkdownRule(self, snippet, file, licenseFamily, fileUrl):
        if fileUrl:
            snippet_comment = f'**Snippet analysis has found following match from file: [{file}]({fileUrl})**\n\n'
        else:
            snippet_comment = f'## Snippet analysis has found following match**\n\n'
        snippet_comment += f'**License family:** {":warning:" if "RECIPROCAL" in licenseFamily or "UNKNOWN" in licenseFamily else ""}{licenseFamily}\n'
        snippet_comment += f'**Name:** {snippet["projectName"]}\n'
        snippet_comment += f'**Version:** {snippet["releaseVersion"]}\n'
        snippet_comment += f'**License:** {snippet["licenseDefinition"]["licenseDisplayName"]}\n'
        return snippet_comment

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
            
    
