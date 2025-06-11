import logging
import sys
import os
import json
import argparse
import subprocess
from blackduck.HubRestApi import HubInstance
from timeit import default_timer as timer
from snippetGithubCommenter import GihubCommenter

__author__ = "Jouni Lehto"
__versionro__ = "0.0.1"

class SnippetScanner:

    '''
    This class is to run snippet scan by using Black Duck REST API.

    :param url: BD Url
    :param token BD Access Token
    :param log_level: Logging level
    '''
    def __init__(self, url:str, token:str, giturl:str, gittoken:str, repo:str, prID:int, group:bool, toolNameforSarif:str, log_level:str) -> None:
        logging.basicConfig(format='%(asctime)s:%(levelname)s:%(module)s: %(message)s', stream=sys.stderr, level=log_level)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.debug("Snippet Scanner -script, version: " + __versionro__)
        if not url:
            logging.error("Black Duck URL is not given. You need to give it with --url or as an BD_URL environment variable!")
            exit()
        if not token:
            logging.error("Black Duck Access Token is not given. You need to give it with --token or as an BD_TOKEN environment variable!")
            exit()
        url = url if not url.endswith("/") else url[:-1]
        self.url = url
        self.token = token
        if token:
            self.hub = HubInstance(url, api_token=token, insecure=True)
        if gittoken:
            self.gitcommenter = GihubCommenter(gittoken=gittoken, giturl=giturl, repo=repo, prID=prID, group=group, toolNameforSarif=toolNameforSarif,  log_level=log_level, version=__versionro__)

    def __hashFileContent(self, file:str, action_path:str) -> str:
        p = subprocess.Popen(f"java -cp \"{action_path}/snippet-scanner-1.0-SNAPSHOT.jar{os.pathsep}{action_path}/sca-fingerprint-client-1.0.0.jar\" com.blackduck.snippet.App \"{file}\"", stdout=subprocess.PIPE, shell=True)
        output, err = p.communicate()
        if err:
            logging.error(err)
        if output:
            return json.loads(output.decode())
        return None
    
    def __sendSnippet(self, fingerprints) -> dict:
        if fingerprints:
            api = f"{args.url}/api/snippet-matching"
            headers = self.hub.get_headers()
            headers["Content-Type"] = "application/vnd.blackducksoftware.bill-of-materials-6+json"
            response = self.hub.execute_post(url=api, data=fingerprints, custom_headers=headers)
            return response.json()

    def anylyzeSnippets(self, prComment:bool, action_path:str) -> None:
        analysisFiles = snippetScanner.gitcommenter.analysisFiles
        analysisResults = {}
        if analysisFiles and len(analysisFiles) > 0:
            for analysisFile in analysisFiles:
                logging.debug(f"Analyzing file: {analysisFile}")
                hashes = self.__hashFileContent(analysisFile, action_path)
                #Code fingerprints must be between 8 and 35000
                if hashes and "fingerprints" in hashes and len(hashes["fingerprints"])>=8 and len(hashes["fingerprints"])<=3500:
                    results = self.__sendSnippet(hashes)
                    if results and "snippetMatches" in results and len(results["snippetMatches"]) > 0:
                        if prComment:
                            snippetScanner.gitcommenter.createMarkdownComment(analysisFile, results)
                        else:
                            analysisResults[analysisFile]=results
                elif hashes and "fingerprints" in hashes and len(hashes["fingerprints"]) < 8:
                    logging.error(f"File {analysisFile} was too small for snippet analysis!")
                elif hashes and "fingerprints" in hashes and len(hashes["fingerprints"]) > 3500:
                    logging.error(f"File {analysisFile} was too big for snippet analysis!")
        return analysisResults
    
def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")
#Main for example how to run the script
if __name__ == "__main__":
    try:
        start = timer()
        #Initialize the parser
        parser = argparse.ArgumentParser(
            description="Black Duck Snipper Scanner."
        )
        #Parse commandline arguments
        parser.add_argument('--url', default=os.environ.get('BD_URL'), help="Baseurl for Black Duck Hub", required=False)
        parser.add_argument('--token', default=os.environ.get('BD_TOKEN'), help="BD Access token", required=False)
        parser.add_argument('--giturl', default=os.environ.get('GIT_URL'), help="Baseurl for GitHub", required=False)
        parser.add_argument('--gittoken', default=os.environ.get('GIT_TOKEN'), help="GitHub token", required=False)
        parser.add_argument('--prID', help="Pull request ID", required=False)
        parser.add_argument('--repo', help="GitHub repository", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="INFO")
        parser.add_argument('--action_path', help="Path where actions are downloaded", required=True)
        parser.add_argument('--result_file', help="File for result json", default="blackduckSnippetFindings.json", required=False)
        parser.add_argument('--group', help="Will create only one groupped comment per file.", default=True, type=str2bool)
        parser.add_argument('--prComment', help="Will create Pull Request Comments, otherwise json exported.", default=False, type=str2bool)
        parser.add_argument('--sarif', help="Will create sarif format file.", default=False, type=str2bool)
        parser.add_argument('--toolNameforSarif', help="Tool name in Sarif json", default="Black Duck Snippet", required=False)

        args = parser.parse_args()

        snippetScanner = SnippetScanner(args.url, args.token, args.giturl, args.gittoken, args.repo, args.prID, args.group, args.toolNameforSarif, args.log_level)
        results = snippetScanner.anylyzeSnippets(args.prComment, args.action_path)
        if not args.prComment:
            if args.sarif:
                output_results = snippetScanner.gitcommenter.createSarif(results, args.url)
            else:
                output_results = results
            with open(args.result_file, "w", encoding="UTF-8") as f:
                f.write(json.dumps(output_results, indent=3))
            with open("snippet_results.md", "w", encoding="UTF-8") as snippetFile:
                snippetFile.write(snippetScanner.gitcommenter.createSummaryMarkdown(results))
        end = timer()
        usedTime = end - start
        logging.info(f"Took: {usedTime} seconds.")
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        exit(-1)