import logging
import sys
import os
import argparse
import subprocess
from blackduck.HubRestApi import HubInstance
from timeit import default_timer as timer
from snippetGihubCommenter import GihubCommenter

__author__ = "Jouni Lehto"
__versionro__ = "0.0.1"

class SnippetScanner:

    '''
    This class is to run snippet scan by using Black Duck REST API.

    :param url: BD Url
    :param token BD Access Token
    :param log_level: Logging level
    '''
    def __init__(self, url:str, token:str, giturl:str, gittoken:str, repo:str, prID:int, changedOnly:bool, group:bool, log_level:str) -> None:
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
            self.gitcommenter = GihubCommenter(gittoken=gittoken, giturl=giturl, repo=repo, prID=prID, changedFiles=changedOnly, group=group, log_level=log_level)

    def __hashFileContent(self, file) -> str:
        p = subprocess.Popen(f"java -cp \"../blackduck-snippet-scanner/snippet-scanner-1.0-SNAPSHOT.jar;../blackduck-snippet-scanner/sca-fingerprint-client-1.0.0.jar\" com.blackduck.snippet.App \"{file}\"", stdout=subprocess.PIPE, shell=True)
        # p = subprocess.Popen(f"java -cp \"snippet-scanner-1.0-SNAPSHOT.jar;sca-fingerprint-client-1.0.0.jar\" com.blackduck.snippet.App \"{file}\"", stdout=subprocess.PIPE, shell=True)
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

    def anylyzeSnippets(self, prComment:bool) -> None:
        analysisFiles = snippetScanner.gitcommenter.analysisFiles
        analysisResults = {}
        if analysisFiles and len(analysisFiles) > 0:
            for analysisFile in analysisFiles:
                logging.debug(f"Analyzing file: {analysisFile}")
                hashes = self.__hashFileContent(analysisFile)
                #Code fingerprints must be between 8 and 35000
                if hashes and "fingerprints" in hashes and len(hashes["fingerprints"])>=8 and len(hashes["fingerprints"])<=3500:
                    results = self.__sendSnippet(hashes)
                    if results and "snippetMatches" in results and len(results["snippetMatches"]) > 0:
                        if prComment:
                            snippetScanner.gitcommenter.createMarkdownComment(analysisFile, results)
                        else:
                            analysisResults[analysisFile]=results
        return analysisResults

def str2bool(v):
    return v.lower() in ("yes", "true", "t", "1")
#Main for example how to run the script
if __name__ == "__main__":
    try:
        start = timer()
        #Initialize the parser
        parser = argparse.ArgumentParser(
            description="Black Duck Notices Report."
        )
        #Parse commandline arguments
        parser.add_argument('--url', default=os.environ.get('BD_URL'), help="Baseurl for Black Duck Hub", required=False)
        parser.add_argument('--token', default=os.environ.get('BD_TOKEN'), help="BD Access token", required=False)
        parser.add_argument('--giturl', default=os.environ.get('BD_URL'), help="Baseurl for Black Duck Hub", required=False)
        parser.add_argument('--gittoken', default=os.environ.get('BD_TOKEN'), help="BD Access token", required=False)
        parser.add_argument('--prID', help="BD Access token", required=False)
        parser.add_argument('--repo', help="BD Access token", required=False)
        parser.add_argument('--log_level', help="Will print more info... default=INFO", default="DEBUG")
        parser.add_argument('--fileWithPath', help="File with full file path", required=True)
        parser.add_argument('--result_file', help="File for result json", default="blackduckSnippetFindings.json", required=True)
        parser.add_argument('--changedOnly', help="Analyzing only changed files in Pull Request", default=True, type=str2bool)
        parser.add_argument('--group', help="Will create only one groupped comment per file.", default=True, type=str2bool)
        parser.add_argument('--prComment', help="Will create Pull Request Comments, otherwise json exported.", default=False, type=str2bool)

        args = parser.parse_args()

        snippetScanner = SnippetScanner(args.url, args.token, args.giturl, args.gittoken, args.repo, args.prID, args.changedOnly, args.group, args.log_level)
        results = snippetScanner.anylyzeSnippets(args.prComment)
        if not args.prComment and results:
            import json
            with open(args.result_file, "w") as f:
                f.write(json.dumps(results, indent=3))
        
        end = timer()
        usedTime = end - start
        logging.info(f"Took: {usedTime} seconds.")
        logging.info("Done")
    except Exception as e:
        logging.exception(e)
        exit(-1)