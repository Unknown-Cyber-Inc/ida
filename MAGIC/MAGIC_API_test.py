import os
import requests
import json
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv 

# load dotenv depending if this is run through IDA or as its own script
if __name__ != '__main__':
    load_dotenv('MAGIC/.env')
else:
    load_dotenv()
MAGIC_API_ENDPOINT = os.getenv("MAGIC_API_ENDPOINT")
MAGIC_API_KEY = os.getenv("MAGIC_API_KEY")
MALWAREPATH = os.getenv("MALWAREPATH")
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

#other endpoints for organization
files_url = MAGIC_API_ENDPOINT + '/files'

#automatically prettyprint the recieved response object to terminal
#dependant on this website
def prettyprint(res,headers=None,params=None,data=None,files=None,full_filepath=False,print_res_header=False,indent=2):
    print(prettystring(res,headers,params,data,files,full_filepath,print_res_header,indent))

#need to build and return a string to print inside textboxes
def prettystring(res,headers=None,params=None,data=None,files=None,full_filepath=False,print_res_header=False,indent=2):

    status = res.status_code
    method = res.request.method
    endpoint = res.url.split('?')[0].split(MAGIC_API_ENDPOINT)[-1]
    if endpoint == '': endpoint = '/' #print root in case we hit root endpoint
    res_headers = res.headers

    printstring = '\t' + str(status) + ' ' + method + ' ' + endpoint
    if headers:
        printstring = printstring + '\nheaders |'
        for k,v in headers.items():
            printstring = printstring + '\n        |' + k + ': ' + str(v)
    if params:
        printstring = printstring + '\nparams  |'
        for k,v in params.items():
            printstring = printstring + '\n        |' + k + ': ' + str(v)
    if data:
        printstring = printstring + '\ndata    |'
        for k,v in data.items():
            printstring = printstring + '\n        |' + k + ': ' + str(v)
    if files:
        printstring = printstring + '\nfiles   |'
        for file in files:
            if full_filepath:
                printstring = printstring + '\n        |' + file + ',' 
            else:
                printstring = printstring + '\n        |' + file.split('/')[-1] + ',' 

    printstring = '\nsent    |\n' + '===========================================================================' + '\n' + printstring + '\n'
    printstring = printstring + 'recieved|\n' + '===========================================================================' + '\n'
    
    #printing RECIEVED header
    if print_res_header: printstring = printstring + 'head:' + json.dumps(dict(res_headers),indent=indent) + '\n'
    '''
    successful delete/patch methods don't return a body
    don't try to print body if method and status infer success
    '''
    bodyless_responses = { 
        "DELETE":204,
        "PATCH":200,
    }
    if not (method in bodyless_responses and bodyless_responses[method] is status):
        printstring = printstring + 'body:' + json.dumps(res.json(),indent=indent) + '\n'
    return printstring + '\n'

#convert list of file paths to dict of files and binaries appropriate to upload
#malware should generally be lightweight in theory
#but this shouldn't be used in practice anyway
#explicitly set rb to not ruin file integrity!!!
def safeopen_filelist(filelist):
    files = []
    if PLUGIN_DEBUG: print("\nfile io info:\n---------------------------------------------------------------------------")
    for filepath in filelist:
        try:
            files.append(('filedata',open(filepath,'rb')))
            if PLUGIN_DEBUG: print(filepath.split('/')[-1] + ' opened successfully')
        except:
            print("error opening '" + filepath + "'. ignoring it.")
    return files

# make sure imported files are closed just for the sake of correctness
def close_filelist(filelist):
    for filetuple in filelist:
        filetuple[1].close()
        if PLUGIN_DEBUG and filetuple[1].closed: print(str(filetuple[1]).split('\'')[1].split('/')[-1] + " closed successfully")
        else: print("file " + str(filetuple[1]) + " failed to close")
    if PLUGIN_DEBUG: print("---------------------------------------------------------------------------")

"""
building API functions
notes:
curl url?key=val <-> requests.request(url,params={key:val}) # applies to GET
curl -H <-> requests.request(headers={}) # applies to all requests
curl -F <-> requests.request(data/files={}) # applies to POST, PUT, PATCH
"""
# ===================================================================================

"""
explain any endpoint
"""
def explain_endpoint(endpoint='',method='GET'):
    if method == 'GET':
        res = requests.get(url=MAGIC_API_ENDPOINT+endpoint, params={"explain":"true"})
    elif method == 'POST':
        res = requests.post(url=MAGIC_API_ENDPOINT+endpoint, params={"explain":"true"})
    elif method == 'PATCH':
        res = requests.patch(url=MAGIC_API_ENDPOINT+endpoint, params={"explain":"true"})
    elif method == 'DELETE':
        res = requests.delete(url=MAGIC_API_ENDPOINT+endpoint, params={"explain":"true"})
    elif method == 'PUT':
        res = requests.put(url=MAGIC_API_ENDPOINT+endpoint, params={"explain":"true"})
    else:
        res = requests.get(url=MAGIC_API_ENDPOINT+endpoint, params={"explain":"true"})
    return res

"""
CRUD Files
"""

#request file list and info
def get_files(headers={},params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.get(url=files_url, params=params, headers=headers)
    return res

#upload a file
def post_file(headers={},data={},files=[]):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY
    # headers["Content-Type"] = "multipart/form-data" # THIS ACTUALLY BREAKS DO NOT USE IT!!!! (not world-ending, just frustrating)

    # open and POST binary files, then close the file and return response
    files_post = safeopen_filelist(files)
    res = requests.post(url=files_url, headers=headers, data=data, files=files_post)
    close_filelist(files_post)
    return res

#delete file
# param - force required
def delete_file(binary_id, headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.delete(url=files_url + '/' + binary_id, headers=headers, params=params)
    return res

#update file
# param - update_mask required
def patch_file(binary_id, headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.patch(url=files_url + '/' + binary_id, headers=headers, params=params)
    return res

"""
CRUD tags
"""

"""
GET av data and GET labels for given file
"""

"""
GENERATE yara rules for given file
"""

"""
GET all matches of a file
"""

"""
GET all procedures and info for a given file
"""

"""
GET availability of a file through API
"""

"""
DOWNLOAD file
"""


"""
testing API functions
"""
# ===================================================================================
if __name__ == "__main__":
    """
    explain any endpoint
    """
    # p(explain_endpoint())
    # p(explain_endpoint('files'))
    # p(explain_endpoint('files','POST'))

    """
    CRUD files
    """
    data = {
        "tags":["tag1","tag2"],
        "notes":"note"
    }
    files = [
        MALWAREPATH + "COMPROBANTE_SWA0980011002021_ELECTRÓNICA.exe",
        MALWAREPATH + "LooseFileB",
    ]

    # prettyprint(get_files())

    # need to grab the response in order to remove the added files
    # res = post_file(files=files,data=data)
    # prettyprint(res,files=files,data=data)

    # prettyprint(get_files())

    # for resource in res.json()['resources']:
    #     params = {"update_mask":"public"}
    #     prettyprint(patch_file(binary_id=resource,params=params),params=params)
    #     params = {"force":True}
    #     prettyprint(delete_file(binary_id=resource['sha1'],params=params),params=params)

    # prettyprint(get_files())

    """
    CRUD tags
    """

    """
    GET av data and GET labels for given file
    """

    """
    GENERATE yara rules for given file
    """

    """
    GET all matches of a file
    """

    """
    GET all procedures and info for a given file
    """

    """
    GET availability of a file through API
    """

    """
    DOWNLOAD file
    """

    """
    testing API functions
    """