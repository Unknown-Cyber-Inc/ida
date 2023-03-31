import os
import requests
import json
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv 

load_dotenv()
MAGIC_API_ENDPOINT = os.getenv("MAGIC_API_ENDPOINT")
MAGIC_API_KEY = os.getenv("MAGIC_API_KEY")
MALWAREPATH = os.getenv("MALWAREPATH")
#other endpoints
files_url = MAGIC_API_ENDPOINT + 'files/'

#automatically prettyprint the recieved response object to terminal
#dependant on this website
def p(res,data=None,files=None,full_filepath=False,print_header=False,indent=2):

    status = str(res.status_code)
    method = res.request.method
    endpoint = res.url.split("?")[0].split(MAGIC_API_ENDPOINT)[1]
    headers = res.headers

    printstring = status + ' ' + method + ' ' + endpoint
    if data:
        printstring = printstring + ' data|'
        for k,v in data.items():
            if type(v) == str:
                printstring = printstring + ' ' + k + ':' + v
    if files:
        printstring = printstring + ' files|'
        for file in files:
            if full_filepath:
                printstring = printstring + file + ',' 
            else:
                printstring = printstring + file.split('/')[-1] + ',' 

    print("")
    print("data sent:")
    print(printstring)
    if print_header: print(headers)
    print("===========================================================================")
    # successful delete methods don't return a body
    # nor do patches (on files? or other things?)
    if (method != "DELETE" ) or (method == "DELETE" and status != "204"):
        body = res.json()
        print(json.dumps(body,indent=indent))
    print("")

#convert list of file paths to dict of files and binaries appropriate to upload
#malware should generally be lightweight in theory
#but this shouldn't be used in practice anyway
#explicitly set rb to not ruin file integrity!!!
def safeopen_filelist(filelist):
    files = []
    print("\nfile io info:\n---------------------------------------------------------------------------")
    for filepath in filelist:
        try:
            files.append(('filedata',open(filepath,'rb')))
            print(filepath.split('/')[-1] + ' opened successfully')
        except:
            print("error opening '" + filepath + "'. ignoring it.")
    return files

def close_filelist(filelist):
    for filetuple in filelist:
        filetuple[1].close()
        if filetuple[1].closed: print(str(filetuple[1]).split('\'')[1].split('/')[-1] + " closed successfully")
        else: print("file " + str(filetuple[1]) + " failed to close")
    print("---------------------------------------------------------------------------")

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
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.get(url=files_url, params=params, headers=headers)
    return res

#upload a file
def post_file(headers={},data={},files=[]):
    headers["X-API-KEY"] = MAGIC_API_KEY
    # headers["Content-Type"] = "multipart/form-data" # THIS ACTUALLY BREAKS DO NOT USE IT!!!! (not world-ending, just frustrating)

    # open and POST binary files, then close the file and return response
    files_post = safeopen_filelist(files)
    res = requests.post(url=files_url, headers=headers, data=data, files=files_post)
    close_filelist(files_post)
    return res

#delete file
def delete_file(binary_id, headers={}, params={}, force:bool=False):
    headers["X-API-KEY"] = MAGIC_API_KEY
    params["force"] = force

    res = requests.delete(url=files_url + binary_id, headers=headers, params=params)
    return res

#update file
def patch_file():
    return

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
    "tags":"tag",
    "notes":"note"
}
files = [
    MALWAREPATH + "COMPROBANTE_SWA0980011002021_ELECTRÓNICA.exe",
    MALWAREPATH + "LooseFileB",
]

p(get_files())

res = post_file(files=files)
p(res,files=files)

p(get_files())

for resource in res.json()['resources']:
    # p(patch_file())
    p(delete_file(binary_id=resource['sha1'],force=True))
p(get_files())

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