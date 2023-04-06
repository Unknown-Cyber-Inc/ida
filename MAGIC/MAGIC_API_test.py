import os
import requests
import json
from dotenv import load_dotenv 

# ENVPATH needs to be replaced by the actual path to the env file. absolute is easier to manage.
# The rest come from .env
load_dotenv(os.getenv("CYENVPATH"))
MAGIC_API_ENDPOINT = os.getenv("MAGIC_API_ENDPOINT")
MAGIC_API_KEY = os.getenv("MAGIC_API_KEY")
MALWAREPATH = os.getenv("MALWAREPATH")
PLUGIN_DEBUG = True if os.getenv("PLUGIN_DEBUG") == "True" else False

#other endpoints for organization
files_url = MAGIC_API_ENDPOINT + '/files'
tags_url = MAGIC_API_ENDPOINT + '/tags'
yara_url = MAGIC_API_ENDPOINT + '/yara'

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
    explain = hasattr(res,"explain")
    body = None
    if res.text != '':
        body = res.json()

    printstring = '\t'
    if explain: printstring = printstring + 'explain '
    printstring = printstring + str(status) + ' ' + method + ' ' + endpoint
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

    #explain request
    if explain:
        printstring = printstring + json.dumps(body['resource'],indent=indent) + '\n'
    elif body: #not explain, but has a body
        printstring = printstring + 'body:' + json.dumps(body,indent=indent) + '\n'
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
    endpoint = '/' + endpoint
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
    res.explain = True # add this attribute to response to determine if this is an explain function
    # seems hacky
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
def patch_file(binary_id, headers={}, params={}, data={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.patch(url=files_url + '/' + binary_id, headers=headers, params=params)
    return res

"""
CRUD tags
"""

#request all tags list and info
def get_tags(headers={},params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.get(url=tags_url, params=params, headers=headers)
    return res

#create project for tagging files
def create_project(headers={},data={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.post(url=tags_url, headers=headers, data=data)
    return res

#update tags
# param - update_mask required
def update_all_tags(data={}, headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.patch(url=tags_url, data=data, headers=headers, params=params)
    return res

# delete selected tags with passed filter
# if no filter passed, this WILL DELETE ALL TAGS
def delete_selected_tags(headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.delete(url=tags_url, headers=headers, params=params)
    return res

"""
CRUD tags/{id}
"""


#request tag and info
def get_tag(binary_id, headers={},params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.get(url=tags_url + '/' + binary_id, params=params, headers=headers)
    return res

#update tag
# param - update_mask required
def update_tag(binary_id, data={}, headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.patch(url=tags_url + '/' + binary_id, data=data, headers=headers, params=params)
    return res

#delete tag
def delete_tag(binary_id, headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.delete(url=tags_url + '/' + binary_id, headers=headers, params=params)
    return res

"""
CRUD tags/{id}/files
"""

#request files associated with a specific tag
def get_tag_files(binary_id, headers={},params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.get(url=tags_url + '/' + binary_id + '/' + 'files', params=params, headers=headers)
    return res

#delete tags from a file
def delete_tag_files(binary_id, headers={}, params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.delete(url=tags_url + '/' + binary_id + '/' + 'files', headers=headers, params=params)
    return res

"""
GET av data and GET labels for given file
"""

"""
GENERATE yara rules for given file
"""

# generate yara for file
def gen_yara(headers={},data={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY
    # headers["Content-Type"] = "multipart/form-data" # THIS ACTUALLY BREAKS DO NOT USE IT!!!! (not world-ending, just frustrating)

    res = requests.post(url=yara_url, headers=headers, data=data)
    return res

"""
GET all matches of a file
"""

#get file matches based on yara
def get_file_matches(binary_id, headers={},params={}):
    # this is to circumvent adding the api key to the headers object
    headers = headers.copy()
    headers["X-API-KEY"] = MAGIC_API_KEY

    res = requests.get(url=yara_url + '/' + binary_id + '/' + 'matches', params=params, headers=headers)
    return res

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
    # data = {
    #     "tags":["tag1","tag2","tag3","tag4","tag"],
    #     "notes":"note"
    # }
    # files = [
    #     MALWAREPATH + "COMPROBANTE_SWA0980011002021_ELECTRÓNICA.exe",
    #     MALWAREPATH + "LooseFileB",
    # ]

    # # need to grab the response in order to remove the added files
    # res = post_file(files=files,data=data)
    # prettyprint(res,files=files,data=data)



    # for resource in res.json()['resources']:
    #     params = {"update_mask":"public"}
    #     data = {"public":"true"}
    #     prettyprint(patch_file(binary_id=resource['sha1'],params=params,data=data),params=params,data=data)
    #     params = {"force":True}
    #     prettyprint(delete_file(binary_id=resource['sha1'],params=params),params=params)

    # prettyprint(get_files())

    """
    CRUD tags
    """

    # prettyprint(get_tags())

    # data={
    #     "name":"seg",
    #     "color":"#329db6",
    # }
    # # prettyprint(create_project(data=data),data=data)

    # data={
    #     "color":"#ffffff",
    # }
    # params={
    #     "update_mask":"color"
    # }
    # prettyprint(update_all_tags(params=params,data=data),params=params,data=data)

    # params={
    #     "filters":not *
    #     "force":True
    # }
    # prettyprint(delete_selected_tags(params=params),params=params)

    """
    CRUD tags/{id}
    """

    # prettyprint(get_tag("642e433ea309161920bb7704"))

    # prettyprint(explain_endpoint("tags/642e433ea309161920bb7703","PATCH"))

    # params={
    #     "update_mask":"color,name",
    # }
    # data={
    #     "name":"tag22",
    #     "color":"#ffffff"
    # }
    # prettyprint(update_tag("642e433ea309161920bb7703",params=params,data=data),params=params,data=data)

    # params={
    #     "force":True
    # }
    # prettyprint(delete_tag("642e433ea309161920bb7703",params=params),params=params)

    # prettyprint(get_tag_files("642e433ea309161920bb7704"))

    # prettyprint(delete_tag_files("642e433ea309161920bb7704",params={"force":True}))

    """
    GET av data and GET labels for given file
    """

    """
    GENERATE yara rules for given file
    """

    # data={
    #     "files":"c5120cf63b470c2681769b833d3dabab66547c01"
    # }
    # prettyprint(gen_yara(data=data),data=data)

    """
    GET all matches of a file
    """

    # prettyprint(get_file_matches("c5120cf63b470c2681769b833d3dabab66547c01"))

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